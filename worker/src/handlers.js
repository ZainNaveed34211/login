// API handlers. Every endpoint validates input server-side, uses
// parameterized D1 queries, returns generic auth errors, and never returns
// password hashes, session hashes, raw MFA secrets, recovery-code hashes,
// encryption keys, or stack traces.
import {
  base32Decode,
  base32Encode,
  decryptSecret,
  encryptSecret,
  generateRecoveryCodes,
  hashPassword,
  normalizeEmail,
  normalizeRecoveryCode,
  randomBytes,
  randomToken,
  safeLog,
  sha256Hex,
  totpCode,
  verifyPassword,
  verifyTotp,
} from './crypto.js'
import {
  audit,
  changesOf,
  createSession,
  deleteAllSessions,
  deleteSessionByHash,
  getEntitlement,
  getSessionByHash,
  getUserByEmail,
  getUserById,
  isoPlus,
  listSessions,
  nowIso,
} from './db.js'
import {
  checkRateD1,
  checkRateD1Account,
  csrfOk,
  errorResponse,
  ipHash,
  isCodeFormat,
  isOneTimeToken,
  isSessionId,
  isValidEmail,
  isValidName,
  isValidPhone,
  isValidPassword,
  jsonResponse,
  originOk,
  readJson,
  clientIp,
  publicUser,
} from './security.js'
import { clampPbkdf2Iterations } from './crypto.js'

function iterations(env) {
  // Workers Free native WebCrypto rejects PBKDF2 iteration counts above
  // 100000 (NotSupportedError), so the production default is 100000 — the
  // platform maximum on the free plan. The stored hash records its own
  // iteration count, so this can be raised again on a paid plan without
  // breaking existing accounts. Any env value above the maximum is
  // clamped, never honoured and never thrown on.
  return clampPbkdf2Iterations(parseInt(env.PBKDF2_ITERATIONS || '100000', 10))
}
function sessionCookie(token, env) {
  const insecure = env.ALLOW_INSECURE_COOKIE === 'true'
  if (insecure) return `kluzar_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=172800`
  return `kluzar_session=${token}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=172800`
}
function clearCookie(env) {
  const insecure = env.ALLOW_INSECURE_COOKIE === 'true'
  if (insecure) return 'kluzar_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'
  return 'kluzar_session=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0'
}
function parseCookie(request) {
  const header = request.headers.get('Cookie') || ''
  const out = {}
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=')
    if (k) out[k] = v.join('=')
  }
  return out
}
async function getSession(request, env) {
  const token = parseCookie(request).kluzar_session
  // A session token this system issues is a base64url random token.
  // Anything else can never match a stored hash: reject before any
  // database lookup, without leaking whether a session exists.
  if (!isOneTimeToken(token)) return null
  const hash = await sha256Hex(token)
  const session = await getSessionByHash(env.DB, hash)
  if (!session) return null
  if (new Date(session.expires_at).getTime() <= Date.now()) {
    await deleteSessionByHash(env.DB, hash)
    return null
  }
  const user = await getUserById(env.DB, session.user_id)
  if (!user || user.status !== 'active') return null
  return { ...session, user, tokenHash: hash }
}
async function requireSession(request, env) {
  const session = await getSession(request, env)
  if (!session) return { session: null, error: 'unauthorized' }
  return { session, error: null }
}
// ---- Manage assertion helpers (new, approval-gated) ----
// Issue a short-lived, Ed25519-signed identity assertion for the
// Kluzar Manage portal. Identity ONLY (user id + session id) — no
// plan, no subscription claim, no personal data. The Manage API
// reads the live entitlement from shared D1 itself on every request.
const MANAGE_ORIGIN = 'https://manage.kluzar.com'
const ASSERTION_TTL_SECONDS = 300
const ASSERTION_KID = 'manage-assertion-v1'

function b64urlEncode(bytes) {
  let s = ''
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode(...bytes.subarray(i, i + chunk))
  }
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function randomJti() {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return b64urlEncode(bytes)
}

// Sign one assertion with the Accounts private key. Throws when the
// key is missing or malformed — the caller turns that into a 500 and
// never returns an assertion.
async function signManageAssertion(env, { userId, sessionId }) {
  const raw = env.MANAGE_ASSERTION_PRIVATE_KEY
  if (!raw) throw new Error('Signing key not configured.')
  let jwk
  try {
    jwk = JSON.parse(raw)
  } catch {
    throw new Error('Signing key malformed.')
  }
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.d !== 'string') {
    throw new Error('Signing key malformed.')
  }
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['sign'])
  const nowSec = Math.floor(Date.now() / 1000)
  const header = { alg: 'EdDSA', typ: 'JWT', kid: ASSERTION_KID }
  const payload = {
    sub: userId,
    sid: sessionId,
    aud: 'kluzar-manage-api',
    iat: nowSec,
    exp: nowSec + ASSERTION_TTL_SECONDS,
    jti: randomJti(),
  }
  const enc = new TextEncoder()
  const signingInput = `${b64urlEncode(enc.encode(JSON.stringify(header)))}.${b64urlEncode(enc.encode(JSON.stringify(payload)))}`
  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, key, enc.encode(signingInput))
  return `${signingInput}.${b64urlEncode(new Uint8Array(signature))}`
}

const ONE_TIME_TABLES = new Set(['setup_tokens', 'login_challenges', 'recovery_transactions'])
function checkOneTimeTable(table) {
  // Table names can never come from user input. Callers pass only the
  // three hardcoded names above; anything else is a programming error
  // and must fail rather than build a query from an unknown name.
  if (!ONE_TIME_TABLES.has(table)) throw new Error('Invalid token table')
}
async function createOneTimeToken(db, table, userId, minutes) {
  checkOneTimeTable(table)
  const token = randomToken(32)
  const hash = await sha256Hex(token)
  // DELETE + INSERT in one batch: all-or-nothing. A failure cannot
  // leave the user with no valid token while the caller thinks one
  // was issued, and a concurrent create cannot interleave between
  // the delete and the insert.
  await db.batch([
    db.prepare(`DELETE FROM ${table} WHERE user_id = ?`).bind(userId),
    db.prepare(`INSERT INTO ${table} (id, user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`)
      .bind(randomToken(16), userId, hash, nowIso(), isoPlus(minutes * 60 * 1000)),
  ])
  return token
}
// Lookup only — does NOT consume. Used for the first step of a
// multi-step flow (MFA setup: setup creates a pending secret, verify
// consumes the token) and as the pre-check before an atomic consume.
// A lookup alone must never authorise a final action.
async function peekOneTimeToken(db, table, token) {
  checkOneTimeTable(table)
  if (!isOneTimeToken(token)) return null
  const hash = await sha256Hex(token)
  const row = await db.prepare(`SELECT * FROM ${table} WHERE token_hash = ?`).bind(hash).first()
  if (!row) return null
  if (new Date(row.expires_at).getTime() <= Date.now()) {
    await db.prepare(`DELETE FROM ${table} WHERE token_hash = ?`).bind(hash).run()
    return null
  }
  return row
}
// Atomic consume. The caller must already have verified whatever the
// token gates (TOTP code, new password validity) BEFORE calling this,
// so a failed verification does not burn a token the user can retry
// with — but once verification has passed, only the first concurrent
// caller wins: the conditional DELETE/UPDATE affects exactly 1 row
// for the winner and 0 rows for every loser, which must fail.
// setup_tokens / login_challenges have no `used` column, so consume
// deletes the row (expiry-guarded). recovery_transactions has `used`,
// so consume marks it used (expiry- and used-guarded). Returns the
// previously peeked row on success, null on failure.
async function consumeOneTimeToken(db, table, token, peekedRow = null) {
  checkOneTimeTable(table)
  if (!isOneTimeToken(token)) return null
  const hash = await sha256Hex(token)
  const now = nowIso()
  let res
  if (table === 'recovery_transactions') {
    res = await db
      .prepare('UPDATE recovery_transactions SET used = 1 WHERE token_hash = ? AND used = 0 AND expires_at > ?')
      .bind(hash, now)
      .run()
  } else {
    res = await db
      .prepare(`DELETE FROM ${table} WHERE token_hash = ? AND expires_at > ?`)
      .bind(hash, now)
      .run()
  }
  if (changesOf(res) !== 1) return null
  if (peekedRow) return peekedRow
  return { token_hash: hash }
}
// Atomic TOTP step claim. verifyTotp (pure, in crypto.js) already
// refuses steps at or below last_used_step, but two concurrent
// requests could both pass that pure check before either updated the
// row. This conditional UPDATE is the enforcement: only the first
// caller changes exactly 1 row; every other caller gets 0 and fails.
async function claimTotpStep(db, userId, step) {
  const res = await db
    .prepare('UPDATE mfa_secrets SET last_used_step = ? WHERE user_id = ? AND (last_used_step IS NULL OR last_used_step < ?)')
    .bind(step, userId, step)
    .run()
  return changesOf(res) === 1
}
async function verifyRecoveryCode(db, userId, code) {
  const normalized = normalizeRecoveryCode(code)
  // A recovery code is 16 alphanumeric characters (shown as 4-4-4-4).
  // Anything else can never match a stored hash.
  if (!/^[A-Z0-9]{16}$/.test(normalized)) return false
  const hash = await sha256Hex(normalized)
  // Atomic claim: check + mark-used in ONE conditional UPDATE.
  // Two concurrent uses of the same code: first affects 1 row (wins),
  // second affects 0 rows (fails). The old SELECT-then-UPDATE allowed
  // both to pass.
  const res = await db
    .prepare('UPDATE recovery_codes SET used = 1, used_at = ? WHERE user_id = ? AND code_hash = ? AND used = 0')
    .bind(nowIso(), userId, hash)
    .run()
  return changesOf(res) === 1
}
async function verifyMfaCode(db, env, user, code) {
  // Returns {ok, via} where via is 'totp' or 'recovery'. TOTP first.
  if (isCodeFormat(code)) {
    const secretRow = await db.prepare('SELECT * FROM mfa_secrets WHERE user_id = ? AND enabled = 1').bind(user.id).first()
    if (!secretRow) return { ok: false, via: null }
    const secret = await decryptSecret(env, secretRow.encrypted_secret)
    const res = await verifyTotp(secret, code, secretRow.last_used_step)
    if (!res.ok) return { ok: false, via: null }
    if (!(await claimTotpStep(db, user.id, res.step))) return { ok: false, via: null }
    return { ok: true, via: 'totp' }
  }
  const ok = await verifyRecoveryCode(db, user.id, code)
  return { ok, via: ok ? 'recovery' : null }
}

export async function handleRequest(request, env) {
  const url = new URL(request.url)
  const path = url.pathname.replace(/\/$/, '') || '/'
  const method = request.method
  const ip = clientIp(request)
  const ipH = await ipHash(ip)
  const userAgent = request.headers.get('User-Agent') || ''

  // CORS preflight
  if (method === 'OPTIONS') {
    const { corsHeaders, securityHeaders } = await import('./security.js')
    return new Response(null, {
      status: 204,
      headers: { ...securityHeaders(), ...corsHeaders(env, request) },
    })
  }

  try {
    // ---- Public: register ----
    if (method === 'POST' && path === '/auth/register') {
      if (!(await checkRateD1(env.DB, request, 'register'))) return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
      if (!originOk(env, request)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      const body = await readJson(request)
      // Validate before any use: email must be a string (normalizeEmail
      // alone would coerce numbers/objects into a string), password is
      // checked by isValidPassword (type + length + mixed characters).
      if (typeof body.email !== 'string') {
        return errorResponse(env, request, 400, 'Please enter a valid email and a password of 12 to 128 characters with an uppercase letter, a lowercase letter, a number, and a symbol.', 'VALIDATION')
      }
      const email = normalizeEmail(body.email)
      const password = body.password
      if (!isValidEmail(email) || !isValidPassword(password)) {
        return errorResponse(env, request, 400, 'Please enter a valid email and a password of 12 to 128 characters with an uppercase letter, a lowercase letter, a number, and a symbol.', 'VALIDATION')
      }
      const existing = await getUserByEmail(env.DB, email)
      if (existing) {
        // Generic wording; no setup token, no new account. Full
        // non-enumeration for registration is not achievable without email
        // delivery (see docs) — this is rate-limited and generic-worded.
        await audit(env.DB, existing.id, 'register_duplicate', ipH, false, 'duplicate')
        return errorResponse(env, request, 409, 'Registration could not be completed. Please try logging in or use a different email.', 'REGISTER_FAILED')
      }
      const passwordHash = await hashPassword(password, iterations(env))
      const userId = randomToken(16)
      const setupToken = randomToken(32)
      const setupHash = await sha256Hex(setupToken)
      // User + entitlement + setup token in ONE batch: a failure cannot
      // leave a user without an entitlement or without a setup token.
      // Duplicate-email race: two concurrent registers both pass the
      // SELECT above; the second batch then violates the UNIQUE
      // constraint on users.email_normalized and must return 409,
      // never 500.
      try {
        await env.DB.batch([
          env.DB.prepare(
            'INSERT INTO users (id, email, email_normalized, password_hash, status, email_verified, mfa_enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
          ).bind(userId, email, email, passwordHash, 'pending_mfa', 0, 0, nowIso(), nowIso()),
          env.DB.prepare('INSERT INTO entitlements (user_id, plan, status, updated_at) VALUES (?, ?, ?, ?)')
            .bind(userId, 'free', 'active', nowIso()),
          env.DB.prepare('DELETE FROM setup_tokens WHERE user_id = ?').bind(userId),
          env.DB.prepare('INSERT INTO setup_tokens (id, user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
            .bind(randomToken(16), userId, setupHash, nowIso(), isoPlus(30 * 60 * 1000)),
        ])
      } catch (err) {
        const msg = String(err && err.message ? err.message : '')
        if (/UNIQUE constraint/i.test(msg)) {
          const raced = await getUserByEmail(env.DB, email)
          if (raced) await audit(env.DB, raced.id, 'register_duplicate', ipH, false, 'duplicate')
          return errorResponse(env, request, 409, 'Registration could not be completed. Please try logging in or use a different email.', 'REGISTER_FAILED')
        }
        throw err
      }
      await audit(env.DB, userId, 'register', ipH, true, '')
      safeLog('register', { userId, ok: true })
      return jsonResponse(env, request, 201, { ok: true, userId, email, status: 'pending_mfa', setupToken })
    }

    // ---- Public: login (password step) ----
    if (method === 'POST' && path === '/auth/login') {
      if (!(await checkRateD1(env.DB, request, 'login'))) return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
      if (!originOk(env, request)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      const body = await readJson(request)
      if (typeof body.email !== 'string') {
        return errorResponse(env, request, 401, 'Invalid email or password.', 'INVALID_CREDENTIALS')
      }
      const email = normalizeEmail(body.email)
      const password = body.password
      if (!isValidEmail(email) || typeof password !== 'string') {
        return errorResponse(env, request, 401, 'Invalid email or password.', 'INVALID_CREDENTIALS')
      }
      // Per-account rate limit, in addition to the per-IP limit above.
      // The email key is a hash, never the raw email, so the rate table
      // stores no plaintext PII. This stops targeted brute force from
      // many IPs without loosening the per-IP limit.
      if (!(await checkRateD1Account(env.DB, 'login', await sha256Hex(email)))) {
        return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
      }
      const user = await getUserByEmail(env.DB, email)
      // Dummy hash for timing equalisation when the user does not exist.
      // LAZY: previously it was computed unconditionally for every login,
      // so a known user paid for TWO PBKDF2 runs (dummy + real verify).
      // Now it is computed only when the user does not exist. Unknown
      // users still cost exactly one full hash (the dummy verify), so
      // account enumeration via timing is preserved; known users cost
      // one hash instead of two. Iterations are NOT lowered.
      let passwordOk
      if (user) {
        passwordOk = await verifyPassword(password, user.password_hash)
      } else {
        const dummyHash = await hashPassword('dummy-password-for-timing', iterations(env))
        passwordOk = await verifyPassword(password, dummyHash)
      }
      if (!user || !passwordOk) {
        await audit(env.DB, user ? user.id : '', 'login_failed', ipH, false, '')
        return errorResponse(env, request, 401, 'Invalid email or password.', 'INVALID_CREDENTIALS')
      }
      if (user.status === 'pending_mfa') {
        const setupToken = await createOneTimeToken(env.DB, 'setup_tokens', user.id, 30)
        return jsonResponse(env, request, 200, { ok: true, setupRequired: true, setupToken })
      }
      if (user.mfa_enabled === 1) {
        const challengeToken = await createOneTimeToken(env.DB, 'login_challenges', user.id, 10)
        return jsonResponse(env, request, 200, { ok: true, mfaRequired: true, challengeToken })
      }
      const session = await createSession(env.DB, user.id, userAgent, ipH)
      await audit(env.DB, user.id, 'login', ipH, true, 'no-mfa')
      return jsonResponse(env, request, 200, { ok: true, user: publicUser(user), csrfToken: session.csrfToken }, { 'Set-Cookie': sessionCookie(session.token, env) })
    }

    // ---- MFA setup (pending via setupToken, or re-setup via session) ----
    if (method === 'POST' && path === '/auth/mfa/setup') {
      if (!(await checkRateD1(env.DB, request, 'mfaSetup'))) return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
      if (!originOk(env, request)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      const body = await readJson(request)
      let user = null
      let setupRow = null
      if (body.setupToken) {
        // PEEK only: setup is step 1 of 2. Deleting here would break
        // the verify step that must use the same token, and would
        // burn the token on a mere QR refresh. The verify step is
        // the consuming step. An attacker with the token could call
        // setup repeatedly, but that only re-issues a pending secret
        // for an account they already hold the setup token for — it
        // creates no session and activates nothing.
        setupRow = await peekOneTimeToken(env.DB, 'setup_tokens', body.setupToken)
        if (!setupRow) return errorResponse(env, request, 400, 'Setup session expired. Please log in again.', 'INVALID_SETUP')
        user = await getUserById(env.DB, setupRow.user_id)
      } else {
        const { session, error } = await requireSession(request, env)
        if (error) return errorResponse(env, request, 401, 'Please log in again.', 'UNAUTHORIZED')
        // Authenticated branch: CSRF is required (previously missing).
        // The frontend now sends X-CSRF-Token on this call; the
        // unauthenticated setupToken branch above is token-gated, not
        // session-gated, so CSRF does not apply to it.
        if (!csrfOk(env, request, session)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
        if (!(await checkRateD1Account(env.DB, 'mfaSetup', session.user.id))) {
          return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
        }
        if (typeof body.currentPassword !== 'string' || !(await verifyPassword(body.currentPassword, session.user.password_hash))) {
          return errorResponse(env, request, 401, 'Current password is incorrect.', 'INVALID_CREDENTIALS')
        }
        user = session.user
      }
      if (!user) return errorResponse(env, request, 400, 'Setup session expired. Please log in again.', 'INVALID_SETUP')
      const secretBytes = randomBytes(20)
      const manualKey = base32Encode(secretBytes).replace(/=+$/, '')
      const encrypted = await encryptSecret(env, secretBytes)
      await env.DB.prepare('DELETE FROM pending_mfa_secrets WHERE user_id = ?').bind(user.id).run()
      await env.DB.prepare('INSERT INTO pending_mfa_secrets (user_id, encrypted_secret, created_at, expires_at) VALUES (?, ?, ?, ?)')
        .bind(user.id, encrypted, nowIso(), isoPlus(30 * 60 * 1000))
        .run()
      const otpauthUrl = `otpauth://totp/Kluzar:${encodeURIComponent(user.email)}?secret=${manualKey}&issuer=Kluzar&algorithm=SHA1&digits=6&period=30`
      return jsonResponse(env, request, 200, {
        ok: true,
        otpauthUrl,
        manualKey,
        setupToken: body.setupToken || undefined,
      })
    }

    // ---- MFA verify (setup / login challenge / re-setup) ----
    if (method === 'POST' && path === '/auth/mfa/verify') {
      if (!(await checkRateD1(env.DB, request, 'mfaVerify'))) return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
      if (!originOk(env, request)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      const body = await readJson(request)
      const code = body.code
      // A) Registration setup
      if (body.setupToken) {
        const setupRow = await peekOneTimeToken(env.DB, 'setup_tokens', body.setupToken)
        if (!setupRow) return errorResponse(env, request, 400, 'Setup session expired. Please log in again.', 'INVALID_SETUP')
        if (!(await checkRateD1Account(env.DB, 'mfaVerify', setupRow.user_id))) {
          return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
        }
        const pending = await env.DB.prepare('SELECT * FROM pending_mfa_secrets WHERE user_id = ?').bind(setupRow.user_id).first()
        if (!pending || new Date(pending.expires_at).getTime() <= Date.now() || !isCodeFormat(code)) {
          return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
        }
        const secret = await decryptSecret(env, pending.encrypted_secret)
        const res = await verifyTotp(secret, code, null)
        if (!res.ok) return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
        // Consume AFTER a correct code, BEFORE issuing anything: a
        // wrong code leaves the token retryable (existing UX), while
        // two concurrent correct-code verifies race here and only the
        // first (DELETE affects 1 row) proceeds to activation.
        if (!(await consumeOneTimeToken(env.DB, 'setup_tokens', body.setupToken, setupRow))) {
          return errorResponse(env, request, 400, 'Setup session expired. Please log in again.', 'INVALID_SETUP')
        }
        const codes = generateRecoveryCodes(10)
        const codeStmts = []
        for (const c of codes) {
          const h = await sha256Hex(normalizeRecoveryCode(c))
          codeStmts.push(env.DB.prepare('INSERT INTO recovery_codes (id, user_id, code_hash, used, created_at) VALUES (?, ?, ?, ?, ?)').bind(randomToken(16), setupRow.user_id, h, 0, nowIso()))
        }
        // Activation in ONE batch: old secret, new secret, user
        // status, token cleanup, pending cleanup and recovery codes
        // either all apply or none do. Previously these were separate
        // statements, so a mid-way failure could leave a half-activated
        // account.
        await env.DB.batch([
          env.DB.prepare('DELETE FROM mfa_secrets WHERE user_id = ?').bind(setupRow.user_id),
          env.DB.prepare('INSERT INTO mfa_secrets (user_id, encrypted_secret, enabled, last_used_step, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
            .bind(setupRow.user_id, pending.encrypted_secret, 1, res.step, nowIso(), nowIso()),
          env.DB.prepare('UPDATE users SET status = ?, mfa_enabled = ?, updated_at = ? WHERE id = ?')
            .bind('active', 1, nowIso(), setupRow.user_id),
          env.DB.prepare('DELETE FROM setup_tokens WHERE user_id = ?').bind(setupRow.user_id),
          env.DB.prepare('DELETE FROM pending_mfa_secrets WHERE user_id = ?').bind(setupRow.user_id),
          env.DB.prepare('DELETE FROM recovery_codes WHERE user_id = ?').bind(setupRow.user_id),
          ...codeStmts,
        ])
        await audit(env.DB, setupRow.user_id, 'mfa_setup', ipH, true, '')
        // MFA has now succeeded, so a session may be issued (the rule is
        // "no session until MFA succeeds" — setup verify IS that MFA success).
        // This avoids forcing the user to log in again with the same
        // 30-second code, which replay protection would rightly reject.
        const activatedUser = await getUserById(env.DB, setupRow.user_id)
        const session = await createSession(env.DB, setupRow.user_id, userAgent, ipH)
        return jsonResponse(env, request, 200, { ok: true, activated: true, recoveryCodes: codes, user: publicUser(activatedUser), csrfToken: session.csrfToken }, { 'Set-Cookie': sessionCookie(session.token, env) })
      }
      // B) Login challenge (TOTP or recovery code)
      if (body.challengeToken) {
        const challenge = await peekOneTimeToken(env.DB, 'login_challenges', body.challengeToken)
        if (!challenge) return errorResponse(env, request, 400, 'Login session expired. Please log in again.', 'INVALID_CHALLENGE')
        const user = await getUserById(env.DB, challenge.user_id)
        if (!user || user.status !== 'active') return errorResponse(env, request, 400, 'Login session expired. Please log in again.', 'INVALID_CHALLENGE')
        if (!(await checkRateD1Account(env.DB, 'mfaVerify', user.id))) {
          return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
        }
        const res = await verifyMfaCode(env.DB, env, user, code)
        if (!res.ok) return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
        // Consume AFTER a correct code, BEFORE creating the session:
        // wrong codes leave the challenge retryable; concurrent
        // correct-code verifies race here and only one gets a session.
        // verifyMfaCode already atomically claimed the TOTP step /
        // recovery code, so this is the second, independent claim.
        if (!(await consumeOneTimeToken(env.DB, 'login_challenges', body.challengeToken, challenge))) {
          return errorResponse(env, request, 400, 'Login session expired. Please log in again.', 'INVALID_CHALLENGE')
        }
        const session = await createSession(env.DB, user.id, userAgent, ipH)
        await audit(env.DB, user.id, 'login', ipH, true, res.via)
        return jsonResponse(env, request, 200, { ok: true, user: publicUser(user), csrfToken: session.csrfToken }, { 'Set-Cookie': sessionCookie(session.token, env) })
      }
      // C) Authenticated re-setup
      const { session, error } = await requireSession(request, env)
      if (error) return errorResponse(env, request, 401, 'Please log in again.', 'UNAUTHORIZED')
      // Authenticated branch: CSRF is required (previously missing).
      // The frontend now sends X-CSRF-Token on this call.
      if (!csrfOk(env, request, session)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      if (!(await checkRateD1Account(env.DB, 'mfaVerify', session.user.id))) {
        return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
      }
      const pending = await env.DB.prepare('SELECT * FROM pending_mfa_secrets WHERE user_id = ?').bind(session.user.id).first()
      if (!pending || !isCodeFormat(code)) return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
      const secret = await decryptSecret(env, pending.encrypted_secret)
      const res = await verifyTotp(secret, code, null)
      if (!res.ok) return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
      // Atomic pending claim: two concurrent correct-code verifies
      // race here; only the first deletes exactly 1 pending row.
      // Without this, both could insert a secret and both return
      // success for the same code.
      const claimed = await env.DB.prepare('DELETE FROM pending_mfa_secrets WHERE user_id = ? AND encrypted_secret = ?').bind(session.user.id, pending.encrypted_secret).run()
      if (changesOf(claimed) !== 1) return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
      await env.DB.batch([
        env.DB.prepare('DELETE FROM mfa_secrets WHERE user_id = ?').bind(session.user.id),
        env.DB.prepare('INSERT INTO mfa_secrets (user_id, encrypted_secret, enabled, last_used_step, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
          .bind(session.user.id, pending.encrypted_secret, 1, res.step, nowIso(), nowIso()),
        env.DB.prepare('UPDATE users SET mfa_enabled = ?, updated_at = ? WHERE id = ?').bind(1, nowIso(), session.user.id),
      ])
      await audit(env.DB, session.user.id, 'mfa_res setup', ipH, true, '')
      return jsonResponse(env, request, 200, { ok: true, mfaEnabled: true })
    }

    // ---- Session ----
    if (method === 'GET' && path === '/auth/session') {
      const session = await getSession(request, env)
      if (!session) return jsonResponse(env, request, 401, { ok: false, authenticated: false })
      const entitlement = await getEntitlement(env.DB, session.user.id)
      return jsonResponse(env, request, 200, { ok: true, authenticated: true, user: publicUser(session.user), csrfToken: session.csrf_token, entitlement })
    }

    // ---- Manage assertion (new, approval-gated) ----
    if (method === 'POST' && path === '/auth/manage-assertion') {
      const session = await getSession(request, env)
      if (!session) return jsonResponse(env, request, 401, { ok: false, authenticated: false })
      if (!csrfOk(env, request, session)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      const origin = request.headers.get('Origin') || ''
      if (origin !== MANAGE_ORIGIN) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      if (!(await checkRateD1(env.DB, request, 'manageAssertion'))) return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
      let assertion
      try {
        assertion = await signManageAssertion(env, { userId: session.user.id, sessionId: session.id })
      } catch {
        return errorResponse(env, request, 500, 'Assertion service is not configured.', 'ASSERTION_UNAVAILABLE')
      }
      await audit(env.DB, session.user.id, 'manage_assertion_issued', ipH, true, '')
      return jsonResponse(env, request, 200, { ok: true, assertion, expiresIn: ASSERTION_TTL_SECONDS })
    }
    if (method !== 'POST' && path === '/auth/manage-assertion') {
      return errorResponse(env, request, 405, 'Method not allowed.', 'METHOD_NOT_ALLOWED')
    }
    if (method === 'POST' && path === '/auth/logout') {
      const session = await getSession(request, env)
      // No session: idempotent success (clear the cookie anyway).
      // With a session: CSRF is required (previously missing). A
      // cross-site POST without the token must not log the victim
      // out. The frontend now fetches the token from GET /auth/session
      // and sends it here; Pages must deploy before this Worker change
      // (old frontend + new Worker would leave the server session
      // alive while the browser appears logged out).
      if (session) {
        if (!csrfOk(env, request, session)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
        await deleteSessionByHash(env.DB, session.tokenHash)
      }
      return jsonResponse(env, request, 200, { ok: true }, { 'Set-Cookie': clearCookie(env) })
    }
    if (method === 'POST' && path === '/auth/logout-all') {
      const { session, error } = await requireSession(request, env)
      if (error) return errorResponse(env, request, 401, 'Please log in again.', 'UNAUTHORIZED')
      // CSRF was previously missing here; the frontend already sends
      // X-CSRF-Token on this call, so adding the check breaks nothing.
      if (!csrfOk(env, request, session)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      await deleteAllSessions(env.DB, session.user.id)
      await audit(env.DB, session.user.id, 'logout_all', ipH, true, '')
      return jsonResponse(env, request, 200, { ok: true }, { 'Set-Cookie': clearCookie(env) })
    }

    // ---- Password change (logged in) ----
    if (method === 'POST' && path === '/auth/password/change') {
      const { session, error } = await requireSession(request, env)
      if (error) return errorResponse(env, request, 401, 'Please log in again.', 'UNAUTHORIZED')
      if (!csrfOk(env, request, session)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      if (!(await checkRateD1(env.DB, request, 'passwordChange', session.user.id))) return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
      const body = await readJson(request)
      if (typeof body.currentPassword !== 'string' || !(await verifyPassword(body.currentPassword, session.user.password_hash))) {
        return errorResponse(env, request, 401, 'Current password is incorrect.', 'INVALID_CREDENTIALS')
      }
      if (session.user.mfa_enabled === 1) {
        const res = await verifyMfaCode(env.DB, env, session.user, body.mfaCode)
        if (!res.ok) return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
      }
      if (!isValidPassword(body.newPassword)) return errorResponse(env, request, 400, 'New password must be 12 to 128 characters and include an uppercase letter, a lowercase letter, a number, and a symbol.', 'VALIDATION')
      const newHash = await hashPassword(body.newPassword, iterations(env))
      await env.DB.prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?').bind(newHash, nowIso(), session.user.id).run()
      // Rotate current session, revoke all others.
      await env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?').bind(session.user.id, session.tokenHash).run()
      await deleteSessionByHash(env.DB, session.tokenHash)
      const newSession = await createSession(env.DB, session.user.id, userAgent, ipH)
      await audit(env.DB, session.user.id, 'password_change', ipH, true, '')
      return jsonResponse(env, request, 200, { ok: true, csrfToken: newSession.csrfToken }, { 'Set-Cookie': sessionCookie(newSession.token, env) })
    }

    // ---- Forgot password (step 1: verify code, issue recovery transaction) ----
    if (method === 'POST' && path === '/auth/password/forgot') {
      if (!(await checkRateD1(env.DB, request, 'forgot'))) return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
      if (!originOk(env, request)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      const body = await readJson(request)
      if (typeof body.email !== 'string') {
        // Same generic response as for a non-existent account: never
        // reveal whether the email exists or was merely malformed.
        return jsonResponse(env, request, 200, { ok: true, message: 'If an account exists, a recovery step is available. Please check your authenticator or recovery codes.' })
      }
      const email = normalizeEmail(body.email)
      const user = isValidEmail(email) ? await getUserByEmail(env.DB, email) : null
      if (!user || user.status !== 'active') {
        // Generic response: do not reveal whether the email exists.
        return jsonResponse(env, request, 200, { ok: true, message: 'If an account exists, a recovery step is available. Please check your authenticator or recovery codes.' })
      }
      if (!(await checkRateD1Account(env.DB, 'forgot', await sha256Hex(email)))) {
        return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
      }
      const res = await verifyMfaCode(env.DB, env, user, body.code)
      if (!res.ok) return errorResponse(env, request, 400, 'Invalid email or recovery code.', 'INVALID_CODE')
      const recoveryToken = randomToken(32)
      const hash = await sha256Hex(recoveryToken)
      // Replace any older transaction for this user atomically, so
      // only the newest recovery token is valid at a time.
      await env.DB.batch([
        env.DB.prepare('DELETE FROM recovery_transactions WHERE user_id = ?').bind(user.id),
        env.DB.prepare('INSERT INTO recovery_transactions (id, user_id, token_hash, created_at, expires_at, used) VALUES (?, ?, ?, ?, ?, ?)')
          .bind(randomToken(16), user.id, hash, nowIso(), isoPlus(15 * 60 * 1000), 0),
      ])
      await audit(env.DB, user.id, 'password_forgot', ipH, true, res.via)
      return jsonResponse(env, request, 200, { ok: true, recoveryToken, expiresIn: 900 })
    }
    // ---- Forgot password (step 2: reset) ----
    if (method === 'POST' && path === '/auth/password/reset') {
      if (!(await checkRateD1(env.DB, request, 'reset'))) return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
      if (!originOk(env, request)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      const body = await readJson(request)
      if (!isValidPassword(body.newPassword)) return errorResponse(env, request, 400, 'New password must be 12 to 128 characters and include an uppercase letter, a lowercase letter, a number, and a symbol.', 'VALIDATION')
      // Peek first (token shape + expiry), then consume atomically
      // BEFORE changing the password: two concurrent resets race on
      // the consume, and only the winner changes the password. A
      // failed consume must not change anything.
      const txPeek = await peekOneTimeToken(env.DB, 'recovery_transactions', body.recoveryToken)
      if (!txPeek) return errorResponse(env, request, 400, 'Invalid or expired recovery link.', 'INVALID_RECOVERY')
      const user = await getUserById(env.DB, txPeek.user_id)
      if (!user) return errorResponse(env, request, 400, 'Invalid or expired recovery link.', 'INVALID_RECOVERY')
      if (!(await consumeOneTimeToken(env.DB, 'recovery_transactions', body.recoveryToken, txPeek))) {
        return errorResponse(env, request, 400, 'Invalid or expired recovery link.', 'INVALID_RECOVERY')
      }
      const newHash = await hashPassword(body.newPassword, iterations(env))
      await env.DB.batch([
        env.DB.prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?').bind(newHash, nowIso(), user.id),
        env.DB.prepare('DELETE FROM recovery_transactions WHERE user_id = ?').bind(user.id),
        env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id),
      ])
      await audit(env.DB, user.id, 'password_reset', ipH, true, '')
      return jsonResponse(env, request, 200, { ok: true, message: 'Password changed. Please log in again.' })
    }

    // ---- Recovery codes regenerate (atomic) ----
    if (method === 'POST' && path === '/auth/recovery-codes/regenerate') {
      const { session, error } = await requireSession(request, env)
      if (error) return errorResponse(env, request, 401, 'Please log in again.', 'UNAUTHORIZED')
      if (!csrfOk(env, request, session)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      if (!(await checkRateD1(env.DB, request, 'regenerate', session.user.id))) return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
      const body = await readJson(request)
      if (typeof body.currentPassword !== 'string' || !(await verifyPassword(body.currentPassword, session.user.password_hash))) {
        return errorResponse(env, request, 401, 'Current password is incorrect.', 'INVALID_CREDENTIALS')
      }
      // Authenticator code only (TOTP) for regeneration, per spec.
      if (!isCodeFormat(body.mfaCode)) return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
      const secretRow = await env.DB.prepare('SELECT * FROM mfa_secrets WHERE user_id = ? AND enabled = 1').bind(session.user.id).first()
      if (!secretRow) return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
      const secret = await decryptSecret(env, secretRow.encrypted_secret)
      const res = await verifyTotp(secret, body.mfaCode, secretRow.last_used_step)
      if (!res.ok) return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
      // Atomic step claim (previously an unconditional UPDATE, so two
      // concurrent regenerations with the same code could both pass).
      if (!(await claimTotpStep(env.DB, session.user.id, res.step))) {
        return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
      }
      const codes = generateRecoveryCodes(10)
      const stmts = [env.DB.prepare('DELETE FROM recovery_codes WHERE user_id = ?').bind(session.user.id)]
      for (const c of codes) {
        const h = await sha256Hex(normalizeRecoveryCode(c))
        stmts.push(env.DB.prepare('INSERT INTO recovery_codes (id, user_id, code_hash, used, created_at) VALUES (?, ?, ?, ?, ?)').bind(randomToken(16), session.user.id, h, 0, nowIso()))
      }
      // Batch = atomic: if any insert fails, the old set must be preserved.
      // Real D1 batch is atomic; the test mock implements snapshot/restore.
      await env.DB.batch(stmts)
      await audit(env.DB, session.user.id, 'recovery_regenerate', ipH, true, '')
      return jsonResponse(env, request, 200, { ok: true, recoveryCodes: codes })
    }

    // ---- MFA disable ----
    if (method === 'POST' && path === '/auth/mfa/disable') {
      const { session, error } = await requireSession(request, env)
      if (error) return errorResponse(env, request, 401, 'Please log in again.', 'UNAUTHORIZED')
      if (!csrfOk(env, request, session)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      // Dedicated rate limit (previously missing entirely): disabling
      // MFA is irreversible for the victim if an attacker ever holds
      // a session, so brute force on password + code here gets its
      // own per-account + per-IP limit, not the generic fallback.
      if (!(await checkRateD1(env.DB, request, 'mfaDisable', session.user.id))) return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
      const body = await readJson(request)
      if (typeof body.currentPassword !== 'string' || !(await verifyPassword(body.currentPassword, session.user.password_hash))) {
        return errorResponse(env, request, 401, 'Current password is incorrect.', 'INVALID_CREDENTIALS')
      }
      // verifyMfaCode enforces TOTP (with atomic step claim) or a
      // single-use recovery code (with atomic claim) — password alone
      // is never enough to disable MFA.
      const res = await verifyMfaCode(env.DB, env, session.user, body.mfaCode)
      if (!res.ok) return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
      // One batch: secrets, pending secrets, recovery codes, user
      // flag and all sessions either all change or none do. A
      // mid-way failure previously could leave MFA half-disabled.
      await env.DB.batch([
        env.DB.prepare('DELETE FROM mfa_secrets WHERE user_id = ?').bind(session.user.id),
        env.DB.prepare('DELETE FROM pending_mfa_secrets WHERE user_id = ?').bind(session.user.id),
        env.DB.prepare('DELETE FROM recovery_codes WHERE user_id = ?').bind(session.user.id),
        env.DB.prepare('UPDATE users SET mfa_enabled = ?, updated_at = ? WHERE id = ?').bind(0, nowIso(), session.user.id),
        env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(session.user.id),
      ])
      const newSession = await createSession(env.DB, session.user.id, userAgent, ipH)
      await audit(env.DB, session.user.id, 'mfa_disable', ipH, true, '')
      return jsonResponse(env, request, 200, { ok: true, mfaEnabled: false, csrfToken: newSession.csrfToken }, { 'Set-Cookie': sessionCookie(newSession.token, env) })
    }

    // ---- Profile ----
    if (method === 'GET' && path === '/account/profile') {
      const { session, error } = await requireSession(request, env)
      if (error) return errorResponse(env, request, 401, 'Please log in again.', 'UNAUTHORIZED')
      const entitlement = await getEntitlement(env.DB, session.user.id)
      return jsonResponse(env, request, 200, { ok: true, user: publicUser(session.user), entitlement })
    }
    if (method === 'PATCH' && path === '/account/profile') {
      const { session, error } = await requireSession(request, env)
      if (error) return errorResponse(env, request, 401, 'Please log in again.', 'UNAUTHORIZED')
      if (!csrfOk(env, request, session)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      const body = await readJson(request)
      // Server decides the account from the session. Any userId in the body
      // is ignored — this prevents IDOR / account-takeover via client IDs.
      const firstName = body.firstName ?? session.user.first_name ?? ''
      const lastName = body.lastName ?? session.user.last_name ?? ''
      const phone = body.phone ?? session.user.phone ?? ''
      if (!isValidName(firstName) || !isValidName(lastName) || !isValidPhone(phone)) {
        return errorResponse(env, request, 400, 'Profile details are invalid.', 'VALIDATION')
      }
      await env.DB.prepare('UPDATE users SET first_name = ?, last_name = ?, phone = ?, updated_at = ? WHERE id = ?')
        .bind(String(firstName).slice(0, 100), String(lastName).slice(0, 100), String(phone).slice(0, 50), nowIso(), session.user.id)
        .run()
      const updated = await getUserById(env.DB, session.user.id)
      return jsonResponse(env, request, 200, { ok: true, user: publicUser(updated) })
    }
    // ---- Entitlements ----
    if (method === 'GET' && path === '/account/entitlements') {
      const { session, error } = await requireSession(request, env)
      if (error) return errorResponse(env, request, 401, 'Please log in again.', 'UNAUTHORIZED')
      const entitlement = await getEntitlement(env.DB, session.user.id)
      return jsonResponse(env, request, 200, { ok: true, entitlement })
    }
    // ---- Sessions list / revoke ----
    if (method === 'GET' && path === '/account/sessions') {
      const { session, error } = await requireSession(request, env)
      if (error) return errorResponse(env, request, 401, 'Please log in again.', 'UNAUTHORIZED')
      const rows = await listSessions(env.DB, session.user.id)
      return jsonResponse(env, request, 200, {
        ok: true,
        sessions: rows.map((r) => ({ ...r, current: r.id === session.id })),
      })
    }
    if (method === 'POST' && path === '/account/sessions/revoke') {
      const { session, error } = await requireSession(request, env)
      if (error) return errorResponse(env, request, 401, 'Please log in again.', 'UNAUTHORIZED')
      if (!csrfOk(env, request, session)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      const body = await readJson(request)
      // Session IDs are server-issued opaque IDs. A non-string, empty
      // or malformed value can never match a row and must not reach
      // the query unvalidated, even though the query is parameterized.
      if (!isSessionId(body.sessionId) || body.sessionId === session.id) return errorResponse(env, request, 400, 'Cannot revoke the current session here. Use Log out.', 'VALIDATION')
      await env.DB.prepare('DELETE FROM sessions WHERE id = ? AND user_id = ?').bind(body.sessionId, session.user.id).run()
      return jsonResponse(env, request, 200, { ok: true })
    }

    return errorResponse(env, request, 404, 'Not found.', 'NOT_FOUND')
  } catch (err) {
    // Never leak stack traces or internals.
    if (err && err.message === 'BODY_TOO_LARGE') return errorResponse(env, request, 413, 'Request is too large.', 'BODY_TOO_LARGE')
    if (err && err.message === 'BAD_JSON') return errorResponse(env, request, 400, 'Invalid request.', 'BAD_JSON')
    safeLog('worker_error', { message: 'internal_error' })
    return errorResponse(env, request, 500, 'Something went wrong. Please try again.', 'INTERNAL')
  }
}
