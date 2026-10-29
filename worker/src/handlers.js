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
  checkRate,
  csrfOk,
  errorResponse,
  ipHash,
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

function iterations(env) {
  const n = parseInt(env.PBKDF2_ITERATIONS || '600000', 10)
  return Number.isFinite(n) && n > 0 ? n : 600000
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
  if (!token) return null
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
  await db.prepare(`DELETE FROM ${table} WHERE user_id = ?`).bind(userId).run()
  await db
    .prepare(`INSERT INTO ${table} (id, user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`)
    .bind(randomToken(16), userId, hash, nowIso(), isoPlus(minutes * 60 * 1000))
    .run()
  return token
}
async function consumeOneTimeToken(db, table, token) {
  checkOneTimeTable(table)
  if (!token) return null
  const hash = await sha256Hex(token)
  const row = await db.prepare(`SELECT * FROM ${table} WHERE token_hash = ?`).bind(hash).first()
  if (!row) return null
  if (new Date(row.expires_at).getTime() <= Date.now()) {
    await db.prepare(`DELETE FROM ${table} WHERE token_hash = ?`).bind(hash).run()
    return null
  }
  return row
}
async function verifyRecoveryCode(db, userId, code) {
  const normalized = normalizeRecoveryCode(code)
  if (!normalized) return false
  const hash = await sha256Hex(normalized)
  const row = await db
    .prepare('SELECT * FROM recovery_codes WHERE user_id = ? AND code_hash = ? AND used = 0')
    .bind(userId, hash)
    .first()
  if (!row) return false
  await db.prepare('UPDATE recovery_codes SET used = 1, used_at = ? WHERE id = ?').bind(nowIso(), row.id).run()
  return true
}
async function verifyMfaCode(db, env, user, code) {
  // Returns {ok, via} where via is 'totp' or 'recovery'. TOTP first.
  if (/^\d{6}$/.test(String(code || ''))) {
    const secretRow = await db.prepare('SELECT * FROM mfa_secrets WHERE user_id = ? AND enabled = 1').bind(user.id).first()
    if (!secretRow) return { ok: false, via: null }
    const secret = await decryptSecret(env, secretRow.encrypted_secret)
    const res = await verifyTotp(secret, code, secretRow.last_used_step)
    if (!res.ok) return { ok: false, via: null }
    await db.prepare('UPDATE mfa_secrets SET last_used_step = ? WHERE user_id = ?').bind(res.step, user.id).run()
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
      if (!checkRate(env, request, 'register')) return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
      if (!originOk(env, request)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      const body = await readJson(request)
      const email = normalizeEmail(body.email)
      const password = body.password
      if (!isValidEmail(email) || !isValidPassword(password)) {
        return errorResponse(env, request, 400, 'Please enter a valid email and a password of at least 12 characters.', 'VALIDATION')
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
      await env.DB.prepare(
        'INSERT INTO users (id, email, email_normalized, password_hash, status, email_verified, mfa_enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      )
        .bind(userId, email, email, passwordHash, 'pending_mfa', 0, 0, nowIso(), nowIso())
        .run()
      await env.DB.prepare('INSERT INTO entitlements (user_id, plan, status, updated_at) VALUES (?, ?, ?, ?)')
        .bind(userId, 'free', 'active', nowIso())
        .run()
      const setupToken = await createOneTimeToken(env.DB, 'setup_tokens', userId, 30)
      await audit(env.DB, userId, 'register', ipH, true, '')
      safeLog('register', { userId, ok: true })
      return jsonResponse(env, request, 201, { ok: true, userId, email, status: 'pending_mfa', setupToken })
    }

    // ---- Public: login (password step) ----
    if (method === 'POST' && path === '/auth/login') {
      if (!checkRate(env, request, 'login')) return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
      if (!originOk(env, request)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      const body = await readJson(request)
      const email = normalizeEmail(body.email)
      const password = body.password
      if (!isValidEmail(email) || typeof password !== 'string') {
        return errorResponse(env, request, 401, 'Invalid email or password.', 'INVALID_CREDENTIALS')
      }
      const user = await getUserByEmail(env.DB, email)
      // Dummy hash for timing equalisation when the user does not exist.
      const dummyHash = await hashPassword('dummy-password-for-timing', iterations(env))
      const passwordOk = user ? await verifyPassword(password, user.password_hash) : await verifyPassword(password, dummyHash)
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
      if (!originOk(env, request)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      const body = await readJson(request)
      let user = null
      let setupRow = null
      if (body.setupToken) {
        setupRow = await consumeOneTimeToken(env.DB, 'setup_tokens', body.setupToken)
        // consumeOneTimeToken only looks up; do NOT delete yet (retry allowed)
        if (!setupRow) return errorResponse(env, request, 400, 'Setup session expired. Please log in again.', 'INVALID_SETUP')
        // Re-lookup without deleting: consumeOneTimeToken above did not delete, so re-fetch is safe.
        user = await getUserById(env.DB, setupRow.user_id)
      } else {
        const { session, error } = await requireSession(request, env)
        if (error) return errorResponse(env, request, 401, 'Please log in again.', 'UNAUTHORIZED')
        if (!body.currentPassword || !(await verifyPassword(body.currentPassword, session.user.password_hash))) {
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
      if (!checkRate(env, request, 'mfaVerify')) return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
      if (!originOk(env, request)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      const body = await readJson(request)
      const code = body.code
      // A) Registration setup
      if (body.setupToken) {
        const setupRow = await consumeOneTimeToken(env.DB, 'setup_tokens', body.setupToken)
        if (!setupRow) return errorResponse(env, request, 400, 'Setup session expired. Please log in again.', 'INVALID_SETUP')
        const pending = await env.DB.prepare('SELECT * FROM pending_mfa_secrets WHERE user_id = ?').bind(setupRow.user_id).first()
        if (!pending || new Date(pending.expires_at).getTime() <= Date.now() || !/^\d{6}$/.test(String(code || ''))) {
          return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
        }
        const secret = await decryptSecret(env, pending.encrypted_secret)
        const res = await verifyTotp(secret, code, null)
        if (!res.ok) return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
        await env.DB.prepare('DELETE FROM mfa_secrets WHERE user_id = ?').bind(setupRow.user_id).run()
        await env.DB.prepare('INSERT INTO mfa_secrets (user_id, encrypted_secret, enabled, last_used_step, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
          .bind(setupRow.user_id, pending.encrypted_secret, 1, res.step, nowIso(), nowIso())
          .run()
        await env.DB.prepare('UPDATE users SET status = ?, mfa_enabled = ?, updated_at = ? WHERE id = ?')
          .bind('active', 1, nowIso(), setupRow.user_id)
          .run()
        await env.DB.prepare('DELETE FROM setup_tokens WHERE user_id = ?').bind(setupRow.user_id).run()
        await env.DB.prepare('DELETE FROM pending_mfa_secrets WHERE user_id = ?').bind(setupRow.user_id).run()
        const codes = generateRecoveryCodes(10)
        const stmts = [env.DB.prepare('DELETE FROM recovery_codes WHERE user_id = ?').bind(setupRow.user_id)]
        for (const c of codes) {
          const h = await sha256Hex(normalizeRecoveryCode(c))
          stmts.push(env.DB.prepare('INSERT INTO recovery_codes (id, user_id, code_hash, used, created_at) VALUES (?, ?, ?, ?, ?)').bind(randomToken(16), setupRow.user_id, h, 0, nowIso()))
        }
        await env.DB.batch(stmts)
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
        const challenge = await consumeOneTimeToken(env.DB, 'login_challenges', body.challengeToken)
        if (!challenge) return errorResponse(env, request, 400, 'Login session expired. Please log in again.', 'INVALID_CHALLENGE')
        const user = await getUserById(env.DB, challenge.user_id)
        if (!user || user.status !== 'active') return errorResponse(env, request, 400, 'Login session expired. Please log in again.', 'INVALID_CHALLENGE')
        const res = await verifyMfaCode(env.DB, env, user, code)
        if (!res.ok) return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
        await env.DB.prepare('DELETE FROM login_challenges WHERE user_id = ?').bind(user.id).run()
        const session = await createSession(env.DB, user.id, userAgent, ipH)
        await audit(env.DB, user.id, 'login', ipH, true, res.via)
        return jsonResponse(env, request, 200, { ok: true, user: publicUser(user), csrfToken: session.csrfToken }, { 'Set-Cookie': sessionCookie(session.token, env) })
      }
      // C) Authenticated re-setup
      const { session, error } = await requireSession(request, env)
      if (error) return errorResponse(env, request, 401, 'Please log in again.', 'UNAUTHORIZED')
      const pending = await env.DB.prepare('SELECT * FROM pending_mfa_secrets WHERE user_id = ?').bind(session.user.id).first()
      if (!pending || !/^\d{6}$/.test(String(code || ''))) return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
      const secret = await decryptSecret(env, pending.encrypted_secret)
      const res = await verifyTotp(secret, code, null)
      if (!res.ok) return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
      await env.DB.prepare('DELETE FROM mfa_secrets WHERE user_id = ?').bind(session.user.id).run()
      await env.DB.prepare('INSERT INTO mfa_secrets (user_id, encrypted_secret, enabled, last_used_step, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
        .bind(session.user.id, pending.encrypted_secret, 1, res.step, nowIso(), nowIso())
        .run()
      await env.DB.prepare('DELETE FROM pending_mfa_secrets WHERE user_id = ?').bind(session.user.id).run()
      await env.DB.prepare('UPDATE users SET mfa_enabled = ?, updated_at = ? WHERE id = ?').bind(1, nowIso(), session.user.id).run()
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
    if (method === 'POST' && path === '/auth/logout') {
      const session = await getSession(request, env)
      if (session) await deleteSessionByHash(env.DB, session.tokenHash)
      return jsonResponse(env, request, 200, { ok: true }, { 'Set-Cookie': clearCookie(env) })
    }
    if (method === 'POST' && path === '/auth/logout-all') {
      const { session, error } = await requireSession(request, env)
      if (error) return errorResponse(env, request, 401, 'Please log in again.', 'UNAUTHORIZED')
      await deleteAllSessions(env.DB, session.user.id)
      await audit(env.DB, session.user.id, 'logout_all', ipH, true, '')
      return jsonResponse(env, request, 200, { ok: true }, { 'Set-Cookie': clearCookie(env) })
    }

    // ---- Password change (logged in) ----
    if (method === 'POST' && path === '/auth/password/change') {
      const { session, error } = await requireSession(request, env)
      if (error) return errorResponse(env, request, 401, 'Please log in again.', 'UNAUTHORIZED')
      if (!csrfOk(env, request, session)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      if (!checkRate(env, request, 'passwordChange')) return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
      const body = await readJson(request)
      if (!(await verifyPassword(body.currentPassword, session.user.password_hash))) {
        return errorResponse(env, request, 401, 'Current password is incorrect.', 'INVALID_CREDENTIALS')
      }
      if (session.user.mfa_enabled === 1) {
        const res = await verifyMfaCode(env.DB, env, session.user, body.mfaCode)
        if (!res.ok) return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
      }
      if (!isValidPassword(body.newPassword)) return errorResponse(env, request, 400, 'New password must be at least 12 characters.', 'VALIDATION')
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
      if (!checkRate(env, request, 'forgot')) return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
      if (!originOk(env, request)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      const body = await readJson(request)
      const email = normalizeEmail(body.email)
      const user = isValidEmail(email) ? await getUserByEmail(env.DB, email) : null
      if (!user || user.status !== 'active') {
        // Generic response: do not reveal whether the email exists.
        return jsonResponse(env, request, 200, { ok: true, message: 'If an account exists, a recovery step is available. Please check your authenticator or recovery codes.' })
      }
      const res = await verifyMfaCode(env.DB, env, user, body.code)
      if (!res.ok) return errorResponse(env, request, 400, 'Invalid email or recovery code.', 'INVALID_CODE')
      const recoveryToken = randomToken(32)
      const hash = await sha256Hex(recoveryToken)
      await env.DB.prepare('INSERT INTO recovery_transactions (id, user_id, token_hash, created_at, expires_at, used) VALUES (?, ?, ?, ?, ?, ?)')
        .bind(randomToken(16), user.id, hash, nowIso(), isoPlus(15 * 60 * 1000), 0)
        .run()
      await audit(env.DB, user.id, 'password_forgot', ipH, true, res.via)
      return jsonResponse(env, request, 200, { ok: true, recoveryToken, expiresIn: 900 })
    }
    // ---- Forgot password (step 2: reset) ----
    if (method === 'POST' && path === '/auth/password/reset') {
      if (!checkRate(env, request, 'reset')) return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
      if (!originOk(env, request)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      const body = await readJson(request)
      if (!isValidPassword(body.newPassword)) return errorResponse(env, request, 400, 'New password must be at least 12 characters.', 'VALIDATION')
      const tx = await consumeOneTimeToken(env.DB, 'recovery_transactions', body.recoveryToken)
      if (!tx) return errorResponse(env, request, 400, 'Invalid or expired recovery link.', 'INVALID_RECOVERY')
      const user = await getUserById(env.DB, tx.user_id)
      if (!user) return errorResponse(env, request, 400, 'Invalid or expired recovery link.', 'INVALID_RECOVERY')
      const newHash = await hashPassword(body.newPassword, iterations(env))
      await env.DB.prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?').bind(newHash, nowIso(), user.id).run()
      await env.DB.prepare('UPDATE recovery_transactions SET used = 1 WHERE token_hash = ?').bind(await sha256Hex(body.recoveryToken)).run()
      await env.DB.prepare('DELETE FROM recovery_transactions WHERE user_id = ?').bind(user.id).run()
      await deleteAllSessions(env.DB, user.id)
      await audit(env.DB, user.id, 'password_reset', ipH, true, '')
      return jsonResponse(env, request, 200, { ok: true, message: 'Password changed. Please log in again.' })
    }

    // ---- Recovery codes regenerate (atomic) ----
    if (method === 'POST' && path === '/auth/recovery-codes/regenerate') {
      const { session, error } = await requireSession(request, env)
      if (error) return errorResponse(env, request, 401, 'Please log in again.', 'UNAUTHORIZED')
      if (!csrfOk(env, request, session)) return errorResponse(env, request, 403, 'Request not allowed.', 'FORBIDDEN')
      if (!checkRate(env, request, 'regenerate')) return errorResponse(env, request, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
      const body = await readJson(request)
      if (!(await verifyPassword(body.currentPassword, session.user.password_hash))) {
        return errorResponse(env, request, 401, 'Current password is incorrect.', 'INVALID_CREDENTIALS')
      }
      // Authenticator code only (TOTP) for regeneration, per spec.
      if (!/^\d{6}$/.test(String(body.mfaCode || ''))) return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
      const secretRow = await env.DB.prepare('SELECT * FROM mfa_secrets WHERE user_id = ? AND enabled = 1').bind(session.user.id).first()
      if (!secretRow) return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
      const secret = await decryptSecret(env, secretRow.encrypted_secret)
      const res = await verifyTotp(secret, body.mfaCode, secretRow.last_used_step)
      if (!res.ok) return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
      await env.DB.prepare('UPDATE mfa_secrets SET last_used_step = ? WHERE user_id = ?').bind(res.step, session.user.id).run()
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
      const body = await readJson(request)
      if (!(await verifyPassword(body.currentPassword, session.user.password_hash))) {
        return errorResponse(env, request, 401, 'Current password is incorrect.', 'INVALID_CREDENTIALS')
      }
      const res = await verifyMfaCode(env.DB, env, session.user, body.mfaCode)
      if (!res.ok) return errorResponse(env, request, 400, 'Invalid authenticator code.', 'INVALID_CODE')
      await env.DB.prepare('DELETE FROM mfa_secrets WHERE user_id = ?').bind(session.user.id).run()
      await env.DB.prepare('DELETE FROM pending_mfa_secrets WHERE user_id = ?').bind(session.user.id).run()
      await env.DB.prepare('DELETE FROM recovery_codes WHERE user_id = ?').bind(session.user.id).run()
      await env.DB.prepare('UPDATE users SET mfa_enabled = ?, updated_at = ? WHERE id = ?').bind(0, nowIso(), session.user.id).run()
      await deleteAllSessions(env.DB, session.user.id)
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
      if (!body.sessionId || body.sessionId === session.id) return errorResponse(env, request, 400, 'Cannot revoke the current session here. Use Log out.', 'VALIDATION')
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
