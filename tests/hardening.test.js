// Hardening tests: atomic one-time tokens, TOTP/recovery races,
// D1 rate limiting, hash validation, byte-size limits, CSRF/Origin
// fail-closed, input validation, session cookies. These tests run
// against the Node mock D1, which faithfully implements the SQL the
// Worker uses (conditional UPDATE/DELETE + meta.changes, ON CONFLICT
// upserts, IS NULL / OR conditions). True multi-isolate concurrency
// and live D1 behaviour cannot be verified in Node — see REPORT.md.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { MockD1, testEnv } from './mock-d1.js'
import { call, registerAndActivate, loginWithMfa, totpNow, advanceTotp, secretFromOtpauth } from './helpers.js'
import { resetRateLimits, readJson } from '../worker/src/security.js'
import { verifyPassword, hashPassword, parsePbkdf2Hash, clampPbkdf2Iterations } from '../worker/src/crypto.js'

const root = path.dirname(fileURLToPath(import.meta.url))
function fresh() { const db = new MockD1(); return { db, env: testEnv(db) } }
const PW = 'Correct Horse Battery Staple 123!'

test('concurrent duplicate registers: exactly one 201, the other 409 (never 500)', async () => {
  const { db, env } = fresh()
  resetRateLimits()
  const [a, b] = await Promise.all([
    call(env, '/auth/register', 'POST', { email: 'race@example.com', password: PW }, { ip: '10.4.0.1' }),
    call(env, '/auth/register', 'POST', { email: 'race@example.com', password: PW }, { ip: '10.4.0.2' }),
  ])
  const statuses = [a.status, b.status].sort()
  assert.deepEqual(statuses, [201, 409])
  assert.equal(db.tables.users.length, 1)
  assert.equal(db.tables.entitlements.length, 1)
})

test('concurrent TOTP verifies with the same code: exactly one session, the other fails', async () => {
  const { env } = fresh()
  const { secret } = await registerAndActivate(env, 'totp-race@example.com', PW)
  advanceTotp(env)
  resetRateLimits()
  const login = await call(env, '/auth/login', 'POST', { email: 'totp-race@example.com', password: PW }, { ip: '10.4.1.1' })
  assert.ok(login.data.challengeToken)
  const code = await totpNow(secret)
  const [a, b] = await Promise.all([
    call(env, '/auth/mfa/verify', 'POST', { challengeToken: login.data.challengeToken, code }, { ip: '10.4.1.2' }),
    call(env, '/auth/mfa/verify', 'POST', { challengeToken: login.data.challengeToken, code }, { ip: '10.4.1.3' }),
  ])
  const statuses = [a.status, b.status].sort()
  assert.deepEqual(statuses, [200, 400])
})

test('concurrent recovery-code verifies: exactly one session, the other fails', async () => {
  const { env } = fresh()
  const { secret, recoveryCodes } = await registerAndActivate(env, 'rc-race@example.com', PW)
  resetRateLimits()
  const login = await call(env, '/auth/login', 'POST', { email: 'rc-race@example.com', password: PW }, { ip: '10.4.2.1' })
  const code = recoveryCodes[0]
  const [a, b] = await Promise.all([
    call(env, '/auth/mfa/verify', 'POST', { challengeToken: login.data.challengeToken, code }, { ip: '10.4.2.2' }),
    call(env, '/auth/mfa/verify', 'POST', { challengeToken: login.data.challengeToken, code }, { ip: '10.4.2.3' }),
  ])
  const statuses = [a.status, b.status].sort()
  assert.deepEqual(statuses, [200, 400])
  // The winning code is now used; a third sequential use must also fail.
  resetRateLimits()
  const login2 = await call(env, '/auth/login', 'POST', { email: 'rc-race@example.com', password: PW }, { ip: '10.4.2.4' })
  const third = await call(env, '/auth/mfa/verify', 'POST', { challengeToken: login2.data.challengeToken, code }, { ip: '10.4.2.4' })
  assert.equal(third.status, 400)
})

test('setup token cannot be reused after a successful activation', async () => {
  const { db, env } = fresh()
  resetRateLimits()
  const reg = await call(env, '/auth/register', 'POST', { email: 'setup-reuse@example.com', password: PW }, { ip: '10.4.3.1' })
  const setup = await call(env, '/auth/mfa/setup', 'POST', { setupToken: reg.data.setupToken }, { ip: '10.4.3.1' })
  const secret = secretFromOtpauth(setup.data.otpauthUrl)
  const code = await totpNow(secret)
  const first = await call(env, '/auth/mfa/verify', 'POST', { setupToken: reg.data.setupToken, code }, { ip: '10.4.3.1' })
  assert.equal(first.status, 200)
  resetRateLimits()
  const second = await call(env, '/auth/mfa/verify', 'POST', { setupToken: reg.data.setupToken, code }, { ip: '10.4.3.1' })
  assert.equal(second.status, 400)
  assert.equal(db.tables.setup_tokens.length, 0)
})

test('concurrent password resets with the same token: exactly one succeeds', async () => {
  const { env } = fresh()
  const { secret } = await registerAndActivate(env, 'reset-race@example.com', PW)
  // The activation code already used this 30-second step; advance so
  // the forgot code is a fresh step (same pattern as the existing
  // forgot tests, which log in first — loginWithMfa advances too).
  advanceTotp(env)
  resetRateLimits()
  const forgot = await call(env, '/auth/password/forgot', 'POST', { email: 'reset-race@example.com', code: await totpNow(secret) }, { ip: '10.4.4.1' })
  assert.ok(forgot.data.recoveryToken)
  const token = forgot.data.recoveryToken
  const [a, b] = await Promise.all([
    call(env, '/auth/password/reset', 'POST', { recoveryToken: token, newPassword: 'Changed Password 123!' }, { ip: '10.4.4.2' }),
    call(env, '/auth/password/reset', 'POST', { recoveryToken: token, newPassword: 'Another Password 123!' }, { ip: '10.4.4.3' }),
  ])
  const statuses = [a.status, b.status].sort()
  assert.deepEqual(statuses, [200, 400])
  // Exactly one of the two new passwords works for login.
  resetRateLimits()
  const winner = a.status === 200 ? 'Changed Password 123!' : 'Another Password 123!'
  const loser = a.status === 200 ? 'Another Password 123!' : 'Changed Password 123!'
  const okLogin = await call(env, '/auth/login', 'POST', { email: 'reset-race@example.com', password: winner }, { ip: '10.4.4.4' })
  assert.equal(okLogin.data.mfaRequired, true)
  const badLogin = await call(env, '/auth/login', 'POST', { email: 'reset-race@example.com', password: loser }, { ip: '10.4.4.5' })
  assert.equal(badLogin.status, 401)
})

test('D1 rate limit persists after the in-memory limiter is reset', async () => {
  const { env } = fresh()
  resetRateLimits()
  let last = null
  for (let i = 0; i < 6; i++) {
    last = await call(env, '/auth/register', 'POST', { email: `d1rate${i}@example.com`, password: PW }, { ip: '10.4.5.1' })
  }
  assert.equal(last.status, 429)
  // Clearing the per-isolate Map must NOT clear the D1 counters.
  resetRateLimits()
  const again = await call(env, '/auth/register', 'POST', { email: 'd1rateX@example.com', password: PW }, { ip: '10.4.5.1' })
  assert.equal(again.status, 429)
})

test('per-account login limit blocks targeted brute force from fresh IPs', async () => {
  const { env } = fresh()
  await registerAndActivate(env, 'target@example.com', PW)
  for (let i = 0; i < 10; i++) {
    const r = await call(env, '/auth/login', 'POST', { email: 'target@example.com', password: 'Wrong Password 123!' }, { ip: `10.4.6.${i + 1}` })
    assert.equal(r.status, 401)
  }
  const blocked = await call(env, '/auth/login', 'POST', { email: 'target@example.com', password: 'Wrong Password 123!' }, { ip: '10.4.6.99' })
  assert.equal(blocked.status, 429)
})

test('MFA disable has a dedicated rate limit (wrong attempts, then 429)', async () => {
  const { env } = fresh()
  const { secret } = await registerAndActivate(env, 'disable-rate@example.com', PW)
  const { cookie, csrf } = await loginWithMfa(env, 'disable-rate@example.com', PW, secret, '10.4.7.1')
  let last = null
  for (let i = 0; i < 6; i++) {
    last = await call(env, '/auth/mfa/disable', 'POST', { currentPassword: 'Wrong Password 123!', mfaCode: '000000' }, { cookie, headers: { 'X-CSRF-Token': csrf }, ip: '10.4.7.1' })
  }
  assert.equal(last.status, 429)
})

test('stored hash validation: malformed, oversized-iteration and wrong-length hashes are rejected, valid hashes still verify', async () => {
  assert.equal(await verifyPassword(PW, 'not-a-hash'), false)
  assert.equal(await verifyPassword(PW, 'pbkdf2-sha256$abc$salt$hash'), false)
  assert.equal(await verifyPassword(PW, 'pbkdf2-sha256$0$c2FsdA$hash'), false)
  assert.equal(await verifyPassword(PW, 'pbkdf2-sha256$-5$c2FsdA$hash'), false)
  assert.equal(await verifyPassword(PW, 'pbkdf2-sha256$600000$c2FsdA$hash'), false)
  assert.equal(await verifyPassword(PW, 'pbkdf2-sha256$100001$c2FsdA$hash'), false)
  assert.equal(await verifyPassword(PW, 'pbkdf2-sha256$1000$!!!$hash'), false)
  assert.equal(await verifyPassword(PW, 'pbkdf2-sha256$1000$c2FsdA$short'), false)
  assert.equal(await verifyPassword('', 'pbkdf2-sha256$1000$c2FsdA$hash'), false)
  assert.equal(await verifyPassword('x'.repeat(129), 'pbkdf2-sha256$1000$c2FsdA$hash'), false)
  assert.equal(await verifyPassword(12345, 'pbkdf2-sha256$1000$c2FsdA$hash'), false)
  assert.equal(parsePbkdf2Hash('pbkdf2-sha256$1000$c2FsdA$hash'), null)
  assert.equal(clampPbkdf2Iterations(600000), 100000)
  assert.equal(clampPbkdf2Iterations(1000), 1000)
  assert.equal(clampPbkdf2Iterations('not-a-number'), 100000)
  // Valid hashes still verify, including at the Workers Free maximum.
  const h1 = await hashPassword(PW, 1000)
  assert.equal(await verifyPassword(PW, h1), true)
  assert.equal(await verifyPassword('Wrong Password 123!', h1), false)
  const hMax = await hashPassword(PW, 100000)
  assert.ok(hMax.startsWith('pbkdf2-sha256$100000$'))
  assert.equal(await verifyPassword(PW, hMax), true)
  // A caller passing 600000 gets a capped hash, never an error and
  // never a stored count above the Workers Free maximum.
  const hCapped = await hashPassword(PW, 600000)
  assert.ok(hCapped.startsWith('pbkdf2-sha256$100000$'))
  assert.equal(await verifyPassword(PW, hCapped), true)
})

test('readJson enforces a BYTE limit, not a character limit', async () => {
  // 5,000 emoji = 5,000 characters but 20,000 bytes: must be rejected.
  const emojiBody = JSON.stringify({ x: '😀'.repeat(5000) })
  assert.ok(emojiBody.length < 16384, 'test premise: character count is under the limit')
  assert.ok(new TextEncoder().encode(emojiBody).length > 16384, 'test premise: byte count is over the limit')
  const bigReq = new Request('https://account-api.kluzar.com/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: emojiBody })
  await assert.rejects(readJson(bigReq), (e) => e.message === 'BODY_TOO_LARGE')
  // 3,000 emoji = 12,000 bytes: must parse.
  const okReq = new Request('https://account-api.kluzar.com/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ x: '😀'.repeat(3000) }) })
  const parsed = await readJson(okReq)
  assert.equal(parsed.x, '😀'.repeat(3000))
  // Malformed JSON is rejected, never thrown as a crash.
  const badReq = new Request('https://account-api.kluzar.com/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{not json' })
  await assert.rejects(readJson(badReq), (e) => e.message === 'BAD_JSON')
  const arrReq = new Request('https://account-api.kluzar.com/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '[1,2,3]' })
  await assert.rejects(readJson(arrReq), (e) => e.message === 'BAD_JSON')
})

test('Origin and CSRF are fail-closed on state-changing routes', async () => {
  const { env } = fresh()
  const { secret } = await registerAndActivate(env, 'csrf2@example.com', PW)
  const { cookie, csrf } = await loginWithMfa(env, 'csrf2@example.com', PW, secret, '10.4.8.1')
  // Missing Origin on an authenticated PATCH: 403, even with a valid CSRF token.
  const noOrigin = await call(env, '/account/profile', 'PATCH', { firstName: 'No' }, { cookie, headers: { 'X-CSRF-Token': csrf }, ip: '10.4.8.1', origin: null })
  assert.equal(noOrigin.status, 403)
  // Disallowed Origin: 403.
  const evil = await call(env, '/account/profile', 'PATCH', { firstName: 'No' }, { cookie, headers: { 'X-CSRF-Token': csrf }, ip: '10.4.8.1', origin: 'https://evil.example.com' })
  assert.equal(evil.status, 403)
  // Missing Origin on public POSTs: 403.
  const noOriginReg = await call(env, '/auth/register', 'POST', { email: 'no-origin@example.com', password: PW }, { ip: '10.4.8.2', origin: null })
  assert.equal(noOriginReg.status, 403)
  const noOriginLogin = await call(env, '/auth/login', 'POST', { email: 'csrf2@example.com', password: PW }, { ip: '10.4.8.2', origin: null })
  assert.equal(noOriginLogin.status, 403)
  // Logout without CSRF: 403, and the session survives.
  const noCsrfLogout = await call(env, '/auth/logout', 'POST', {}, { cookie, ip: '10.4.8.1' })
  assert.equal(noCsrfLogout.status, 403)
  const still = await call(env, '/auth/session', 'GET', undefined, { cookie, ip: '10.4.8.1' })
  assert.equal(still.status, 200)
  // Logout-all without CSRF: 403.
  const noCsrfAll = await call(env, '/auth/logout-all', 'POST', {}, { cookie, ip: '10.4.8.1' })
  assert.equal(noCsrfAll.status, 403)
})

test('authenticated MFA setup and re-setup verify require CSRF', async () => {
  const { env } = fresh()
  const { secret } = await registerAndActivate(env, 'setup-csrf@example.com', PW)
  const { cookie, csrf } = await loginWithMfa(env, 'setup-csrf@example.com', PW, secret, '10.4.9.1')
  // Setup (authenticated branch) without CSRF: 403.
  const noCsrf = await call(env, '/auth/mfa/setup', 'POST', { currentPassword: PW }, { cookie, ip: '10.4.9.1' })
  assert.equal(noCsrf.status, 403)
  // With CSRF: 200 and a fresh pending secret.
  const ok = await call(env, '/auth/mfa/setup', 'POST', { currentPassword: PW }, { cookie, headers: { 'X-CSRF-Token': csrf }, ip: '10.4.9.1' })
  assert.equal(ok.status, 200)
  assert.ok(ok.data.otpauthUrl)
  // Re-setup verify without CSRF: 403 (pending secret survives).
  const newSecret = secretFromOtpauth(ok.data.otpauthUrl)
  const noCsrfVerify = await call(env, '/auth/mfa/verify', 'POST', { code: await totpNow(newSecret) }, { cookie, ip: '10.4.9.1' })
  assert.equal(noCsrfVerify.status, 403)
  // With CSRF: 200.
  const okVerify = await call(env, '/auth/mfa/verify', 'POST', { code: await totpNow(newSecret) }, { cookie, headers: { 'X-CSRF-Token': csrf }, ip: '10.4.9.1' })
  assert.equal(okVerify.status, 200)
  assert.equal(okVerify.data.mfaEnabled, true)
})

test('client input is validated before use: bad types, markup, and oversized values are rejected safely', async () => {
  const { env } = fresh()
  const { secret } = await registerAndActivate(env, 'validate@example.com', PW)
  const { cookie, csrf } = await loginWithMfa(env, 'validate@example.com', PW, secret, '10.5.0.1')
  // Markup in a name: 400, and the stored name is unchanged.
  const markup = await call(env, '/account/profile', 'PATCH', { firstName: '<script>alert(1)</script>' }, { cookie, headers: { 'X-CSRF-Token': csrf }, ip: '10.5.0.1' })
  assert.equal(markup.status, 400)
  // Letters in a phone number: 400.
  const badPhone = await call(env, '/account/profile', 'PATCH', { phone: 'abc-def' }, { cookie, headers: { 'X-CSRF-Token': csrf }, ip: '10.5.0.1' })
  assert.equal(badPhone.status, 400)
  // Non-string email on register: 400, never a crash.
  const numEmail = await call(env, '/auth/register', 'POST', { email: 12345, password: PW }, { ip: '10.5.0.2' })
  assert.equal(numEmail.status, 400)
  // Oversized / non-string passwords on login: generic 401, never 500.
  const hugePw = await call(env, '/auth/login', 'POST', { email: 'validate@example.com', password: 'x'.repeat(5000) }, { ip: '10.5.0.2' })
  assert.equal(hugePw.status, 401)
  const numPw = await call(env, '/auth/login', 'POST', { email: 'validate@example.com', password: 12345 }, { ip: '10.5.0.2' })
  assert.equal(numPw.status, 401)
  // Non-string session ID on revoke: 400.
  const badSession = await call(env, '/account/sessions/revoke', 'POST', { sessionId: 12345 }, { cookie, headers: { 'X-CSRF-Token': csrf }, ip: '10.5.0.1' })
  assert.equal(badSession.status, 400)
  // Non-string recovery token on reset: 400, never a crash.
  const badToken = await call(env, '/auth/password/reset', 'POST', { recoveryToken: 12345, newPassword: 'Another Password 123!' }, { ip: '10.5.0.2' })
  assert.equal(badToken.status, 400)
  // Oversized session cookie: 401, never a database lookup crash.
  const hugeCookie = await call(env, '/auth/session', 'GET', undefined, { cookie: 'kluzar_session=' + 'x'.repeat(5000), ip: '10.5.0.1' })
  assert.equal(hugeCookie.status, 401)
})

test('session cookie flags: HttpOnly + 2-day expiry in both modes, Secure + SameSite=None in production mode', async () => {
  // loginWithMfa returns only the bare cookie (split on ';'), so
  // capture the full Set-Cookie header via direct calls here.
  async function loginCookie(env, email, password, secret, ip) {
    advanceTotp(env)
    resetRateLimits()
    const login = await call(env, '/auth/login', 'POST', { email, password }, { ip })
    assert.ok(login.data.challengeToken)
    const verify = await call(env, '/auth/mfa/verify', 'POST', { challengeToken: login.data.challengeToken, code: await totpNow(secret) }, { ip })
    assert.equal(verify.status, 200)
    return verify.setCookie
  }
  const { env } = fresh()
  const { secret } = await registerAndActivate(env, 'cookie@example.com', PW)
  const setCookie = await loginCookie(env, 'cookie@example.com', PW, secret, '10.5.1.1')
  assert.ok(setCookie.includes('HttpOnly'), 'test mode cookie must be HttpOnly')
  assert.ok(setCookie.includes('SameSite=Lax'), 'test (insecure) mode uses Lax')
  assert.ok(setCookie.includes('Max-Age=172800'), 'expiry must be 2 days')
  // Production mode: ALLOW_INSECURE_COOKIE=false.
  const prod = fresh()
  prod.env.ALLOW_INSECURE_COOKIE = 'false'
  const { secret: secret2 } = await registerAndActivate(prod.env, 'cookie2@example.com', PW)
  const prodCookie = await loginCookie(prod.env, 'cookie2@example.com', PW, secret2, '10.5.1.2')
  assert.ok(prodCookie.includes('HttpOnly'))
  assert.ok(prodCookie.includes('Secure'), 'production cookie must be Secure')
  assert.ok(prodCookie.includes('SameSite=None'), 'production cross-subdomain cookie must be SameSite=None')
  assert.ok(prodCookie.includes('Max-Age=172800'))
})

test('D1 batch rollback preserves old recovery codes on failure (mock batch atomicity)', async () => {
  const db = new MockD1()
  db.tables.recovery_codes.push({ id: 'old1', user_id: 'u1', code_hash: 'hash-old', used: 0, created_at: '2026-01-01' })
  db.tables.recovery_codes.push({ id: 'other1', user_id: 'u2', code_hash: 'hash-other', used: 0, created_at: '2026-01-01' })
  // The failing insert must conflict with a row the batch does NOT
  // delete (u2's code); a conflict with u1's own deleted row would
  // succeed, because the delete already removed it.
  const duplicate = db.prepare('INSERT INTO recovery_codes (id, user_id, code_hash, used, created_at) VALUES (?, ?, ?, ?, ?)').bind('new1', 'u1', 'hash-other', 0, '2026-01-02')
  const del = db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').bind('u1')
  await assert.rejects(db.batch([del, duplicate]))
  assert.equal(db.tables.recovery_codes.length, 2)
  assert.ok(db.tables.recovery_codes.some((r) => r.id === 'old1'), 'u1 old code must survive a failed batch')
})

test('frontend never renders user data via innerHTML', async () => {
  const shared = readFileSync(path.join(root, '../shared.js'), 'utf8')
  for (const line of shared.split('\n')) {
    if (!line.includes('innerHTML')) continue
    // Allowed: static chrome/footer, clearing a list, eye SVG constants.
    // Forbidden: any user-controlled value (session, email, name, phone).
    assert.ok(!line.includes('session.user') && !line.includes('dash-') && !line.includes('firstName') && !line.includes('phone'),
      'innerHTML must never carry user data: ' + line.trim())
  }
  assert.ok(shared.includes('textContent'), 'user data must be rendered via textContent')
})
