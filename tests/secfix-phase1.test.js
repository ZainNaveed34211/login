import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { MockD1, testEnv } from './mock-d1.js'
import { call, registerAndActivate, secretFromOtpauth, totpNow } from './helpers.js'
import { checkRateD1, checkRateD1Account, resetRateLimits } from '../worker/src/security.js'

const ADMIN_ORIGIN = 'https://admin.kluzar.com'

function fresh() { const db = new MockD1(); return { db, env: testEnv(db) } }

function allowlist(db, userId) {
  db.tables.admin_allowlist.push({ user_id: userId, role: 'super_admin' })
}

function deallowlist(db, userId) {
  db.tables.admin_allowlist = db.tables.admin_allowlist.filter((r) => r.user_id !== userId)
}

async function adminChallenge(env, email, password, ip) {
  return call(env, '/auth/admin-mfa/challenge', 'POST', { email, password }, { ip, origin: ADMIN_ORIGIN })
}

async function adminSetupFlow(env, email, password, ip) {
  const challenge = await adminChallenge(env, email, password, ip)
  assert.equal(challenge.status, 200, 'challenge must succeed: ' + JSON.stringify(challenge.data))
  const setup = await call(env, '/auth/admin-mfa/setup', 'POST', { challengeToken: challenge.data.challengeToken }, { ip, origin: ADMIN_ORIGIN })
  assert.equal(setup.status, 200, 'setup must succeed: ' + JSON.stringify(setup.data))
  const secret = secretFromOtpauth(setup.data.otpauthUrl)
  const code = await totpNow(secret)
  const verify = await call(env, '/auth/admin-mfa/verify-setup', 'POST', { challengeToken: challenge.data.challengeToken, code }, { ip, origin: ADMIN_ORIGIN })
  assert.equal(verify.status, 200, 'verify-setup must succeed: ' + JSON.stringify(verify.data))
  return { secret, cookie: verify.sessionCookie, csrf: verify.data.csrfToken, recoveryCodes: verify.data.recoveryCodes }
}

test('rate-limit cleanup no longer deletes other endpoints buckets', async () => {
  const { db, env } = fresh()
  resetRateLimits()
  await registerAndActivate(env, 'bucket@example.com', 'Correct Horse Battery Staple 123!')
  resetRateLimits()
  const ip = '10.3.0.1'
  for (let i = 0; i < 10; i++) {
    const attempt = await call(env, '/auth/login', 'POST', { email: 'bucket@example.com', password: 'Wrong Password 123!' }, { ip })
    assert.equal(attempt.status, 401)
  }
  const probe = await call(env, '/auth/mfa/verify', 'POST', {}, { ip })
  assert.equal(probe.status, 401)
  const loginRows = db.tables.rate_limits.filter((r) => r.key.startsWith('login:'))
  assert.ok(loginRows.length >= 2, 'login buckets must survive an mfaVerify call, got: ' + JSON.stringify(db.tables.rate_limits.map((r) => r.key)))
  const next = await call(env, '/auth/login', 'POST', { email: 'bucket@example.com', password: 'Correct Horse Battery Staple 123!' }, { ip })
  assert.equal(next.status, 429)
  assert.equal(next.data.code, 'RATE_LIMITED')
})

test('fail-closed limiters return 429 on D1 errors, other limiters keep the memory fallback', async () => {
  resetRateLimits()
  const throwing = { prepare() { throw new Error('D1 down') } }
  const throwingEnv = { DB: throwing, IP_HASH_SECRET: 'test-ip-hash-secret' }
  const req = new Request('https://account-api.kluzar.com/auth/login', { method: 'POST', headers: { 'CF-Connecting-IP': '10.4.0.1' } })
  assert.equal(await checkRateD1(throwingEnv, req, 'login'), false)
  assert.equal(await checkRateD1(throwingEnv, req, 'adminMfaVerify'), false)
  assert.equal(await checkRateD1(throwingEnv, req, 'forgot'), false)
  assert.equal(await checkRateD1Account(throwing, 'login', 'acct-1'), false)
  assert.equal(await checkRateD1(throwingEnv, req, 'manageAssertion'), true)
  assert.equal(await checkRateD1Account(throwing, 'manageAssertion', 'acct-1'), true)
})

test('login returns 429 when D1 rate limiting fails', async () => {
  const { env } = fresh()
  resetRateLimits()
  const throwingEnv = { ...env, DB: { prepare() { throw new Error('D1 down') }, batch() { throw new Error('D1 down') } } }
  const res = await call(throwingEnv, '/auth/login', 'POST', { email: 'someone@example.com', password: 'Whatever Password 123!' }, { ip: '10.4.0.2' })
  assert.equal(res.status, 429)
  assert.equal(res.data.code, 'RATE_LIMITED')
})

test('non-allowlisted account with the correct password gets the generic 401 and no challenge', async () => {
  const { db, env } = fresh()
  resetRateLimits()
  const { userId } = await registerAndActivate(env, 'plain@example.com', 'Correct Horse Battery Staple 123!')
  resetRateLimits()
  const denied = await adminChallenge(env, 'plain@example.com', 'Correct Horse Battery Staple 123!', '10.5.0.1')
  assert.equal(denied.status, 401)
  assert.equal(denied.data.error, 'Invalid email or password.')
  assert.equal(denied.data.code, 'INVALID_CREDENTIALS')
  assert.ok(!denied.data.challengeToken)
  const deniedAudit = db.tables.audit_events.find((r) => r.user_id === userId && r.event_type === 'admin_challenge_denied')
  assert.ok(deniedAudit, 'admin_challenge_denied audit must exist')
  const wrong = await adminChallenge(env, 'plain@example.com', 'Wrong Password 123!', '10.5.0.2')
  assert.equal(wrong.status, 401)
  assert.equal(wrong.data.error, denied.data.error)
  assert.equal(wrong.data.code, denied.data.code)
})

test('allowlisted account completes the admin MFA flow; suspended account is denied', async () => {
  const { db, env } = fresh()
  resetRateLimits()
  const { userId } = await registerAndActivate(env, 'admin1@example.com', 'Correct Horse Battery Staple 123!')
  allowlist(db, userId)
  resetRateLimits()
  const challenge = await adminChallenge(env, 'admin1@example.com', 'Correct Horse Battery Staple 123!', '10.5.0.3')
  assert.equal(challenge.status, 200)
  assert.ok(challenge.data.challengeToken)
  assert.equal(challenge.data.adminMfaSetup, false)
  db.tables.users[0].status = 'suspended'
  resetRateLimits()
  const suspended = await adminChallenge(env, 'admin1@example.com', 'Correct Horse Battery Staple 123!', '10.5.0.4')
  assert.equal(suspended.status, 401)
  assert.ok(!suspended.data.challengeToken)
})

test('allowlist re-check blocks setup, verify-setup and verify after removal', async () => {
  const { db, env } = fresh()
  resetRateLimits()
  const { userId } = await registerAndActivate(env, 'admin2@example.com', 'Correct Horse Battery Staple 123!')
  allowlist(db, userId)
  resetRateLimits()
  const challenge = await adminChallenge(env, 'admin2@example.com', 'Correct Horse Battery Staple 123!', '10.6.0.1')
  assert.equal(challenge.status, 200)
  deallowlist(db, userId)
  const setup = await call(env, '/auth/admin-mfa/setup', 'POST', { challengeToken: challenge.data.challengeToken }, { ip: '10.6.0.1', origin: ADMIN_ORIGIN })
  assert.equal(setup.status, 400)
  assert.equal(setup.data.code, 'INVALID_SETUP')
  allowlist(db, userId)
  const setup2 = await call(env, '/auth/admin-mfa/setup', 'POST', { challengeToken: challenge.data.challengeToken }, { ip: '10.6.0.2', origin: ADMIN_ORIGIN })
  assert.equal(setup2.status, 200)
  const secret = secretFromOtpauth(setup2.data.otpauthUrl)
  deallowlist(db, userId)
  const code = await totpNow(secret)
  const verifySetup = await call(env, '/auth/admin-mfa/verify-setup', 'POST', { challengeToken: challenge.data.challengeToken, code }, { ip: '10.6.0.3', origin: ADMIN_ORIGIN })
  assert.equal(verifySetup.status, 400)
  assert.equal(verifySetup.data.code, 'INVALID_SETUP')
  allowlist(db, userId)
  const codeFresh = await totpNow(secret)
  const verifySetup2 = await call(env, '/auth/admin-mfa/verify-setup', 'POST', { challengeToken: challenge.data.challengeToken, code: codeFresh }, { ip: '10.6.0.4', origin: ADMIN_ORIGIN })
  assert.equal(verifySetup2.status, 200)
  const challenge2 = await adminChallenge(env, 'admin2@example.com', 'Correct Horse Battery Staple 123!', '10.6.0.5')
  assert.equal(challenge2.status, 200)
  deallowlist(db, userId)
  const code2 = await totpNow(secret)
  const verify = await call(env, '/auth/admin-mfa/verify', 'POST', { challengeToken: challenge2.data.challengeToken, code: code2 }, { ip: '10.6.0.6', origin: ADMIN_ORIGIN })
  assert.equal(verify.status, 400)
  assert.equal(verify.data.code, 'INVALID_CHALLENGE')
})

test('admin session stops working and is deleted once the account leaves the allowlist', async () => {
  const { db, env } = fresh()
  resetRateLimits()
  const { userId } = await registerAndActivate(env, 'admin3@example.com', 'Correct Horse Battery Staple 123!')
  allowlist(db, userId)
  resetRateLimits()
  const flow = await adminSetupFlow(env, 'admin3@example.com', 'Correct Horse Battery Staple 123!', '10.7.0.1')
  assert.ok(flow.cookie)
  assert.equal(flow.recoveryCodes.length, 10)
  const before = await call(env, '/auth/admin-session', 'GET', undefined, { cookie: flow.cookie, ip: '10.7.0.2', origin: ADMIN_ORIGIN })
  assert.equal(before.status, 200)
  assert.equal(before.data.authenticated, true)
  deallowlist(db, userId)
  const after = await call(env, '/auth/admin-session', 'GET', undefined, { cookie: flow.cookie, ip: '10.7.0.3', origin: ADMIN_ORIGIN })
  assert.equal(after.status, 401)
  assert.equal(after.data.authenticated, false)
  assert.equal(db.tables.sessions.filter((s) => s.scope === 'admin').length, 0, 'de-allowlisted admin session must be deleted')
})

test('admin-scope session is rejected on normal endpoints but logout-all accepts it', async () => {
  const { db, env } = fresh()
  resetRateLimits()
  const { userId } = await registerAndActivate(env, 'admin4@example.com', 'Correct Horse Battery Staple 123!')
  allowlist(db, userId)
  resetRateLimits()
  const flow = await adminSetupFlow(env, 'admin4@example.com', 'Correct Horse Battery Staple 123!', '10.8.0.1')
  const profile = await call(env, '/account/profile', 'GET', undefined, { cookie: flow.cookie, ip: '10.8.0.2' })
  assert.equal(profile.status, 401)
  const logoutAll = await call(env, '/auth/logout-all', 'POST', {}, { cookie: flow.cookie, ip: '10.8.0.3', headers: { 'X-CSRF-Token': flow.csrf } })
  assert.equal(logoutAll.status, 200)
  assert.equal(db.tables.sessions.length, 0)
})

test('logout works with an admin-scope session', async () => {
  const { db, env } = fresh()
  resetRateLimits()
  const { userId } = await registerAndActivate(env, 'admin5@example.com', 'Correct Horse Battery Staple 123!')
  allowlist(db, userId)
  resetRateLimits()
  const flow = await adminSetupFlow(env, 'admin5@example.com', 'Correct Horse Battery Staple 123!', '10.8.0.4')
  const logout = await call(env, '/auth/logout', 'POST', {}, { cookie: flow.cookie, ip: '10.8.0.5', headers: { 'X-CSRF-Token': flow.csrf } })
  assert.equal(logout.status, 200)
  assert.equal(db.tables.sessions.filter((s) => s.scope === 'admin').length, 0)
})

test('purge migration deletes admin leftovers for non-allowlisted users only', async () => {
  const sql = readFileSync(new URL('../migrations/0006_admin_allowlist_purge.sql', import.meta.url), 'utf8')
  for (const table of ['admin_mfa_secrets', 'pending_admin_mfa_secrets', 'admin_recovery_codes', 'admin_challenges']) {
    assert.ok(sql.includes(`DELETE FROM ${table} WHERE user_id NOT IN (SELECT user_id FROM admin_allowlist)`), table)
  }
  assert.ok(sql.includes(`DELETE FROM sessions WHERE scope = 'admin' AND user_id NOT IN (SELECT user_id FROM admin_allowlist)`))
})
