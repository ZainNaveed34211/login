import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { MockD1, testEnv } from './mock-d1.js'
import { call, registerAndActivate, loginWithMfa, secretFromOtpauth, totpNow, advanceTotp } from './helpers.js'
import { ipHash, isValidPassword, resetRateLimits } from '../worker/src/security.js'
import { hashPassword, sha256Hex, normalizeRecoveryCode } from '../worker/src/crypto.js'

const ADMIN_ORIGIN = 'https://admin.kluzar.com'
const GENERIC_FORGOT = 'If an account exists, a recovery step is available. Please check your authenticator or recovery codes.'

function fresh() { const db = new MockD1(); return { db, env: testEnv(db) } }

async function adminSetupFlow(env, email, password, ip) {
  const challenge = await call(env, '/auth/admin-mfa/challenge', 'POST', { email, password }, { ip, origin: ADMIN_ORIGIN })
  assert.equal(challenge.status, 200, 'challenge: ' + JSON.stringify(challenge.data))
  const setup = await call(env, '/auth/admin-mfa/setup', 'POST', { challengeToken: challenge.data.challengeToken }, { ip, origin: ADMIN_ORIGIN })
  assert.equal(setup.status, 200, 'setup: ' + JSON.stringify(setup.data))
  const secret = secretFromOtpauth(setup.data.otpauthUrl)
  const code = await totpNow(secret)
  const verify = await call(env, '/auth/admin-mfa/verify-setup', 'POST', { challengeToken: challenge.data.challengeToken, code }, { ip, origin: ADMIN_ORIGIN })
  assert.equal(verify.status, 200, 'verify-setup: ' + JSON.stringify(verify.data))
  return { secret, cookie: verify.sessionCookie, csrf: verify.data.csrfToken }
}

test('forgot returns identical bodies for unknown email, inactive user and wrong code', async () => {
  const { db, env } = fresh()
  resetRateLimits()
  await registerAndActivate(env, 'forgot3@example.com', 'Correct Horse Battery Staple 123!')
  const unknown = await call(env, '/auth/password/forgot', 'POST', { email: 'nobody@example.com', code: '123456' }, { ip: '10.9.0.1' })
  assert.equal(unknown.status, 200)
  assert.equal(unknown.data.message, GENERIC_FORGOT)
  assert.ok(!unknown.data.recoveryToken)
  db.tables.users[0].status = 'suspended'
  const inactive = await call(env, '/auth/password/forgot', 'POST', { email: 'forgot3@example.com', code: '123456' }, { ip: '10.9.0.2' })
  assert.equal(inactive.status, 200)
  db.tables.users[0].status = 'active'
  const wrong = await call(env, '/auth/password/forgot', 'POST', { email: 'forgot3@example.com', code: '000000' }, { ip: '10.9.0.3' })
  assert.equal(wrong.status, 200)
  assert.deepEqual(unknown.data, inactive.data)
  assert.deepEqual(unknown.data, wrong.data)
})

test('admin session idle timeout deletes the session after 30 minutes', async () => {
  const { db, env } = fresh()
  resetRateLimits()
  const { userId } = await registerAndActivate(env, 'idle@example.com', 'Correct Horse Battery Staple 123!')
  db.tables.admin_allowlist.push({ user_id: userId, role: 'super_admin' })
  resetRateLimits()
  const flow = await adminSetupFlow(env, 'idle@example.com', 'Correct Horse Battery Staple 123!', '10.9.1.1')
  const row = db.tables.sessions.find((s) => s.scope === 'admin')
  assert.ok(row)
  row.last_seen_at = new Date(Date.now() - 31 * 60 * 1000).toISOString()
  const idle = await call(env, '/auth/admin-session', 'GET', undefined, { cookie: flow.cookie, ip: '10.9.1.2', origin: ADMIN_ORIGIN })
  assert.equal(idle.status, 401)
  assert.equal(idle.data.authenticated, false)
  assert.equal(db.tables.sessions.filter((s) => s.scope === 'admin').length, 0)
})

test('admin session last_seen_at refreshes at most once a minute', async () => {
  const { db, env } = fresh()
  resetRateLimits()
  const { userId } = await registerAndActivate(env, 'idle2@example.com', 'Correct Horse Battery Staple 123!')
  db.tables.admin_allowlist.push({ user_id: userId, role: 'super_admin' })
  resetRateLimits()
  const flow = await adminSetupFlow(env, 'idle2@example.com', 'Correct Horse Battery Staple 123!', '10.9.2.1')
  const row = db.tables.sessions.find((s) => s.scope === 'admin')
  const stale = new Date(Date.now() - 2 * 60 * 1000).toISOString()
  row.last_seen_at = stale
  const ok = await call(env, '/auth/admin-session', 'GET', undefined, { cookie: flow.cookie, ip: '10.9.2.2', origin: ADMIN_ORIGIN })
  assert.equal(ok.status, 200)
  assert.notEqual(row.last_seen_at, stale)
  assert.ok(Date.now() - new Date(row.last_seen_at).getTime() < 10 * 1000)
  const refreshed = row.last_seen_at
  row.last_seen_at = new Date(Date.now() - 30 * 1000).toISOString()
  const ok2 = await call(env, '/auth/admin-session', 'GET', undefined, { cookie: flow.cookie, ip: '10.9.2.3', origin: ADMIN_ORIGIN })
  assert.equal(ok2.status, 200)
  assert.notEqual(row.last_seen_at, refreshed)
  assert.ok(Date.now() - new Date(row.last_seen_at).getTime() >= 29 * 1000)
})

test('admin sessions live 8 hours, normal sessions 2 days', async () => {
  const { db, env } = fresh()
  resetRateLimits()
  const { userId } = await registerAndActivate(env, 'life@example.com', 'Correct Horse Battery Staple 123!')
  db.tables.admin_allowlist.push({ user_id: userId, role: 'super_admin' })
  resetRateLimits()
  await adminSetupFlow(env, 'life@example.com', 'Correct Horse Battery Staple 123!', '10.9.3.1')
  const adminRow = db.tables.sessions.find((s) => s.scope === 'admin')
  const adminLife = new Date(adminRow.expires_at).getTime() - new Date(adminRow.created_at).getTime()
  assert.ok(Math.abs(adminLife - 8 * 60 * 60 * 1000) < 60 * 1000, `admin lifetime ${adminLife}`)
  const normalRow = db.tables.sessions.find((s) => s.scope === 'full')
  assert.ok(normalRow)
  const normalLife = new Date(normalRow.expires_at).getTime() - new Date(normalRow.created_at).getTime()
  assert.ok(Math.abs(normalLife - 2 * 24 * 60 * 60 * 1000) < 60 * 1000, `normal lifetime ${normalLife}`)
})

test('production cookies use __Host- prefix and Lax; legacy cookie still accepted; admin cookie rejected on normal endpoints', async () => {
  const { db, env } = fresh()
  resetRateLimits()
  const { userId, secret } = await registerAndActivate(env, 'cook@example.com', 'Correct Horse Battery Staple 123!')
  db.tables.admin_allowlist.push({ user_id: userId, role: 'super_admin' })
  resetRateLimits()
  const legacy = await loginWithMfa(env, 'cook@example.com', 'Correct Horse Battery Staple 123!', secret, '10.9.4.1')
  assert.ok(legacy.cookie.startsWith('kluzar_session='))
  env.ALLOW_INSECURE_COOKIE = 'false'
  const withLegacy = await call(env, '/auth/session', 'GET', undefined, { cookie: legacy.cookie, ip: '10.9.4.2' })
  assert.equal(withLegacy.status, 200, 'old kluzar_session must still work during transition')
  advanceTotp(env)
  resetRateLimits()
  const login = await call(env, '/auth/login', 'POST', { email: 'cook@example.com', password: 'Correct Horse Battery Staple 123!' }, { ip: '10.9.4.3' })
  const verify = await call(env, '/auth/mfa/verify', 'POST', { challengeToken: login.data.challengeToken, code: await totpNow(secret) }, { ip: '10.9.4.3' })
  assert.equal(verify.status, 200)
  assert.ok(verify.setCookie.startsWith('__Host-kluzar_session='), verify.setCookie)
  assert.ok(verify.setCookie.includes('Secure'))
  assert.ok(verify.setCookie.includes('SameSite=Lax'))
  assert.ok(verify.setCookie.includes('Max-Age=172800'))
  resetRateLimits()
  const admin = await adminSetupFlow(env, 'cook@example.com', 'Correct Horse Battery Staple 123!', '10.9.4.4')
  assert.ok(admin.cookie.startsWith('__Host-kluzar_admin='), admin.cookie)
  const normalWithAdmin = await call(env, '/auth/session', 'GET', undefined, { cookie: admin.cookie, ip: '10.9.4.5' })
  assert.equal(normalWithAdmin.status, 401)
  const adminSession = await call(env, '/auth/admin-session', 'GET', undefined, { cookie: admin.cookie, ip: '10.9.4.6', origin: ADMIN_ORIGIN })
  assert.equal(adminSession.status, 200)
  assert.ok(adminSession.data.authenticated)
})

test('logout clears the new cookies and the legacy cookie', async () => {
  const { env } = fresh()
  resetRateLimits()
  const { secret } = await registerAndActivate(env, 'logout@example.com', 'Correct Horse Battery Staple 123!')
  env.ALLOW_INSECURE_COOKIE = 'false'
  const { cookie, csrf } = await loginWithMfa(env, 'logout@example.com', 'Correct Horse Battery Staple 123!', secret, '10.9.5.1')
  const res = await call(env, '/auth/logout', 'POST', {}, { cookie, ip: '10.9.5.2', headers: { 'X-CSRF-Token': csrf } })
  assert.equal(res.status, 200)
  const cleared = res.res.headers.getSetCookie()
  assert.ok(cleared.some((c) => c.startsWith('__Host-kluzar_session=') && c.includes('Max-Age=0')), JSON.stringify(cleared))
  assert.ok(cleared.some((c) => c.startsWith('__Host-kluzar_admin=') && c.includes('Max-Age=0')), JSON.stringify(cleared))
  assert.ok(cleared.some((c) => c.startsWith('kluzar_session=') && c.includes('Max-Age=0')), JSON.stringify(cleared))
})

test('expired temp password is rejected; valid temp password works and change clears the flag', async () => {
  const { db, env } = fresh()
  resetRateLimits()
  const now = new Date().toISOString()
  const passwordHash = await hashPassword('Temp Password 123!', 1000)
  db.tables.users.push({
    id: 'tmp-1', email: 'tmp@example.com', email_normalized: 'tmp@example.com', password_hash: passwordHash,
    status: 'active', email_verified: 0, mfa_enabled: 0, first_name: '', last_name: '', phone: '',
    created_at: now, updated_at: now, must_change_password: 1,
    temp_password_expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
  })
  db.tables.entitlements.push({ user_id: 'tmp-1', plan: 'free', status: 'active', updated_at: now })
  const ok = await call(env, '/auth/login', 'POST', { email: 'tmp@example.com', password: 'Temp Password 123!' }, { ip: '10.9.6.1' })
  assert.equal(ok.status, 200)
  assert.equal(ok.data.user.mustChangePassword, true)
  const changed = await call(env, '/auth/password/change', 'POST', { currentPassword: 'Temp Password 123!', newPassword: 'Fresh Password 456!' }, { cookie: ok.sessionCookie, ip: '10.9.6.2', headers: { 'X-CSRF-Token': ok.data.csrfToken } })
  assert.equal(changed.status, 200)
  const user = db.tables.users.find((u) => u.id === 'tmp-1')
  assert.equal(user.must_change_password, 0)
  assert.equal(user.temp_password_expires_at, null)
  const session = await call(env, '/auth/session', 'GET', undefined, { cookie: changed.sessionCookie, ip: '10.9.6.3' })
  assert.equal(session.data.user.mustChangePassword, false)
  db.tables.users.find((u) => u.id === 'tmp-1').must_change_password = 1
  db.tables.users.find((u) => u.id === 'tmp-1').temp_password_expires_at = new Date(Date.now() - 1000).toISOString()
  const expired = await call(env, '/auth/login', 'POST', { email: 'tmp@example.com', password: 'Temp Password 123!' }, { ip: '10.9.6.4' })
  assert.equal(expired.status, 401)
  assert.equal(expired.data.error, 'Invalid email or password.')
  assert.equal(expired.data.code, 'INVALID_CREDENTIALS')
})

test('admin MFA replace flow claims the step: the same code cannot be reused', async () => {
  const { db, env } = fresh()
  resetRateLimits()
  const { userId } = await registerAndActivate(env, 'replace@example.com', 'Correct Horse Battery Staple 123!')
  db.tables.admin_allowlist.push({ user_id: userId, role: 'super_admin' })
  resetRateLimits()
  const flow = await adminSetupFlow(env, 'replace@example.com', 'Correct Horse Battery Staple 123!', '10.9.7.1')
  for (const row of db.tables.admin_mfa_secrets) row.last_used_step = null
  const challenge = await call(env, '/auth/admin-mfa/challenge', 'POST', { email: 'replace@example.com', password: 'Correct Horse Battery Staple 123!' }, { ip: '10.9.7.2', origin: ADMIN_ORIGIN })
  assert.equal(challenge.status, 200)
  const code = await totpNow(flow.secret)
  const first = await call(env, '/auth/admin-mfa/setup', 'POST', { challengeToken: challenge.data.challengeToken, code }, { ip: '10.9.7.3', origin: ADMIN_ORIGIN })
  assert.equal(first.status, 200)
  assert.ok(first.data.otpauthUrl)
  const replay = await call(env, '/auth/admin-mfa/setup', 'POST', { challengeToken: challenge.data.challengeToken, code }, { ip: '10.9.7.4', origin: ADMIN_ORIGIN })
  assert.equal(replay.status, 400)
  assert.equal(replay.data.code, 'INVALID_CODE')
})

test('re-enabling MFA returns fresh recovery codes and renames the audit event', async () => {
  const { db, env } = fresh()
  resetRateLimits()
  const activated = await registerAndActivate(env, 'reenable@example.com', 'Correct Horse Battery Staple 123!')
  const oldCodes = [...activated.recoveryCodes]
  const { cookie, csrf } = await loginWithMfa(env, 'reenable@example.com', 'Correct Horse Battery Staple 123!', activated.secret, '10.9.8.1')
  resetRateLimits()
  const setup = await call(env, '/auth/mfa/setup', 'POST', { currentPassword: 'Correct Horse Battery Staple 123!' }, { cookie, ip: '10.9.8.2', headers: { 'X-CSRF-Token': csrf } })
  assert.equal(setup.status, 200)
  const secret = secretFromOtpauth(setup.data.otpauthUrl)
  const verify = await call(env, '/auth/mfa/verify', 'POST', { code: await totpNow(secret) }, { cookie, ip: '10.9.8.3', headers: { 'X-CSRF-Token': csrf } })
  assert.equal(verify.status, 200)
  assert.equal(verify.data.mfaEnabled, true)
  assert.equal(verify.data.recoveryCodes.length, 10)
  const audit = db.tables.audit_events.find((r) => r.event_type === 'mfa_reenabled')
  assert.ok(audit, 'mfa_reenabled audit must exist')
  assert.ok(!db.tables.audit_events.some((r) => r.event_type === 'mfa_res setup'), 'old typo event must be gone')
  assert.equal(db.tables.recovery_codes.length, 10)
  const oldHashes = new Set()
  for (const c of oldCodes) oldHashes.add(await sha256Hex(normalizeRecoveryCode(c)))
  assert.ok(!db.tables.recovery_codes.some((r) => oldHashes.has(r.code_hash)), 'old codes must be replaced')
})

test('ipHash is HMAC-SHA256 keyed by secret, 32 hex chars, and fails without the secret', async () => {
  const a = await ipHash('203.0.113.7', 'secret-one')
  const b = await ipHash('203.0.113.7', 'secret-one')
  const c = await ipHash('203.0.113.7', 'secret-two')
  const d = await ipHash('203.0.113.8', 'secret-one')
  assert.equal(a, b)
  assert.notEqual(a, c)
  assert.notEqual(a, d)
  assert.match(a, /^[0-9a-f]{32}$/)
  await assert.rejects(ipHash('203.0.113.7', undefined))
  await assert.rejects(ipHash('203.0.113.7', ''))
})

test('password policy rejects the email local-part and common passwords, accepts a strong unrelated password', async () => {
  const { env } = fresh()
  resetRateLimits()
  const local = await call(env, '/auth/register', 'POST', { email: 'victoria@example.com', password: 'Victoria Falls 99!' }, { ip: '10.9.9.1' })
  assert.equal(local.status, 400)
  assert.equal(local.data.code, 'VALIDATION')
  const unrelated = await call(env, '/auth/register', 'POST', { email: 'other@example.com', password: 'Victoria Falls 99!' }, { ip: '10.9.9.2' })
  assert.equal(unrelated.status, 201)
  const common = await call(env, '/auth/register', 'POST', { email: 'common@example.com', password: 'unbelievable' }, { ip: '10.9.9.3' })
  assert.equal(common.status, 400)
  assert.equal(isValidPassword('Correct Horse Battery Staple 123!'), true)
  assert.equal(isValidPassword('unbelievable'), false)
  const securitySrc = readFileSync(new URL('../worker/src/security.js', import.meta.url), 'utf8')
  assert.ok(securitySrc.includes('COMMON_PASSWORDS.has(password.toLowerCase())'), 'common-password check must be wired')
})

test('wrangler disables workers.dev and preview URLs', async () => {
  const toml = readFileSync(new URL('../wrangler.toml', import.meta.url), 'utf8')
  assert.ok(toml.includes('workers_dev = false'))
  assert.ok(toml.includes('preview_urls = false'))
})
