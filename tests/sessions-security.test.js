import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { MockD1, testEnv } from './mock-d1.js'
import { call, registerAndActivate, loginWithMfa, totpNow } from './helpers.js'
import { resetRateLimits } from '../worker/src/security.js'

function fresh() { const db = new MockD1(); return { db, env: testEnv(db) } }
const root = path.dirname(fileURLToPath(import.meta.url))

test('logout invalidates the old cookie; logout-all invalidates all devices; fresh login works', async () => {
  const { env } = fresh()
  const { secret } = await registerAndActivate(env, 'sess@example.com', 'Correct Horse Battery Staple 123!')
  const a = await loginWithMfa(env, 'sess@example.com', 'Correct Horse Battery Staple 123!', secret, '10.3.0.1')
  const b = await loginWithMfa(env, 'sess@example.com', 'Correct Horse Battery Staple 123!', secret, '10.3.0.2')
  resetRateLimits()
  // Logout now requires CSRF (hardening): the frontend fetches the
  // token from GET /auth/session and sends it, as in shared.js logout().
  const out = await call(env, '/auth/logout', 'POST', {}, { cookie: a.cookie, headers: { 'X-CSRF-Token': a.csrf }, ip: '10.3.0.1' })
  assert.equal(out.status, 200)
  const replay = await call(env, '/auth/session', 'GET', undefined, { cookie: a.cookie, ip: '10.3.0.1' })
  assert.equal(replay.status, 401, 'logged-out cookie must fail')
  const otherStill = await call(env, '/auth/session', 'GET', undefined, { cookie: b.cookie, ip: '10.3.0.2' })
  assert.equal(otherStill.status, 200, 'other device unaffected by single logout')
  resetRateLimits()
  const outAll = await call(env, '/auth/logout-all', 'POST', {}, { cookie: b.cookie, headers: { 'X-CSRF-Token': b.csrf }, ip: '10.3.0.2' })
  assert.equal(outAll.status, 200)
  const replayAll = await call(env, '/auth/session', 'GET', undefined, { cookie: b.cookie, ip: '10.3.0.2' })
  assert.equal(replayAll.status, 401, 'logout-all must invalidate every session')
  // Fresh login creates a new valid session; old cookies cannot revive it
  const freshLogin = await loginWithMfa(env, 'sess@example.com', 'Correct Horse Battery Staple 123!', secret, '10.3.0.3')
  assert.notEqual(freshLogin.cookie, b.cookie)
  const freshSession = await call(env, '/auth/session', 'GET', undefined, { cookie: freshLogin.cookie, ip: '10.3.0.3' })
  assert.equal(freshSession.status, 200)
})

test('expired session fails even if the cookie is replayed', async () => {
  const { db, env } = fresh()
  const { secret } = await registerAndActivate(env, 'exp@example.com', 'Correct Horse Battery Staple 123!')
  const { cookie } = await loginWithMfa(env, 'exp@example.com', 'Correct Horse Battery Staple 123!', secret)
  // Expire every session (setup session + login session) so the replayed
  // login cookie is the one being tested.
  for (const s of db.tables.sessions) s.expires_at = new Date(Date.now() - 1000).toISOString()
  const replay = await call(env, '/auth/session', 'GET', undefined, { cookie, ip: '10.3.0.4' })
  assert.equal(replay.status, 401)
})

test('session lifetime is two days', async () => {
  const { db, env } = fresh()
  const { secret } = await registerAndActivate(env, 'life@example.com', 'Correct Horse Battery Staple 123!')
  await loginWithMfa(env, 'life@example.com', 'Correct Horse Battery Staple 123!', secret)
  const s = db.tables.sessions[0]
  const diff = new Date(s.expires_at).getTime() - new Date(s.created_at).getTime()
  assert.ok(Math.abs(diff - 2 * 24 * 60 * 60 * 1000) < 60 * 1000, 'expiry must be ~2 days after creation')
})

test('SQL injection cannot log in, and profile PATCH ignores client-supplied user IDs (no IDOR)', async () => {
  const { db, env } = fresh()
  const a = await registerAndActivate(env, 'victim@example.com', 'Correct Horse Battery Staple 123!')
  const b = await registerAndActivate(env, 'attacker@example.com', 'Correct Horse Battery Staple 123!')
  resetRateLimits()
  const injection = await call(env, '/auth/login', 'POST', { email: "' OR '1'='1", password: 'Anything 123456!' }, { ip: '10.3.0.5' })
  assert.equal(injection.status, 401)
  const { cookie, csrf } = await loginWithMfa(env, 'attacker@example.com', 'Correct Horse Battery Staple 123!', b.secret)
  resetRateLimits()
  const patch = await call(env, '/account/profile', 'PATCH', { userId: a.userId, firstName: 'Hacked' }, { cookie, headers: { 'X-CSRF-Token': csrf }, ip: '10.3.0.6' })
  assert.equal(patch.status, 200)
  const victim = db.tables.users.find((u) => u.id === a.userId)
  const attacker = db.tables.users.find((u) => u.id === b.userId)
  assert.notEqual(victim.first_name, 'Hacked', 'victim profile must not change')
  assert.equal(attacker.first_name, 'Hacked', 'only the authenticated account changes')
})

test('CSRF: state-changing requests without the session CSRF token fail', async () => {
  const { env } = fresh()
  const { secret } = await registerAndActivate(env, 'csrf@example.com', 'Correct Horse Battery Staple 123!')
  const { cookie } = await loginWithMfa(env, 'csrf@example.com', 'Correct Horse Battery Staple 123!', secret)
  resetRateLimits()
  const noToken = await call(env, '/account/profile', 'PATCH', { firstName: 'No' }, { cookie, ip: '10.3.0.7' })
  assert.equal(noToken.status, 403)
  const wrongToken = await call(env, '/account/profile', 'PATCH', { firstName: 'No' }, { cookie, headers: { 'X-CSRF-Token': 'wrong' }, ip: '10.3.0.7' })
  assert.equal(wrongToken.status, 403)
})

test('disallowed origins cannot read credentialed API responses', async () => {
  const { env } = fresh()
  const res = await call(env, '/auth/session', 'GET', undefined, { origin: 'https://evil.example.com', ip: '10.3.0.8' })
  assert.notEqual(res.res.headers.get('Access-Control-Allow-Origin'), 'https://evil.example.com')
  const allowed = await call(env, '/auth/session', 'GET', undefined, { origin: 'http://localhost:3000', ip: '10.3.0.8' })
  assert.equal(allowed.res.headers.get('Access-Control-Allow-Origin'), 'http://localhost:3000')
  assert.equal(allowed.res.headers.get('Access-Control-Allow-Credentials'), 'true')
})

test('request-size limit and safe errors (no stack traces)', async () => {
  const { env } = fresh()
  resetRateLimits()
  const big = await call(env, '/auth/register', 'POST', { email: 'big@example.com', password: 'x'.repeat(20000) }, { ip: '10.3.0.9' })
  assert.ok([400, 413].includes(big.status))
  assert.ok(!JSON.stringify(big.data).includes('at ') || !JSON.stringify(big.data).includes('handlers.js'))
  assert.ok(!('stack' in big.data))
})

test('entitlements default to free, never fabricated as paid', async () => {
  const { env } = fresh()
  const { secret } = await registerAndActivate(env, 'ent@example.com', 'Correct Horse Battery Staple 123!')
  const { cookie } = await loginWithMfa(env, 'ent@example.com', 'Correct Horse Battery Staple 123!', secret)
  const ent = await call(env, '/account/entitlements', 'GET', undefined, { cookie, ip: '10.3.1.0' })
  assert.equal(ent.status, 200)
  assert.equal(ent.data.entitlement.plan, 'free')
  assert.equal(ent.data.entitlement.premium, false)
})

test('frontend: Get Premium points to payments.kluzar.com, config is single-source, no secrets in frontend', async () => {
  const app = readFileSync(path.join(root, '../shared.js'), 'utf8')
  const config = readFileSync(path.join(root, '../config.js'), 'utf8')
  const index = readFileSync(path.join(root, '../index.html'), 'utf8')
  const dashboard = readFileSync(path.join(root, '../dashboard/index.html'), 'utf8')
  assert.ok(config.includes("PAYMENTS_URL: 'https://payments.kluzar.com'"))
  assert.ok(app.includes('PAYMENTS_URL'), 'shared code must use the configured payments URL')
  assert.ok(!app.includes('https://payments.kluzar.com'), 'shared code must not hardcode the payments URL elsewhere')
  assert.ok(dashboard.includes('get-premium-btn'))
  assert.ok(app.includes('kluzar_password_failures'), 'two-wrong-password UI reset must exist')
  assert.ok(!app.includes('MFA_ENCRYPTION_KEY'))
  assert.ok(!config.includes('MFA_ENCRYPTION_KEY'))
  assert.ok(!index.includes('MFA_ENCRYPTION_KEY'))
  assert.ok(readFileSync(path.join(root, '../qr-lib.js'), 'utf8').length > 10000, 'QR library bundle must be present')
})

test('worker never returns hashes, secrets, or internal fields in public responses', async () => {
  const { env } = fresh()
  const { secret } = await registerAndActivate(env, 'leak@example.com', 'Correct Horse Battery Staple 123!')
  const { cookie } = await loginWithMfa(env, 'leak@example.com', 'Correct Horse Battery Staple 123!', secret)
  const session = await call(env, '/auth/session', 'GET', undefined, { cookie, ip: '10.3.1.1' })
  const text = JSON.stringify(session.data)
  assert.ok(!text.includes('password_hash'))
  assert.ok(!text.includes('token_hash'))
  assert.ok(!text.includes('encrypted_secret'))
  assert.ok(!text.includes('code_hash'))
})
