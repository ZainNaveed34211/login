import test from 'node:test'
import assert from 'node:assert/strict'
import { MockD1, testEnv } from './mock-d1.js'
import { call, registerAndActivate, secretFromOtpauth, totpNow } from './helpers.js'
import { resetRateLimits } from '../worker/src/security.js'

const ADMIN_ORIGIN = 'https://admin.kluzar.com'

function fresh() {
  const db = new MockD1()
  const env = testEnv(db)
  env.ALLOWED_ORIGINS = 'http://localhost:3000,https://admin.kluzar.com'
  return { db, env }
}

function decodePayload(assertion) {
  return JSON.parse(Buffer.from(assertion.split('.')[1], 'base64url').toString())
}

async function signingEnv(env) {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  const priv = await crypto.subtle.exportKey('jwk', pair.privateKey)
  env.ADMIN_ASSERTION_PRIVATE_KEY = JSON.stringify(priv)
  return env
}

async function adminSession(env, email, password, ip) {
  const challenge = await call(env, '/auth/admin-mfa/challenge', 'POST', { email, password }, { ip, origin: ADMIN_ORIGIN })
  assert.equal(challenge.status, 200, 'challenge: ' + JSON.stringify(challenge.data))
  const setup = await call(env, '/auth/admin-mfa/setup', 'POST', { challengeToken: challenge.data.challengeToken }, { ip, origin: ADMIN_ORIGIN })
  assert.equal(setup.status, 200, 'setup: ' + JSON.stringify(setup.data))
  const secret = secretFromOtpauth(setup.data.otpauthUrl)
  const code = await totpNow(secret)
  const verify = await call(env, '/auth/admin-mfa/verify-setup', 'POST', { challengeToken: challenge.data.challengeToken, code }, { ip, origin: ADMIN_ORIGIN })
  assert.equal(verify.status, 200, 'verify-setup: ' + JSON.stringify(verify.data))
  for (const row of env.DB.tables.admin_mfa_secrets) row.last_used_step = null
  return { secret, cookie: verify.sessionCookie, csrf: verify.data.csrfToken }
}

test('admin step-up returns a 60-second assertion with step_up true; normal assertions have no step_up', async () => {
  const { db, env } = fresh()
  await signingEnv(env)
  resetRateLimits()
  const { userId } = await registerAndActivate(env, 'stepup@example.com', 'Correct Horse Battery Staple 123!')
  db.tables.admin_allowlist.push({ user_id: userId, role: 'super_admin' })
  resetRateLimits()
  const flow = await adminSession(env, 'stepup@example.com', 'Correct Horse Battery Staple 123!', '10.10.0.1')
  const stepup = await call(env, '/auth/admin-stepup', 'POST', { code: await totpNow(flow.secret) }, { cookie: flow.cookie, ip: '10.10.0.2', origin: ADMIN_ORIGIN, headers: { 'X-CSRF-Token': flow.csrf } })
  assert.equal(stepup.status, 200, JSON.stringify(stepup.data))
  assert.equal(stepup.data.expiresIn, 60)
  const payload = decodePayload(stepup.data.assertion)
  assert.equal(payload.step_up, true)
  assert.equal(payload.exp - payload.iat, 60)
  assert.equal(payload.aud, 'kluzar-admin-api')
  assert.equal(payload.mfa, true)
  const normal = await call(env, '/auth/admin-assertion', 'POST', {}, { cookie: flow.cookie, ip: '10.10.0.3', origin: ADMIN_ORIGIN, headers: { 'X-CSRF-Token': flow.csrf } })
  assert.equal(normal.status, 200)
  assert.equal(decodePayload(normal.data.assertion).step_up, undefined)
  assert.equal(normal.data.expiresIn, 300)
})

test('admin step-up rejects wrong codes, recovery codes, replays, missing session and missing CSRF', async () => {
  const { db, env } = fresh()
  await signingEnv(env)
  resetRateLimits()
  const activated = await registerAndActivate(env, 'stepup2@example.com', 'Correct Horse Battery Staple 123!')
  db.tables.admin_allowlist.push({ user_id: activated.userId, role: 'super_admin' })
  resetRateLimits()
  const flow = await adminSession(env, 'stepup2@example.com', 'Correct Horse Battery Staple 123!', '10.10.1.1')
  const opts = { cookie: flow.cookie, ip: '10.10.1.2', origin: ADMIN_ORIGIN, headers: { 'X-CSRF-Token': flow.csrf } }
  const wrong = await call(env, '/auth/admin-stepup', 'POST', { code: '000000' }, opts)
  assert.equal(wrong.status, 400)
  assert.equal(wrong.data.code, 'INVALID_CODE')
  const recovery = await call(env, '/auth/admin-stepup', 'POST', { code: activated.recoveryCodes[0] }, opts)
  assert.equal(recovery.status, 400)
  const code = await totpNow(flow.secret)
  const first = await call(env, '/auth/admin-stepup', 'POST', { code }, opts)
  assert.equal(first.status, 200)
  const replay = await call(env, '/auth/admin-stepup', 'POST', { code }, opts)
  assert.equal(replay.status, 400)
  const noSession = await call(env, '/auth/admin-stepup', 'POST', { code: await totpNow(flow.secret) }, { ip: '10.10.1.3', origin: ADMIN_ORIGIN, headers: { 'X-CSRF-Token': flow.csrf } })
  assert.equal(noSession.status, 401)
  const noCsrf = await call(env, '/auth/admin-stepup', 'POST', { code: await totpNow(flow.secret) }, { cookie: flow.cookie, ip: '10.10.1.4', origin: ADMIN_ORIGIN })
  assert.equal(noCsrf.status, 403)
  const wrongOrigin = await call(env, '/auth/admin-stepup', 'POST', { code: await totpNow(flow.secret) }, { cookie: flow.cookie, ip: '10.10.1.5', origin: 'https://evil.test', headers: { 'X-CSRF-Token': flow.csrf } })
  assert.equal(wrongOrigin.status, 403)
})
