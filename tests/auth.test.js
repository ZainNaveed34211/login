import test from 'node:test'
import assert from 'node:assert/strict'
import { MockD1, testEnv } from './mock-d1.js'
import { call, registerAndActivate, loginWithMfa, totpNow, advanceTotp } from './helpers.js'
import { resetRateLimits } from '../worker/src/security.js'

function fresh() { const db = new MockD1(); return { db, env: testEnv(db) } }

test('registration succeeds, password is hashed with unique salt, user is pending_mfa', async () => {
  const { db, env } = fresh()
  resetRateLimits()
  const a = await call(env, '/auth/register', 'POST', { email: '  Alice@Example.com ', password: 'Correct Horse Battery Staple 123!' }, { ip: '10.1.0.1' })
  assert.equal(a.status, 201)
  assert.equal(a.data.status, 'pending_mfa')
  assert.ok(a.data.setupToken)
  const user = db.tables.users[0]
  assert.equal(user.email_normalized, 'alice@example.com')
  assert.ok(user.password_hash.startsWith('pbkdf2-sha256$'))
  assert.ok(!user.password_hash.includes('correct horse'))
  const b = await call(env, '/auth/register', 'POST', { email: 'bob@example.com', password: 'Correct Horse Battery Staple 123!' }, { ip: '10.1.0.2' })
  assert.equal(b.status, 201)
  assert.notEqual(db.tables.users[0].password_hash, db.tables.users[1].password_hash)
})

test('duplicate email does not create a second user and returns no setup token', async () => {
  const { db, env } = fresh()
  resetRateLimits()
  await call(env, '/auth/register', 'POST', { email: 'dup@example.com', password: 'Correct Horse Battery Staple 123!' }, { ip: '10.1.0.3' })
  const dup = await call(env, '/auth/register', 'POST', { email: 'dup@example.com', password: 'Another Password 123!' }, { ip: '10.1.0.3' })
  assert.equal(dup.status, 409)
  assert.ok(!dup.data.setupToken)
  assert.equal(db.tables.users.length, 1)
})

test('incorrect password and unknown email return the same generic error', async () => {
  const { env } = fresh()
  await registerAndActivate(env, 'gen@example.com', 'Correct Horse Battery Staple 123!')
  resetRateLimits()
  const wrong = await call(env, '/auth/login', 'POST', { email: 'gen@example.com', password: 'Wrong Password 123!' }, { ip: '10.1.0.4' })
  const unknown = await call(env, '/auth/login', 'POST', { email: 'nobody@example.com', password: 'Wrong Password 123!' }, { ip: '10.1.0.5' })
  assert.equal(wrong.status, 401)
  assert.equal(unknown.status, 401)
  assert.equal(wrong.data.error, unknown.data.error)
  assert.equal(wrong.data.error, 'Invalid email or password.')
})

test('valid password without MFA never creates an authenticated session', async () => {
  const { env } = fresh()
  const { secret } = await registerAndActivate(env, 'mfa@example.com', 'Correct Horse Battery Staple 123!')
  resetRateLimits()
  const login = await call(env, '/auth/login', 'POST', { email: 'mfa@example.com', password: 'Correct Horse Battery Staple 123!' }, { ip: '10.1.0.6' })
  assert.equal(login.data.mfaRequired, true)
  assert.ok(login.data.challengeToken)
  assert.ok(!login.sessionCookie, 'no session cookie before MFA')
  const session = await call(env, '/auth/session', 'GET', undefined, { ip: '10.1.0.6' })
  assert.equal(session.status, 401)
  assert.equal(session.data.authenticated, false)
})

test('full login with TOTP creates a session; wrong TOTP fails', async () => {
  const { env } = fresh()
  const { secret } = await registerAndActivate(env, 'login@example.com', 'Correct Horse Battery Staple 123!')
  const { cookie, csrf, user } = await loginWithMfa(env, 'login@example.com', 'Correct Horse Battery Staple 123!', secret)
  assert.ok(cookie && cookie.startsWith('kluzar_session='))
  assert.ok(csrf)
  assert.equal(user.email, 'login@example.com')
  const session = await call(env, '/auth/session', 'GET', undefined, { cookie, ip: '10.1.0.7' })
  assert.equal(session.status, 200)
  assert.equal(session.data.authenticated, true)
  // Wrong TOTP
  resetRateLimits()
  const login2 = await call(env, '/auth/login', 'POST', { email: 'login@example.com', password: 'Correct Horse Battery Staple 123!' }, { ip: '10.1.0.8' })
  const bad = await call(env, '/auth/mfa/verify', 'POST', { challengeToken: login2.data.challengeToken, code: '000000' }, { ip: '10.1.0.8' })
  assert.equal(bad.status, 400)
})

test('replayed TOTP code fails after a successful use', async () => {
  const { db, env } = fresh()
  const { secret } = await registerAndActivate(env, 'replay@example.com', 'Correct Horse Battery Staple 123!')
  // First login with a code for the current step (simulate a new step
  // after setup, otherwise the setup code itself would be a replay)
  advanceTotp(env)
  resetRateLimits()
  const login = await call(env, '/auth/login', 'POST', { email: 'replay@example.com', password: 'Correct Horse Battery Staple 123!' }, { ip: '10.1.0.9' })
  const code = await totpNow(secret)
  const ok = await call(env, '/auth/mfa/verify', 'POST', { challengeToken: login.data.challengeToken, code }, { ip: '10.1.0.9' })
  assert.equal(ok.status, 200)
  // Second login, same code again (same time step in a fast test run)
  resetRateLimits()
  const login2 = await call(env, '/auth/login', 'POST', { email: 'replay@example.com', password: 'Correct Horse Battery Staple 123!' }, { ip: '10.1.0.10' })
  const replay = await call(env, '/auth/mfa/verify', 'POST', { challengeToken: login2.data.challengeToken, code }, { ip: '10.1.0.10' })
  assert.equal(replay.status, 400)
  assert.ok(db.tables.mfa_secrets[0].last_used_step !== null)
})

test('rate limit is enforced server-side on register', async () => {
  const { env } = fresh()
  resetRateLimits()
  let last = null
  for (let i = 0; i < 6; i++) {
    last = await call(env, '/auth/register', 'POST', { email: `rate${i}@example.com`, password: 'Correct Horse Battery Staple 123!' }, { ip: '10.9.9.9' })
  }
  assert.equal(last.status, 429)
})
