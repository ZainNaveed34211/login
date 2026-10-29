import test from 'node:test'
import assert from 'node:assert/strict'
import { MockD1, testEnv } from './mock-d1.js'
import { call } from './helpers.js'

// SECURITY FIRST: every post-login endpoint must return 401 without a
// valid session cookie, before it reads the body, checks CSRF, or
// touches any account data. No endpoint may leak data to an anonymous
// caller, and no endpoint may be reachable by guessing its URL.
const PROTECTED = [
  ['GET', '/auth/session', undefined],
  ['POST', '/auth/logout-all', {}],
  ['POST', '/auth/password/change', { currentPassword: 'x', mfaCode: '123456', newPassword: 'long-enough-password-123' }],
  ['POST', '/auth/recovery-codes/regenerate', { currentPassword: 'x', mfaCode: '123456' }],
  ['POST', '/auth/mfa/disable', { currentPassword: 'x', mfaCode: '123456' }],
  ['POST', '/auth/mfa/setup', {}],
  ['POST', '/auth/mfa/verify', {}],
  ['GET', '/account/profile', undefined],
  ['PATCH', '/account/profile', { firstName: 'A' }],
  ['GET', '/account/entitlements', undefined],
  ['GET', '/account/sessions', undefined],
  ['POST', '/account/sessions/revoke', { sessionId: 'other' }],
]

test('every post-login endpoint returns 401 without a session, and leaks no user data', async () => {
  const db = new MockD1()
  const env = testEnv(db)
  for (const [method, path, body] of PROTECTED) {
    const out = await call(env, path, method, body, { ip: '10.9.0.1' })
    assert.equal(out.status, 401, `${method} ${path} without a session must be 401, got ${out.status}`)
    assert.ok(!JSON.stringify(out.data).includes('sess@') && !out.data.user && !out.data.entitlement,
      `${method} ${path} must not leak user data without a session`)
  }
})

test('public token endpoints still require their own one-time token, not just a URL guess', async () => {
  const db = new MockD1()
  const env = testEnv(db)
  // No setupToken / challengeToken / recoveryToken at all.
  const setup = await call(env, '/auth/mfa/setup', 'POST', {}, { ip: '10.9.0.2' })
  assert.equal(setup.status, 401)
  const verify = await call(env, '/auth/mfa/verify', 'POST', { code: '123456' }, { ip: '10.9.0.2' })
  assert.equal(verify.status, 401)
  const reset = await call(env, '/auth/password/reset', 'POST', { recoveryToken: 'guessed-token', newPassword: 'long-enough-password-123' }, { ip: '10.9.0.2' })
  assert.equal(reset.status, 400)
  assert.ok(!reset.data.user, 'reset with a guessed token must not return a user')
})
