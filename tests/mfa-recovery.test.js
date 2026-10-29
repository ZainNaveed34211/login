import test from 'node:test'
import assert from 'node:assert/strict'
import { MockD1, testEnv } from './mock-d1.js'
import { call, registerAndActivate, loginWithMfa, totpNow, advanceTotp } from './helpers.js'
import { resetRateLimits } from '../worker/src/security.js'
import { sha256Hex, normalizeRecoveryCode } from '../worker/src/crypto.js'

function fresh() { const db = new MockD1(); return { db, env: testEnv(db) } }

test('recovery codes are single-use and only hashes are stored', async () => {
  const { db, env } = fresh()
  const { secret, recoveryCodes } = await registerAndActivate(env, 'rc@example.com', 'Correct Horse Battery Staple 123!')
  assert.equal(recoveryCodes.length, 10)
  // No plaintext code in D1
  const stored = db.tables.recovery_codes
  assert.equal(stored.length, 10)
  for (const row of stored) {
    assert.ok(!recoveryCodes.includes(row.code_hash))
    assert.equal(row.used, 0)
  }
  const firstHash = await sha256Hex(normalizeRecoveryCode(recoveryCodes[0]))
  assert.ok(stored.some((r) => r.code_hash === firstHash))
  // Use first code at login challenge
  resetRateLimits()
  const login = await call(env, '/auth/login', 'POST', { email: 'rc@example.com', password: 'Correct Horse Battery Staple 123!' }, { ip: '10.2.0.1' })
  const use = await call(env, '/auth/mfa/verify', 'POST', { challengeToken: login.data.challengeToken, code: recoveryCodes[0] }, { ip: '10.2.0.1' })
  assert.equal(use.status, 200)
  // Same code again fails
  resetRateLimits()
  const login2 = await call(env, '/auth/login', 'POST', { email: 'rc@example.com', password: 'Correct Horse Battery Staple 123!' }, { ip: '10.2.0.2' })
  const reuse = await call(env, '/auth/mfa/verify', 'POST', { challengeToken: login2.data.challengeToken, code: recoveryCodes[0] }, { ip: '10.2.0.2' })
  assert.equal(reuse.status, 400)
})

test('regeneration invalidates every old code, new codes work once, failed regeneration preserves old', async () => {
  const { db, env } = fresh()
  const { secret, recoveryCodes: oldCodes } = await registerAndActivate(env, 'regen@example.com', 'Correct Horse Battery Staple 123!')
  const { cookie, csrf } = await loginWithMfa(env, 'regen@example.com', 'Correct Horse Battery Staple 123!', secret)
  // Failed regeneration (wrong password) must preserve old set
  resetRateLimits()
  const failed = await call(env, '/auth/recovery-codes/regenerate', 'POST', { currentPassword: 'Wrong Password 123!', mfaCode: await totpNow(secret) }, { cookie, headers: { 'X-CSRF-Token': csrf }, ip: '10.2.0.3' })
  assert.equal(failed.status, 401)
  assert.equal(db.tables.recovery_codes.length, 10)
  assert.ok(db.tables.recovery_codes.every((r) => r.used === 0))
  // Successful regeneration (new TOTP step after the login above)
  advanceTotp(env)
  resetRateLimits()
  const regen = await call(env, '/auth/recovery-codes/regenerate', 'POST', { currentPassword: 'Correct Horse Battery Staple 123!', mfaCode: await totpNow(secret) }, { cookie, headers: { 'X-CSRF-Token': csrf }, ip: '10.2.0.3' })
  assert.equal(regen.status, 200)
  assert.equal(regen.data.recoveryCodes.length, 10)
  const newCodes = regen.data.recoveryCodes
  // Old code fails at login
  resetRateLimits()
  const login = await call(env, '/auth/login', 'POST', { email: 'regen@example.com', password: 'Correct Horse Battery Staple 123!' }, { ip: '10.2.0.4' })
  const oldUse = await call(env, '/auth/mfa/verify', 'POST', { challengeToken: login.data.challengeToken, code: oldCodes[0] }, { ip: '10.2.0.4' })
  assert.equal(oldUse.status, 400)
  // New code works once, then fails
  resetRateLimits()
  const login2 = await call(env, '/auth/login', 'POST', { email: 'regen@example.com', password: 'Correct Horse Battery Staple 123!' }, { ip: '10.2.0.5' })
  const newUse = await call(env, '/auth/mfa/verify', 'POST', { challengeToken: login2.data.challengeToken, code: newCodes[0] }, { ip: '10.2.0.5' })
  assert.equal(newUse.status, 200)
  resetRateLimits()
  const login3 = await call(env, '/auth/login', 'POST', { email: 'regen@example.com', password: 'Correct Horse Battery Staple 123!' }, { ip: '10.2.0.6' })
  const newReuse = await call(env, '/auth/mfa/verify', 'POST', { challengeToken: login3.data.challengeToken, code: newCodes[0] }, { ip: '10.2.0.6' })
  assert.equal(newReuse.status, 400)
})

test('forgot password: code alone is not enough — recovery transaction is required, reset revokes sessions', async () => {
  const { env } = fresh()
  const { secret, recoveryCodes } = await registerAndActivate(env, 'forgot@example.com', 'Correct Horse Battery Staple 123!')
  const { cookie } = await loginWithMfa(env, 'forgot@example.com', 'Correct Horse Battery Staple 123!', secret)
  // Wrong code fails
  resetRateLimits()
  const bad = await call(env, '/auth/password/forgot', 'POST', { email: 'forgot@example.com', code: '000000' }, { ip: '10.2.0.7' })
  assert.equal(bad.status, 400)
  // Valid TOTP starts a recovery transaction (new step after login)
  advanceTotp(env)
  resetRateLimits()
  const forgot = await call(env, '/auth/password/forgot', 'POST', { email: 'forgot@example.com', code: await totpNow(secret) }, { ip: '10.2.0.7' })
  assert.equal(forgot.status, 200)
  assert.ok(forgot.data.recoveryToken)
  // Reset without a valid transaction fails
  resetRateLimits()
  const noTx = await call(env, '/auth/password/reset', 'POST', { recoveryToken: 'invalid-token', newPassword: 'New Password 123456!' }, { ip: '10.2.0.7' })
  assert.equal(noTx.status, 400)
  // Reset with the transaction succeeds, old session is revoked
  resetRateLimits()
  const reset = await call(env, '/auth/password/reset', 'POST', { recoveryToken: forgot.data.recoveryToken, newPassword: 'New Password 123456!' }, { ip: '10.2.0.7' })
  assert.equal(reset.status, 200)
  const oldSession = await call(env, '/auth/session', 'GET', undefined, { cookie, ip: '10.2.0.7' })
  assert.equal(oldSession.status, 401)
  // Transaction cannot be reused
  resetRateLimits()
  const reuse = await call(env, '/auth/password/reset', 'POST', { recoveryToken: forgot.data.recoveryToken, newPassword: 'Another Password 123!' }, { ip: '10.2.0.7' })
  assert.equal(reuse.status, 400)
  // Fresh login with new password + MFA works
  await loginWithMfa(env, 'forgot@example.com', 'New Password 123456!', secret)
})

test('forgot with a recovery code consumes that code and still requires the transaction', async () => {
  const { env } = fresh()
  const { secret, recoveryCodes } = await registerAndActivate(env, 'forgot2@example.com', 'Correct Horse Battery Staple 123!')
  resetRateLimits()
  const forgot = await call(env, '/auth/password/forgot', 'POST', { email: 'forgot2@example.com', code: recoveryCodes[1] }, { ip: '10.2.0.8' })
  assert.equal(forgot.status, 200)
  assert.ok(forgot.data.recoveryToken)
  // That recovery code is now used and cannot log in
  resetRateLimits()
  const login = await call(env, '/auth/login', 'POST', { email: 'forgot2@example.com', password: 'Correct Horse Battery Staple 123!' }, { ip: '10.2.0.9' })
  const use = await call(env, '/auth/mfa/verify', 'POST', { challengeToken: login.data.challengeToken, code: recoveryCodes[1] }, { ip: '10.2.0.9' })
  assert.equal(use.status, 400)
})

test('password change rotates the current session and revokes others', async () => {
  const { env } = fresh()
  const { secret } = await registerAndActivate(env, 'change@example.com', 'Correct Horse Battery Staple 123!')
  const a = await loginWithMfa(env, 'change@example.com', 'Correct Horse Battery Staple 123!', secret, '10.2.1.1')
  const b = await loginWithMfa(env, 'change@example.com', 'Correct Horse Battery Staple 123!', secret, '10.2.1.2')
  advanceTotp(env)
  resetRateLimits()
  const changed = await call(env, '/auth/password/change', 'POST', { currentPassword: 'Correct Horse Battery Staple 123!', mfaCode: await totpNow(secret), newPassword: 'Changed Password 123!' }, { cookie: a.cookie, headers: { 'X-CSRF-Token': a.csrf }, ip: '10.2.1.1' })
  assert.equal(changed.status, 200)
  assert.ok(changed.sessionCookie, 'new session cookie issued after rotation')
  const other = await call(env, '/auth/session', 'GET', undefined, { cookie: b.cookie, ip: '10.2.1.2' })
  assert.equal(other.status, 401, 'other session revoked')
  const oldCurrent = await call(env, '/auth/session', 'GET', undefined, { cookie: a.cookie, ip: '10.2.1.1' })
  assert.equal(oldCurrent.status, 401, 'old current session rotated out')
  const freshSession = await call(env, '/auth/session', 'GET', undefined, { cookie: changed.sessionCookie, ip: '10.2.1.1' })
  assert.equal(freshSession.status, 200)
})

test('MFA disable requires password and MFA, then login works without MFA', async () => {
  const { env } = fresh()
  const { secret } = await registerAndActivate(env, 'disable@example.com', 'Correct Horse Battery Staple 123!')
  const { cookie, csrf } = await loginWithMfa(env, 'disable@example.com', 'Correct Horse Battery Staple 123!', secret)
  advanceTotp(env)
  resetRateLimits()
  const disabled = await call(env, '/auth/mfa/disable', 'POST', { currentPassword: 'Correct Horse Battery Staple 123!', mfaCode: await totpNow(secret) }, { cookie, headers: { 'X-CSRF-Token': csrf }, ip: '10.2.1.3' })
  assert.equal(disabled.status, 200)
  assert.equal(disabled.data.mfaEnabled, false)
  resetRateLimits()
  const login = await call(env, '/auth/login', 'POST', { email: 'disable@example.com', password: 'Correct Horse Battery Staple 123!' }, { ip: '10.2.1.4' })
  assert.ok(!login.data.mfaRequired)
  assert.ok(login.sessionCookie, 'session issued directly after MFA disabled')
})
