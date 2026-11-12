import test from 'node:test'
import assert from 'node:assert/strict'
import { MockD1, testEnv } from './mock-d1.js'
import { call, registerAndActivate, stubBrevo, lastBrevoCode, verifyEmail, loginWithMfa } from './helpers.js'
import { resetRateLimits } from '../worker/src/security.js'
import { randomBytes, encryptSecret, sha256Hex } from '../worker/src/crypto.js'
import { nowIso } from '../worker/src/db.js'

const PW = 'Correct Horse Battery Staple 123!'
function fresh() { const db = new MockD1(); return { db, env: testEnv(db) } }
async function registerOnly(env, email, ip = '10.3.0.1') {
  resetRateLimits()
  const reg = await call(env, '/auth/register', 'POST', { email, password: PW }, { ip })
  assert.equal(reg.status, 201)
  return reg.data
}
async function loginChallenge(env, email, ip) {
  const login = await call(env, '/auth/login', 'POST', { email, password: PW }, { ip })
  assert.equal(login.status, 200)
  assert.ok(login.data.mfaRequired)
  assert.ok(login.data.challengeToken)
  return login.data.challengeToken
}
function loginRow(db) {
  return db.tables.email_verifications.find((r) => r.purpose === 'login')
}
async function unverifiedMfaUser(env, email, ip = '10.3.0.99') {
  resetRateLimits()
  const reg = await call(env, '/auth/register', 'POST', { email, password: PW }, { ip })
  assert.equal(reg.status, 201)
  const user = env.DB.tables.users[0]
  const encrypted = await encryptSecret(env, randomBytes(20))
  env.DB.tables.mfa_secrets.push({ user_id: user.id, encrypted_secret: encrypted, enabled: 1, last_used_step: null, created_at: nowIso(), updated_at: nowIso() })
  user.mfa_enabled = 1
  user.status = 'active'
  return { userId: user.id }
}

test('send without a valid challenge token fails generically and sends nothing', async () => {
  const { env } = fresh()
  env.BREVO_API_KEY = 'test-brevo-key'
  const stub = stubBrevo()
  try {
    const bad = await call(env, '/auth/mfa/email/send', 'POST', { challengeToken: 'not-a-real-challenge-token' }, { ip: '10.3.1.1' })
    assert.equal(bad.status, 400)
    assert.equal(bad.data.code, 'INVALID_CHALLENGE')
    const missing = await call(env, '/auth/mfa/email/send', 'POST', {}, { ip: '10.3.1.1' })
    assert.equal(missing.status, 400)
    assert.equal(missing.data.code, 'INVALID_CHALLENGE')
    assert.equal(stub.sent.length, 0)
  } finally {
    stub.restore()
  }
})

test('verify with a bogus challenge returns the same generic error as a wrong code', async () => {
  const { env } = fresh()
  const res = await call(env, '/auth/mfa/email/verify', 'POST', { challengeToken: 'not-a-real-challenge-token', code: '123456' }, { ip: '10.3.1.2' })
  assert.equal(res.status, 400)
  assert.equal(res.data.error, 'Invalid or expired sign-in code.')
  assert.equal(res.data.code, 'INVALID_CODE')
})

test('login email endpoints require an allowed Origin', async () => {
  const { env } = fresh()
  const noOrigin = await call(env, '/auth/mfa/email/send', 'POST', { challengeToken: 'x' }, { ip: '10.3.1.3', origin: null })
  assert.equal(noOrigin.status, 403)
  const badOrigin = await call(env, '/auth/mfa/email/verify', 'POST', { challengeToken: 'x', code: '123456' }, { ip: '10.3.1.3', origin: 'https://evil.example.com' })
  assert.equal(badOrigin.status, 403)
})

test('an unverified MFA user gets the same generic error on send and verify', async () => {
  const { db, env } = fresh()
  const email = 'unverified-login@example.com'
  await unverifiedMfaUser(env, email)
  env.BREVO_API_KEY = 'test-brevo-key'
  const stub = stubBrevo()
  try {
    const challengeToken = await loginChallenge(env, email, '10.3.1.4')
    const send = await call(env, '/auth/mfa/email/send', 'POST', { challengeToken }, { ip: '10.3.1.4' })
    assert.equal(send.status, 400)
    assert.equal(send.data.code, 'INVALID_CHALLENGE')
    assert.equal(stub.sent.length, 0)
    const verify = await call(env, '/auth/mfa/email/verify', 'POST', { challengeToken, code: '123456' }, { ip: '10.3.1.4' })
    assert.equal(verify.status, 400)
    assert.equal(verify.data.error, 'Invalid or expired sign-in code.')
    assert.equal(verify.data.code, 'INVALID_CODE')
    assert.equal(db.tables.email_verifications.length, 0)
  } finally {
    stub.restore()
  }
})

test('correct emailed code logs the user in and consumes the challenge', async () => {
  const { db, env } = fresh()
  const email = 'emaillogin@example.com'
  await registerAndActivate(env, email, PW)
  const challengeToken = await loginChallenge(env, email, '10.3.1.5')
  env.BREVO_API_KEY = 'test-brevo-key'
  const stub = stubBrevo()
  let code
  try {
    const send = await call(env, '/auth/mfa/email/send', 'POST', { challengeToken }, { ip: '10.3.1.5' })
    assert.equal(send.status, 200)
    assert.equal(send.data.resendAfter, 60)
    assert.equal(stub.sent.length, 1)
    const sent = stub.sent[0]
    assert.equal(sent.url, 'https://api.brevo.com/v3/smtp/email')
    const body = JSON.parse(sent.options.body)
    assert.equal(body.sender.email, 'verify@kluzar.com')
    assert.equal(body.sender.name, 'Kluzar accounts OTP')
    assert.equal(body.replyTo.email, 'info@kluzar.com')
    assert.equal(body.subject, 'Your Kluzar sign-in code')
    assert.equal(body.to[0].email, email)
    assert.match(body.textContent, /check the Promotions tab/)
    code = lastBrevoCode(stub.sent)
    assert.ok(code)
    const row = loginRow(db)
    assert.ok(row)
    assert.equal(row.purpose, 'login')
    assert.equal(row.code_hash, await sha256Hex(code))
    assert.equal(row.attempts, 0)
    assert.equal(row.verified, 0)
    assert.ok(!('code' in row))
  } finally {
    stub.restore()
  }
  const verify = await call(env, '/auth/mfa/email/verify', 'POST', { challengeToken, code }, { ip: '10.3.1.5' })
  assert.equal(verify.status, 200)
  assert.equal(verify.data.user.email, email)
  assert.ok(verify.data.csrfToken)
  assert.ok(verify.sessionCookie)
  assert.equal(db.tables.login_challenges.length, 0)
  assert.equal(loginRow(db).verified, 1)
})

test('a wrong code fails generically and counts attempts', async () => {
  const { db, env } = fresh()
  const email = 'loginwrong@example.com'
  await registerAndActivate(env, email, PW)
  const challengeToken = await loginChallenge(env, email, '10.3.1.6')
  env.BREVO_API_KEY = 'test-brevo-key'
  const stub = stubBrevo()
  try {
    await call(env, '/auth/mfa/email/send', 'POST', { challengeToken }, { ip: '10.3.1.6' })
  } finally {
    stub.restore()
  }
  const res = await call(env, '/auth/mfa/email/verify', 'POST', { challengeToken, code: '000000' }, { ip: '10.3.1.6' })
  assert.equal(res.status, 400)
  assert.equal(res.data.error, 'Invalid or expired sign-in code.')
  assert.equal(loginRow(db).attempts, 1)
})

test('five wrong attempts lock the code; even the correct code then fails', async () => {
  const { env } = fresh()
  const email = 'loginlocked@example.com'
  await registerAndActivate(env, email, PW)
  const challengeToken = await loginChallenge(env, email, '10.3.1.7')
  env.BREVO_API_KEY = 'test-brevo-key'
  const stub = stubBrevo()
  let code
  try {
    await call(env, '/auth/mfa/email/send', 'POST', { challengeToken }, { ip: '10.3.1.7' })
    code = lastBrevoCode(stub.sent)
  } finally {
    stub.restore()
  }
  for (let i = 0; i < 5; i++) {
    const wrong = await call(env, '/auth/mfa/email/verify', 'POST', { challengeToken, code: '000000' }, { ip: '10.3.1.7' })
    assert.equal(wrong.status, 400)
  }
  const locked = await call(env, '/auth/mfa/email/verify', 'POST', { challengeToken, code }, { ip: '10.3.1.7' })
  assert.equal(locked.status, 400)
  assert.equal(locked.data.error, 'Invalid or expired sign-in code.')
})

test('an expired code fails', async () => {
  const { db, env } = fresh()
  const email = 'loginexpired@example.com'
  await registerAndActivate(env, email, PW)
  const challengeToken = await loginChallenge(env, email, '10.3.1.8')
  env.BREVO_API_KEY = 'test-brevo-key'
  const stub = stubBrevo()
  let code
  try {
    await call(env, '/auth/mfa/email/send', 'POST', { challengeToken }, { ip: '10.3.1.8' })
    code = lastBrevoCode(stub.sent)
  } finally {
    stub.restore()
  }
  loginRow(db).expires_at = new Date(Date.now() - 1000).toISOString()
  const res = await call(env, '/auth/mfa/email/verify', 'POST', { challengeToken, code }, { ip: '10.3.1.8' })
  assert.equal(res.status, 400)
  assert.equal(res.data.error, 'Invalid or expired sign-in code.')
})

test('a used code cannot be reused', async () => {
  const { env } = fresh()
  const email = 'loginreuse@example.com'
  await registerAndActivate(env, email, PW)
  env.BREVO_API_KEY = 'test-brevo-key'
  const stub = stubBrevo()
  let code
  try {
    const firstChallenge = await loginChallenge(env, email, '10.3.1.9')
    await call(env, '/auth/mfa/email/send', 'POST', { challengeToken: firstChallenge }, { ip: '10.3.1.9' })
    code = lastBrevoCode(stub.sent)
    const first = await call(env, '/auth/mfa/email/verify', 'POST', { challengeToken: firstChallenge, code }, { ip: '10.3.1.9' })
    assert.equal(first.status, 200)
  } finally {
    stub.restore()
  }
  const secondChallenge = await loginChallenge(env, email, '10.3.1.10')
  const second = await call(env, '/auth/mfa/email/verify', 'POST', { challengeToken: secondChallenge, code }, { ip: '10.3.1.10' })
  assert.equal(second.status, 400)
  assert.equal(second.data.error, 'Invalid or expired sign-in code.')
})

test('a signup code can never log anyone in', async () => {
  const { db, env } = fresh()
  const email = 'isolated@example.com'
  await registerAndActivate(env, email, PW)
  const user = db.tables.users[0]
  const signupCode = '111111'
  const signupRow = db.tables.email_verifications.find((r) => r.purpose === 'signup')
  assert.ok(signupRow)
  signupRow.code_hash = await sha256Hex(signupCode)
  signupRow.verified = 0
  const challengeToken = await loginChallenge(env, email, '10.3.1.11')
  env.BREVO_API_KEY = 'test-brevo-key'
  const stub = stubBrevo()
  let loginCode
  try {
    await call(env, '/auth/mfa/email/send', 'POST', { challengeToken }, { ip: '10.3.1.11' })
    loginCode = lastBrevoCode(stub.sent)
    assert.ok(loginCode)
    assert.notEqual(loginCode, signupCode)
    assert.equal(db.tables.email_verifications.length, 2)
  } finally {
    stub.restore()
  }
  const withSignupCode = await call(env, '/auth/mfa/email/verify', 'POST', { challengeToken, code: signupCode }, { ip: '10.3.1.11' })
  assert.equal(withSignupCode.status, 400)
  assert.equal(withSignupCode.data.error, 'Invalid or expired sign-in code.')
  const withLoginCode = await call(env, '/auth/mfa/email/verify', 'POST', { challengeToken, code: loginCode }, { ip: '10.3.1.11' })
  assert.equal(withLoginCode.status, 200)
})

test('resend within 60 seconds sends nothing; resend after cooldown sends again', async () => {
  const { db, env } = fresh()
  const email = 'logincooldown@example.com'
  await registerAndActivate(env, email, PW)
  const challengeToken = await loginChallenge(env, email, '10.3.1.12')
  env.BREVO_API_KEY = 'test-brevo-key'
  const stub = stubBrevo()
  try {
    const first = await call(env, '/auth/mfa/email/send', 'POST', { challengeToken }, { ip: '10.3.1.12' })
    assert.equal(first.status, 200)
    assert.equal(stub.sent.length, 1)
    const second = await call(env, '/auth/mfa/email/send', 'POST', { challengeToken }, { ip: '10.3.1.12' })
    assert.equal(second.status, 200)
    assert.equal(stub.sent.length, 1)
    loginRow(db).last_sent_at = new Date(Date.now() - 61 * 1000).toISOString()
    const third = await call(env, '/auth/mfa/email/send', 'POST', { challengeToken }, { ip: '10.3.1.12' })
    assert.equal(third.status, 200)
    assert.equal(stub.sent.length, 2)
  } finally {
    stub.restore()
  }
})

test('send fails closed with 500 when Brevo is not configured', async () => {
  const { db, env } = fresh()
  const email = 'loginnokey@example.com'
  await registerAndActivate(env, email, PW)
  const challengeToken = await loginChallenge(env, email, '10.3.1.13')
  delete env.BREVO_API_KEY
  const stub = stubBrevo()
  try {
    const res = await call(env, '/auth/mfa/email/send', 'POST', { challengeToken }, { ip: '10.3.1.13' })
    assert.equal(res.status, 500)
    assert.equal(stub.sent.length, 0)
    assert.equal(db.tables.email_verifications.filter((r) => r.purpose === 'login').length, 0)
  } finally {
    stub.restore()
  }
})

test('per-IP and per-account rate limits are enforced on login email send', async () => {
  const { env } = fresh()
  const email = 'loginrate@example.com'
  await registerAndActivate(env, email, PW)
  const challengeToken = await loginChallenge(env, email, '10.3.1.14')
  env.BREVO_API_KEY = 'test-brevo-key'
  const stub = stubBrevo()
  try {
    let last
    for (let i = 0; i < 6; i++) {
      last = await call(env, '/auth/mfa/email/send', 'POST', { challengeToken }, { ip: '10.3.1.14' })
    }
    assert.equal(last.status, 429)
  } finally {
    stub.restore()
  }
})

test('TOTP login still works alongside the email-code option', async () => {
  const { env } = fresh()
  const email = 'totpstill@example.com'
  const activated = await registerAndActivate(env, email, PW)
  const res = await loginWithMfa(env, email, PW, activated.secret)
  assert.ok(res.cookie)
  assert.equal(res.user.email, email)
})
