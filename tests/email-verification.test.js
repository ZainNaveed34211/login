import test from 'node:test'
import assert from 'node:assert/strict'
import { MockD1, testEnv } from './mock-d1.js'
import { call, registerAndActivate, stubBrevo, lastBrevoCode, verifyEmail, totpNow, secretFromOtpauth } from './helpers.js'
import { resetRateLimits } from '../worker/src/security.js'
import { randomBytes, base32Encode, encryptSecret, sha256Hex, randomToken } from '../worker/src/crypto.js'
import { nowIso, isoPlus } from '../worker/src/db.js'

const PW = 'Correct Horse Battery Staple 123!'
function fresh() { const db = new MockD1(); return { db, env: testEnv(db) } }
async function registerOnly(env, email, ip = '10.2.0.1') {
  resetRateLimits()
  const reg = await call(env, '/auth/register', 'POST', { email, password: PW }, { ip })
  assert.equal(reg.status, 201)
  return reg.data
}

test('send to an unknown email returns the generic 200 and sends nothing', async () => {
  const { env } = fresh()
  env.BREVO_API_KEY = 'test-brevo-key'
  const stub = stubBrevo()
  try {
    const res = await call(env, '/auth/verification/send', 'POST', { email: 'nobody@example.com' }, { ip: '10.2.1.1' })
    assert.equal(res.status, 200)
    assert.equal(res.data.message, 'If an account exists with this email, a verification code has been sent.')
    assert.equal(res.data.resendAfter, 60)
    assert.equal(stub.sent.length, 0)
  } finally {
    stub.restore()
  }
})

test('send to a registered email calls Brevo with the verify sender and stores only a hash', async () => {
  const { db, env } = fresh()
  const email = 'send@example.com'
  await registerOnly(env, email)
  env.BREVO_API_KEY = 'test-brevo-key'
  const stub = stubBrevo()
  try {
    const res = await call(env, '/auth/verification/send', 'POST', { email }, { ip: '10.2.1.2' })
    assert.equal(res.status, 200)
    assert.equal(stub.sent.length, 1)
    const sent = stub.sent[0]
    assert.equal(sent.url, 'https://api.brevo.com/v3/smtp/email')
    assert.equal(sent.options.headers['api-key'], 'test-brevo-key')
    const body = JSON.parse(sent.options.body)
    assert.equal(body.sender.email, 'verify@kluzar.com')
    assert.equal(body.sender.name, 'Kluzar accounts OTP')
    assert.equal(body.replyTo.email, 'info@kluzar.com')
    assert.equal(body.to[0].email, email)
    assert.match(body.textContent, /\d{6}/)
    const code = body.textContent.match(/(\d{6})/)[1]
    const row = db.tables.email_verifications[0]
    assert.ok(row)
    assert.equal(row.email_normalized, email)
    assert.equal(row.code_hash, await sha256Hex(code))
    assert.equal(row.attempts, 0)
    assert.equal(row.verified, 0)
    assert.ok(!('code' in row))
  } finally {
    stub.restore()
  }
})

test('resend within 60 seconds sends nothing; resend after cooldown sends again', async () => {
  const { db, env } = fresh()
  const email = 'cooldown@example.com'
  await registerOnly(env, email)
  env.BREVO_API_KEY = 'test-brevo-key'
  const stub = stubBrevo()
  try {
    const first = await call(env, '/auth/verification/send', 'POST', { email }, { ip: '10.2.1.3' })
    assert.equal(first.status, 200)
    assert.equal(stub.sent.length, 1)
    const second = await call(env, '/auth/verification/send', 'POST', { email }, { ip: '10.2.1.3' })
    assert.equal(second.status, 200)
    assert.equal(stub.sent.length, 1)
    db.tables.email_verifications[0].last_sent_at = new Date(Date.now() - 61 * 1000).toISOString()
    const third = await call(env, '/auth/verification/send', 'POST', { email }, { ip: '10.2.1.3' })
    assert.equal(third.status, 200)
    assert.equal(stub.sent.length, 2)
  } finally {
    stub.restore()
  }
})

test('send fails closed with 500 when Brevo is not configured', async () => {
  const { db, env } = fresh()
  const email = 'nokey@example.com'
  await registerOnly(env, email)
  const stub = stubBrevo()
  try {
    const res = await call(env, '/auth/verification/send', 'POST', { email }, { ip: '10.2.1.4' })
    assert.equal(res.status, 500)
    assert.equal(stub.sent.length, 0)
    assert.equal(db.tables.email_verifications.length, 0)
  } finally {
    stub.restore()
  }
})

test('send to an already verified user sends nothing', async () => {
  const { env } = fresh()
  const email = 'verified@example.com'
  await registerAndActivate(env, email, PW)
  const stub = stubBrevo()
  try {
    const res = await call(env, '/auth/verification/send', 'POST', { email }, { ip: '10.2.1.5' })
    assert.equal(res.status, 200)
    assert.equal(stub.sent.length, 0)
  } finally {
    stub.restore()
  }
})

test('verify with the correct code marks the email verified', async () => {
  const { db, env } = fresh()
  const email = 'good@example.com'
  await registerOnly(env, email)
  env.BREVO_API_KEY = 'test-brevo-key'
  const stub = stubBrevo()
  let code
  try {
    await call(env, '/auth/verification/send', 'POST', { email }, { ip: '10.2.1.6' })
    code = lastBrevoCode(stub.sent)
    assert.ok(code)
  } finally {
    stub.restore()
  }
  const res = await call(env, '/auth/verification/verify', 'POST', { email, code }, { ip: '10.2.1.6' })
  assert.equal(res.status, 200)
  assert.equal(res.data.emailVerified, true)
  assert.equal(db.tables.users[0].email_verified, 1)
  assert.equal(db.tables.email_verifications[0].verified, 1)
})

test('verify with a wrong code fails generically and counts attempts', async () => {
  const { db, env } = fresh()
  const email = 'wrong@example.com'
  await registerOnly(env, email)
  env.BREVO_API_KEY = 'test-brevo-key'
  const stub = stubBrevo()
  try {
    await call(env, '/auth/verification/send', 'POST', { email }, { ip: '10.2.1.7' })
  } finally {
    stub.restore()
  }
  const res = await call(env, '/auth/verification/verify', 'POST', { email, code: '000000' }, { ip: '10.2.1.7' })
  assert.equal(res.status, 400)
  assert.equal(res.data.error, 'Invalid or expired verification code.')
  assert.equal(db.tables.email_verifications[0].attempts, 1)
  assert.equal(db.tables.users[0].email_verified, 0)
})

test('five wrong attempts lock the code; even the correct code then fails', async () => {
  const { env } = fresh()
  const email = 'locked@example.com'
  await registerOnly(env, email)
  env.BREVO_API_KEY = 'test-brevo-key'
  const stub = stubBrevo()
  let code
  try {
    await call(env, '/auth/verification/send', 'POST', { email }, { ip: '10.2.1.8' })
    code = lastBrevoCode(stub.sent)
  } finally {
    stub.restore()
  }
  for (let i = 0; i < 5; i++) {
    const wrong = await call(env, '/auth/verification/verify', 'POST', { email, code: '000000' }, { ip: '10.2.1.8' })
    assert.equal(wrong.status, 400)
  }
  const locked = await call(env, '/auth/verification/verify', 'POST', { email, code }, { ip: '10.2.1.8' })
  assert.equal(locked.status, 400)
  assert.equal(locked.data.error, 'Invalid or expired verification code.')
})

test('an expired code fails', async () => {
  const { db, env } = fresh()
  const email = 'expired@example.com'
  await registerOnly(env, email)
  env.BREVO_API_KEY = 'test-brevo-key'
  const stub = stubBrevo()
  let code
  try {
    await call(env, '/auth/verification/send', 'POST', { email }, { ip: '10.2.1.9' })
    code = lastBrevoCode(stub.sent)
  } finally {
    stub.restore()
  }
  db.tables.email_verifications[0].expires_at = new Date(Date.now() - 1000).toISOString()
  const res = await call(env, '/auth/verification/verify', 'POST', { email, code }, { ip: '10.2.1.9' })
  assert.equal(res.status, 400)
  assert.equal(res.data.error, 'Invalid or expired verification code.')
})

test('verify for an unknown email returns the same generic error as a wrong code', async () => {
  const { env } = fresh()
  const unknown = await call(env, '/auth/verification/verify', 'POST', { email: 'nobody@example.com', code: '123456' }, { ip: '10.2.1.10' })
  const wrong = await call(env, '/auth/verification/verify', 'POST', { email: 'alsonobody@example.com', code: '000000' }, { ip: '10.2.1.10' })
  assert.equal(unknown.status, 400)
  assert.equal(wrong.status, 400)
  assert.equal(unknown.data.error, wrong.data.error)
  assert.equal(unknown.data.error, 'Invalid or expired verification code.')
})

test('a used code cannot be reused', async () => {
  const { env } = fresh()
  const email = 'reuse@example.com'
  await registerOnly(env, email)
  env.BREVO_API_KEY = 'test-brevo-key'
  const stub = stubBrevo()
  let code
  try {
    await call(env, '/auth/verification/send', 'POST', { email }, { ip: '10.2.1.11' })
    code = lastBrevoCode(stub.sent)
  } finally {
    stub.restore()
  }
  const first = await call(env, '/auth/verification/verify', 'POST', { email, code }, { ip: '10.2.1.11' })
  assert.equal(first.status, 200)
  const second = await call(env, '/auth/verification/verify', 'POST', { email, code }, { ip: '10.2.1.11' })
  assert.equal(second.status, 400)
})

test('MFA setup is blocked until the email is verified, then allowed', async () => {
  const { env } = fresh()
  const email = 'gate@example.com'
  const reg = await registerOnly(env, email)
  const blocked = await call(env, '/auth/mfa/setup', 'POST', { setupToken: reg.setupToken }, { ip: '10.2.1.12' })
  assert.equal(blocked.status, 400)
  assert.equal(blocked.data.code, 'EMAIL_NOT_VERIFIED')
  await verifyEmail(env, email)
  const allowed = await call(env, '/auth/mfa/setup', 'POST', { setupToken: reg.setupToken }, { ip: '10.2.1.12' })
  assert.equal(allowed.status, 200)
  assert.ok(allowed.data.otpauthUrl)
})

test('MFA verify is blocked until the email is verified', async () => {
  const { db, env } = fresh()
  const email = 'vgate@example.com'
  const reg = await registerOnly(env, email)
  const user = db.tables.users[0]
  const secretBytes = randomBytes(20)
  const encrypted = await encryptSecret(env, secretBytes)
  const setupToken = randomToken(32)
  const setupHash = await sha256Hex(setupToken)
  db.tables.pending_mfa_secrets.push({ user_id: user.id, encrypted_secret: encrypted, created_at: nowIso(), expires_at: isoPlus(30 * 60 * 1000) })
  db.tables.setup_tokens.push({ id: randomToken(16), user_id: user.id, token_hash: setupHash, created_at: nowIso(), expires_at: isoPlus(30 * 60 * 1000) })
  const code = await totpNow(base32Encode(secretBytes))
  const blocked = await call(env, '/auth/mfa/verify', 'POST', { setupToken, code }, { ip: '10.2.1.13' })
  assert.equal(blocked.status, 400)
  assert.equal(blocked.data.code, 'EMAIL_NOT_VERIFIED')
})

test('verification endpoints require an allowed Origin', async () => {
  const { env } = fresh()
  const noOrigin = await call(env, '/auth/verification/send', 'POST', { email: 'x@example.com' }, { ip: '10.2.1.14', origin: null })
  assert.equal(noOrigin.status, 403)
  const badOrigin = await call(env, '/auth/verification/verify', 'POST', { email: 'x@example.com', code: '123456' }, { ip: '10.2.1.14', origin: 'https://evil.example.com' })
  assert.equal(badOrigin.status, 403)
})

test('per-IP rate limit is enforced on verification send', async () => {
  const { env } = fresh()
  let last
  for (let i = 0; i < 6; i++) {
    last = await call(env, '/auth/verification/send', 'POST', { email: `rate${i}@example.com` }, { ip: '10.2.1.15' })
  }
  assert.equal(last.status, 429)
})
