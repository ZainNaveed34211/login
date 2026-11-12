import test from 'node:test'
import assert from 'node:assert/strict'
import { MockD1, testEnv } from './mock-d1.js'
import { call, registerAndActivate, stubBrevo } from './helpers.js'
import { resetRateLimits } from '../worker/src/security.js'
import { b64url } from '../worker/src/crypto.js'
import { resetJwksCache } from '../worker/src/oauth.js'
import { sendWelcomeEmail, sendWelcomeEmailOnce } from '../worker/src/email.js'

const PW = 'Correct Horse Battery Staple 123!'
const GOOGLE_CLIENT_ID = 'test-google-client-id'
const YEAR = String(new Date().getFullYear())

function welcomeSent(sent) {
  return sent
    .map((s) => JSON.parse(s.options.body))
    .filter((b) => b.sender.email === 'hello@kluzar.com')
}

test('welcome email uses the general sender, not the OTP sender', async () => {
  const stub = stubBrevo()
  try {
    const ok = await sendWelcomeEmail({ BREVO_API_KEY: 'test-brevo-key' }, 'new@example.com')
    assert.equal(ok, true)
    assert.equal(stub.sent.length, 1)
    const body = JSON.parse(stub.sent[0].options.body)
    assert.equal(body.sender.email, 'hello@kluzar.com')
    assert.equal(body.sender.name, 'Kluzar')
    assert.equal(body.replyTo.email, 'info@kluzar.com')
    assert.equal(body.subject, 'Welcome to Kluzar')
    assert.equal(body.to[0].email, 'new@example.com')
  } finally {
    stub.restore()
  }
})

test('welcome email html follows the white-card reference with no code and no big buttons', async () => {
  const stub = stubBrevo()
  try {
    await sendWelcomeEmail({ BREVO_API_KEY: 'test-brevo-key' }, 'new@example.com')
    const body = JSON.parse(stub.sent[0].options.body)
    assert.ok(body.htmlContent.includes('Welcome!'))
    assert.ok(body.htmlContent.includes('Thank you for creating your Kluzar account.'))
    assert.ok(body.htmlContent.includes('href="https://contact.kluzar.com"'))
    assert.ok(body.htmlContent.includes('>contact us</a>'))
    assert.ok(body.htmlContent.includes('Thanks again!'))
    assert.ok(body.htmlContent.includes('https://kluzar.com/logo.png'))
    assert.ok(body.htmlContent.includes('&copy; ' + YEAR + ' Kluzar. All rights reserved.'))
    assert.ok(body.htmlContent.includes('href="https://support.kluzar.com"'))
    assert.ok(body.htmlContent.includes('href="https://kluzar.com"'))
    assert.ok(body.htmlContent.includes('info@kluzar.com'))
    assert.doesNotMatch(body.htmlContent.replace(/<[^>]*>/g, ''), /\d{6}/)
    assert.doesNotMatch(body.textContent, /\d{6}/)
    assert.doesNotMatch(body.htmlContent, /border-radius:999px/)
    assert.doesNotMatch(body.htmlContent, /<script/i)
    assert.doesNotMatch(body.htmlContent, /<style/i)
    assert.doesNotMatch(body.htmlContent, /@import|fonts\.googleapis|fonts\.gstatic/i)
    assert.ok(body.textContent.includes('Welcome!'))
    assert.ok(body.textContent.includes('Thank you for creating your Kluzar account.'))
    assert.ok(body.textContent.includes('contact us (https://contact.kluzar.com)'))
    assert.ok(body.textContent.includes('Thanks again!'))
  } finally {
    stub.restore()
  }
})

test('welcome email send returns false without a Brevo key', async () => {
  assert.equal(await sendWelcomeEmail({}, 'new@example.com'), false)
})

test('sendWelcomeEmailOnce sends exactly once across repeated calls', async () => {
  resetRateLimits()
  const db = new MockD1()
  const env = testEnv(db)
  env.BREVO_API_KEY = 'test-brevo-key'
  db.tables.users.push({ id: 'u1', email: 'unit@example.com', email_normalized: 'unit@example.com', status: 'active', email_verified: 1, mfa_enabled: 1, welcome_email_sent: 0 })
  const stub = stubBrevo()
  try {
    assert.equal(await sendWelcomeEmailOnce(env, 'u1', 'unit@example.com'), true)
    assert.equal(await sendWelcomeEmailOnce(env, 'u1', 'unit@example.com'), false)
    assert.equal(await sendWelcomeEmailOnce(env, 'u1', 'unit@example.com'), false)
    assert.equal(welcomeSent(stub.sent).length, 1)
    assert.equal(db.tables.users[0].welcome_email_sent, 1)
  } finally {
    stub.restore()
  }
})

test('sendWelcomeEmailOnce releases the flag when Brevo fails so a later trigger can retry', async () => {
  resetRateLimits()
  const db = new MockD1()
  const env = testEnv(db)
  env.BREVO_API_KEY = 'test-brevo-key'
  db.tables.users.push({ id: 'u1', email: 'unit@example.com', email_normalized: 'unit@example.com', status: 'active', email_verified: 1, mfa_enabled: 1, welcome_email_sent: 0 })
  const origFetch = globalThis.fetch
  globalThis.fetch = async () => ({ ok: false, status: 500, json: async () => ({}) })
  try {
    assert.equal(await sendWelcomeEmailOnce(env, 'u1', 'unit@example.com'), false)
    assert.equal(db.tables.users[0].welcome_email_sent, 0)
  } finally {
    globalThis.fetch = origFetch
  }
  const stub = stubBrevo()
  try {
    assert.equal(await sendWelcomeEmailOnce(env, 'u1', 'unit@example.com'), true)
    assert.equal(welcomeSent(stub.sent).length, 1)
    assert.equal(db.tables.users[0].welcome_email_sent, 1)
  } finally {
    stub.restore()
  }
})

test('MFA setup completion sends the welcome email exactly once', async () => {
  resetRateLimits()
  const db = new MockD1()
  const env = testEnv(db)
  env.BREVO_API_KEY = 'test-brevo-key'
  const stub = stubBrevo()
  try {
    await registerAndActivate(env, 'pw-welcome@example.com', PW)
    assert.equal(welcomeSent(stub.sent).length, 1)
    assert.equal(db.tables.users[0].welcome_email_sent, 1)
    assert.equal(await sendWelcomeEmailOnce(env, db.tables.users[0].id, 'pw-welcome@example.com'), false)
    assert.equal(welcomeSent(stub.sent).length, 1)
  } finally {
    stub.restore()
  }
})

let keys = null
async function testKeys() {
  if (keys) return keys
  const keypair = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  )
  const publicJwk = await crypto.subtle.exportKey('jwk', keypair.publicKey)
  publicJwk.kid = 'test-key-1'
  publicJwk.alg = 'RS256'
  publicJwk.use = 'sig'
  keys = { keypair, publicJwk }
  return keys
}

function b64urlStr(s) {
  return b64url(new TextEncoder().encode(s))
}

async function signIdToken({ key, kid = 'test-key-1', claims }) {
  const header = { alg: 'RS256', typ: 'JWT', kid }
  const h = b64urlStr(JSON.stringify(header))
  const p = b64urlStr(JSON.stringify(claims))
  const sig = await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, key, new TextEncoder().encode(h + '.' + p))
  return h + '.' + p + '.' + b64url(new Uint8Array(sig))
}

function googleClaims(over = {}) {
  const now = Math.floor(Date.now() / 1000)
  return { iss: 'https://accounts.google.com', aud: GOOGLE_CLIENT_ID, sub: 'google-sub-123', email: 'oauth-user@example.com', email_verified: true, iat: now, exp: now + 3600, ...over }
}

async function stubIdpAndBrevo(sent) {
  const { keypair, publicJwk } = await testKeys()
  resetJwksCache()
  const origFetch = globalThis.fetch
  globalThis.fetch = async (url, options) => {
    const u = String(url)
    if (u.includes('api.brevo.com')) {
      sent.push({ url, options })
      return { ok: true, status: 201, json: async () => ({ messageId: 'test-message-id' }) }
    }
    if (u.includes('oauth2.googleapis.com/token')) {
      const idToken = await signIdToken({ key: keypair.privateKey, claims: googleClaims() })
      return { ok: true, status: 200, json: async () => ({ access_token: 'test-access', id_token: idToken, token_type: 'Bearer', expires_in: 3600 }) }
    }
    if (u.includes('googleapis.com/oauth2/v3/certs')) {
      return { ok: true, status: 200, json: async () => ({ keys: [publicJwk] }) }
    }
    throw new Error('unexpected fetch: ' + u)
  }
  return { restore() { globalThis.fetch = origFetch } }
}

async function oauthSetupToken(env, ip) {
  const start = await call(env, '/auth/google', 'GET', undefined, { ip, origin: null })
  assert.equal(start.status, 302)
  const loc = start.res.headers.get('Location') || ''
  const state = new URL(loc).searchParams.get('state')
  const cb = await call(env, '/auth/google/callback?code=test-code-123&state=' + encodeURIComponent(state), 'GET', undefined, { ip, origin: null })
  assert.equal(cb.status, 302)
  const m = (cb.setCookie || '').match(/kluzar_oauth_handoff=([^;]+)/)
  assert.ok(m, 'callback must set the handoff cookie')
  const h = await call(env, '/auth/oauth/handoff', 'POST', {}, { ip, cookie: 'kluzar_oauth_handoff=' + m[1] })
  assert.equal(h.status, 200)
  assert.ok(h.data.setupToken, 'handoff must return a setup token')
  return h.data.setupToken
}

test('OAuth MFA defer sends the welcome email exactly once', async () => {
  resetRateLimits()
  const db = new MockD1()
  const env = testEnv(db)
  env.GOOGLE_CLIENT_ID = GOOGLE_CLIENT_ID
  env.GOOGLE_CLIENT_SECRET = 'test-google-client-secret'
  env.BREVO_API_KEY = 'test-brevo-key'
  const sent = []
  const stub = await stubIdpAndBrevo(sent)
  try {
    const setupToken = await oauthSetupToken(env, '10.9.1.1')
    const res = await call(env, '/auth/mfa/defer', 'POST', { setupToken }, { ip: '10.9.1.1' })
    assert.equal(res.status, 200)
    assert.equal(welcomeSent(sent).length, 1)
    assert.equal(db.tables.users[0].welcome_email_sent, 1)
    assert.equal(await sendWelcomeEmailOnce(env, db.tables.users[0].id, 'oauth-user@example.com'), false)
    assert.equal(welcomeSent(sent).length, 1)
  } finally {
    stub.restore()
  }
})
