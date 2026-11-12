import test from 'node:test'
import assert from 'node:assert/strict'
import { MockD1, testEnv } from './mock-d1.js'
import { call, registerAndActivate, loginWithMfa, totpNow, secretFromOtpauth, advanceTotp } from './helpers.js'
import { resetRateLimits } from '../worker/src/security.js'
import { b64url } from '../worker/src/crypto.js'
import { resetJwksCache } from '../worker/src/oauth.js'

const PW = 'Correct Horse Battery Staple 123!'
const GOOGLE_CLIENT_ID = 'test-google-client-id'
const MICROSOFT_CLIENT_ID = 'test-ms-client-id'

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

function microsoftClaims(over = {}) {
  const now = Math.floor(Date.now() / 1000)
  return { iss: 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0', aud: MICROSOFT_CLIENT_ID, sub: 'ms-sub-456', preferred_username: 'ms-user@example.com', iat: now, exp: now + 3600, ...over }
}

function fresh() {
  resetRateLimits()
  const db = new MockD1()
  const env = testEnv(db)
  env.GOOGLE_CLIENT_ID = GOOGLE_CLIENT_ID
  env.GOOGLE_CLIENT_SECRET = 'test-google-secret'
  env.MICROSOFT_CLIENT_ID = MICROSOFT_CLIENT_ID
  env.MICROSOFT_CLIENT_SECRET = 'test-ms-secret'
  return { db, env }
}

async function stubIdp() {
  const { keypair, publicJwk } = await testKeys()
  resetJwksCache()
  const origFetch = globalThis.fetch
  globalThis.fetch = async (url, options) => {
    const u = String(url)
    if (u.includes('oauth2.googleapis.com/token') || u.includes('login.microsoftonline.com/common/oauth2/v2.0/token')) {
      const isGoogle = u.includes('googleapis.com')
      const claims = isGoogle ? googleClaims() : microsoftClaims()
      const idToken = await signIdToken({ key: keypair.privateKey, claims })
      return { ok: true, status: 200, json: async () => ({ access_token: 'test-access', id_token: idToken, token_type: 'Bearer', expires_in: 3600 }) }
    }
    if (u.includes('googleapis.com/oauth2/v3/certs') || u.includes('login.microsoftonline.com/common/discovery/v2.0/keys')) {
      return { ok: true, status: 200, json: async () => ({ keys: [publicJwk] }) }
    }
    throw new Error('unexpected fetch: ' + u)
  }
  return { restore() { globalThis.fetch = origFetch } }
}

async function startOAuth(env, provider, ip) {
  return call(env, '/auth/' + provider, 'GET', undefined, { ip, origin: null })
}

function stateFromRedirect(res) {
  const loc = res.res.headers.get('Location') || ''
  const u = new URL(loc)
  return { location: loc, state: u.searchParams.get('state') }
}

async function callback(env, provider, code, state, ip) {
  return call(env, '/auth/' + provider + '/callback?code=' + encodeURIComponent(code) + '&state=' + encodeURIComponent(state), 'GET', undefined, { ip, origin: null })
}

function handoffCookieFrom(res) {
  const m = (res.setCookie || '').match(/kluzar_oauth_handoff=([^;]+)/)
  return m ? m[1] : null
}

async function doHandoff(env, cookieValue, ip) {
  return call(env, '/auth/oauth/handoff', 'POST', {}, { ip, cookie: 'kluzar_oauth_handoff=' + cookieValue })
}

async function oauthSetupToken(env, provider, ip) {
  const start = await startOAuth(env, provider, ip)
  assert.equal(start.status, 302)
  const { state } = stateFromRedirect(start)
  const cb = await callback(env, provider, 'test-code-123', state, ip)
  assert.equal(cb.status, 302)
  assert.ok(String(cb.res.headers.get('Location') || '').includes('/mfa-setup/'))
  const cookieValue = handoffCookieFrom(cb)
  assert.ok(cookieValue, 'callback must set the handoff cookie')
  const h = await doHandoff(env, cookieValue, ip)
  assert.equal(h.status, 200)
  assert.ok(h.data.setupToken, 'handoff must return a setup token')
  return h.data.setupToken
}

async function defer(env, setupToken, ip) {
  return call(env, '/auth/mfa/defer', 'POST', { setupToken }, { ip })
}

test('OAuth handoff for a new user returns an oauth-sourced setup token', async () => {
  const { db, env } = fresh()
  const stub = await stubIdp()
  try {
    const start = await startOAuth(env, 'google', '10.7.2.1')
    assert.equal(start.status, 302)
    const { state } = stateFromRedirect(start)
    const cb = await callback(env, 'google', 'test-code-123', state, '10.7.2.1')
    assert.equal(cb.status, 302)
    const h = await doHandoff(env, handoffCookieFrom(cb), '10.7.2.1')
    assert.equal(h.status, 200)
    assert.ok(h.data.setupToken)
    assert.equal(h.data.source, 'oauth')
    const row = db.tables.setup_tokens.find((r) => r.user_id)
    assert.ok(row)
    assert.equal(row.source, 'oauth')
    const user = db.tables.users[0]
    assert.equal(user.status, 'pending_mfa')
    assert.equal(user.email_verified, 1)
    assert.equal(user.password_set, 0)
  } finally {
    stub.restore()
  }
})

test('Defer activates an OAuth pending_mfa user and creates a session without MFA', async () => {
  const { db, env } = fresh()
  const stub = await stubIdp()
  try {
    const setupToken = await oauthSetupToken(env, 'google', '10.7.2.2')
    const res = await defer(env, setupToken, '10.7.2.2')
    assert.equal(res.status, 200)
    assert.ok(res.sessionCookie, 'defer must set a session cookie')
    assert.equal(res.data.user.email, 'oauth-user@example.com')
    assert.equal(res.data.user.mfaEnabled, false)
    assert.ok(res.data.csrfToken)
    const user = db.tables.users[0]
    assert.equal(user.status, 'active')
    assert.equal(user.mfa_enabled, 0)
    assert.equal(db.tables.setup_tokens.length, 0, 'defer must consume the setup token')
    const session = await call(env, '/auth/session', 'GET', undefined, { ip: '10.7.2.2', cookie: res.sessionCookie })
    assert.equal(session.status, 200)
    assert.equal(session.data.authenticated, true)
    assert.equal(session.data.user.mfaEnabled, false)
    assert.equal(session.data.entitlement.plan, 'free')
  } finally {
    stub.restore()
  }
})

test('Defer works for Microsoft sign-in too', async () => {
  const { db, env } = fresh()
  const stub = await stubIdp()
  try {
    const setupToken = await oauthSetupToken(env, 'microsoft', '10.7.2.3')
    const res = await defer(env, setupToken, '10.7.2.3')
    assert.equal(res.status, 200)
    assert.equal(res.data.user.email, 'ms-user@example.com')
    assert.equal(res.data.user.mfaEnabled, false)
    assert.equal(db.tables.users[0].status, 'active')
  } finally {
    stub.restore()
  }
})

test('Defer is rejected for a password-signup setup token and the account stays pending_mfa', async () => {
  const { db, env } = fresh()
  const reg = await call(env, '/auth/register', 'POST', { email: 'pw-user@example.com', password: PW }, { ip: '10.7.2.4' })
  assert.equal(reg.status, 201)
  const row = db.tables.setup_tokens[0]
  assert.ok(row)
  assert.equal(row.source, 'password')
  const res = await defer(env, reg.data.setupToken, '10.7.2.4')
  assert.equal(res.status, 400)
  assert.equal(res.data.code, 'INVALID_SETUP')
  assert.ok(!res.sessionCookie, 'rejected defer must not set a session')
  assert.equal(db.tables.users[0].status, 'pending_mfa')
  assert.equal(db.tables.setup_tokens.length, 1, 'rejected defer must not consume the token')
})

test('Defer is rejected without a valid setup token', async () => {
  const { env } = fresh()
  const garbage = await defer(env, 'nonexistent-token-123', '10.7.2.5')
  assert.equal(garbage.status, 400)
  assert.equal(garbage.data.code, 'INVALID_SETUP')
  const empty = await call(env, '/auth/mfa/defer', 'POST', {}, { ip: '10.7.2.5' })
  assert.equal(empty.status, 400)
  assert.equal(empty.data.code, 'INVALID_SETUP')
})

test('Defer consumes the token: a second defer with the same token fails', async () => {
  const { env } = fresh()
  const stub = await stubIdp()
  try {
    const setupToken = await oauthSetupToken(env, 'google', '10.7.2.6')
    const first = await defer(env, setupToken, '10.7.2.6')
    assert.equal(first.status, 200)
    const second = await defer(env, setupToken, '10.7.2.6')
    assert.equal(second.status, 400)
    assert.equal(second.data.code, 'INVALID_SETUP')
  } finally {
    stub.restore()
  }
})

test('Defer is rate-limited per IP', async () => {
  const { env } = fresh()
  const ip = '10.7.2.7'
  let last = null
  for (let i = 0; i < 11; i++) {
    last = await defer(env, 'nonexistent-token-123', ip)
  }
  assert.equal(last.status, 429)
  assert.equal(last.data.code, 'RATE_LIMITED')
})

test('A deferred OAuth user can start MFA setup later without a current password', async () => {
  const { db, env } = fresh()
  const stub = await stubIdp()
  try {
    const setupToken = await oauthSetupToken(env, 'google', '10.7.2.8')
    const deferred = await defer(env, setupToken, '10.7.2.8')
    assert.equal(deferred.status, 200)
    const setup = await call(env, '/auth/mfa/setup', 'POST', {}, { ip: '10.7.2.8', cookie: deferred.sessionCookie, headers: { 'X-CSRF-Token': deferred.data.csrfToken } })
    assert.equal(setup.status, 200)
    assert.ok(setup.data.otpauthUrl)
    assert.ok(setup.data.manualKey)
    const secret = secretFromOtpauth(setup.data.otpauthUrl)
    const code = await totpNow(secret)
    const verify = await call(env, '/auth/mfa/verify', 'POST', { code }, { ip: '10.7.2.8', cookie: deferred.sessionCookie, headers: { 'X-CSRF-Token': deferred.data.csrfToken } })
    assert.equal(verify.status, 200)
    assert.equal(verify.data.mfaEnabled, true)
    const session = await call(env, '/auth/session', 'GET', undefined, { ip: '10.7.2.8', cookie: deferred.sessionCookie })
    assert.equal(session.status, 200)
    assert.equal(session.data.user.mfaEnabled, true)
    assert.equal(db.tables.users[0].password_set, 0)
  } finally {
    stub.restore()
  }
})

test('A logged-in password user still needs the current password for MFA setup', async () => {
  const { env } = fresh()
  const activated = await registerAndActivate(env, 'pw-setup@example.com', PW)
  const logged = await loginWithMfa(env, 'pw-setup@example.com', PW, activated.secret)
  const missing = await call(env, '/auth/mfa/setup', 'POST', {}, { ip: '10.7.2.9', cookie: logged.cookie, headers: { 'X-CSRF-Token': logged.csrf } })
  assert.equal(missing.status, 401)
  assert.equal(missing.data.code, 'PASSWORD_REQUIRED')
  const wrong = await call(env, '/auth/mfa/setup', 'POST', { currentPassword: 'Wrong Password 123!' }, { ip: '10.7.2.9', cookie: logged.cookie, headers: { 'X-CSRF-Token': logged.csrf } })
  assert.equal(wrong.status, 401)
  assert.equal(wrong.data.code, 'INVALID_CREDENTIALS')
  const ok = await call(env, '/auth/mfa/setup', 'POST', { currentPassword: PW }, { ip: '10.7.2.9', cookie: logged.cookie, headers: { 'X-CSRF-Token': logged.csrf } })
  assert.equal(ok.status, 200)
  assert.ok(ok.data.otpauthUrl)
  advanceTotp(env)
})
