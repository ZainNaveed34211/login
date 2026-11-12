import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { MockD1, testEnv } from './mock-d1.js'
import { call, registerAndActivate, totpNow, secretFromOtpauth, advanceTotp } from './helpers.js'
import { resetRateLimits } from '../worker/src/security.js'
import { b64url, sha256Hex } from '../worker/src/crypto.js'
import { resetJwksCache } from '../worker/src/oauth.js'

const root = path.dirname(fileURLToPath(import.meta.url))
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
  const other = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  )
  const publicJwk = await crypto.subtle.exportKey('jwk', keypair.publicKey)
  publicJwk.kid = 'test-key-1'
  publicJwk.alg = 'RS256'
  publicJwk.use = 'sig'
  keys = { keypair, other, publicJwk }
  return keys
}

function b64urlStr(s) {
  return b64url(new TextEncoder().encode(s))
}

async function signIdToken({ key, kid = 'test-key-1', alg = 'RS256', claims }) {
  const header = { alg, typ: 'JWT', kid }
  const h = b64urlStr(JSON.stringify(header))
  const p = b64urlStr(JSON.stringify(claims))
  if (alg === 'none') return h + '.' + p + '.'
  const sig = await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, key, new TextEncoder().encode(h + '.' + p))
  return h + '.' + p + '.' + b64url(new Uint8Array(sig))
}

function googleClaims(over = {}) {
  const now = Math.floor(Date.now() / 1000)
  return {
    iss: 'https://accounts.google.com',
    aud: GOOGLE_CLIENT_ID,
    sub: 'google-sub-123',
    email: 'oauth-user@example.com',
    email_verified: true,
    iat: now,
    exp: now + 3600,
    ...over,
  }
}

function microsoftClaims(over = {}) {
  const now = Math.floor(Date.now() / 1000)
  return {
    iss: 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0',
    aud: MICROSOFT_CLIENT_ID,
    sub: 'ms-sub-456',
    preferred_username: 'ms-user@example.com',
    iat: now,
    exp: now + 3600,
    ...over,
  }
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
  const { keypair, other, publicJwk } = await testKeys()
  resetJwksCache()
  const behavior = {
    googleClaims: () => googleClaims(),
    microsoftClaims: () => microsoftClaims(),
    tokenError: false,
    jwksError: false,
    expectChallenge: null,
    signingKey: keypair.privateKey,
    otherKey: other.privateKey,
    kid: 'test-key-1',
    alg: 'RS256',
  }
  const sent = []
  const origFetch = globalThis.fetch
  globalThis.fetch = async (url, options) => {
    sent.push({ url, options })
    const u = String(url)
    if (u.includes('oauth2.googleapis.com/token') || u.includes('login.microsoftonline.com/common/oauth2/v2.0/token')) {
      if (behavior.tokenError) return { ok: false, status: 400, json: async () => ({ error: 'invalid_grant' }) }
      const body = new URLSearchParams(options.body)
      const verifier = body.get('code_verifier') || ''
      if (behavior.expectChallenge) {
        const { sha256Bytes } = await import('../worker/src/oauth.js')
        const challenge = b64url(await sha256Bytes(verifier))
        if (challenge !== behavior.expectChallenge) {
          return { ok: false, status: 400, json: async () => ({ error: 'invalid_grant' }) }
        }
      }
      const isGoogle = u.includes('googleapis.com')
      const claims = isGoogle ? behavior.googleClaims() : behavior.microsoftClaims()
      const idToken = await signIdToken({ key: behavior.signingKey, kid: behavior.kid, alg: behavior.alg, claims })
      return { ok: true, status: 200, json: async () => ({ access_token: 'test-access', id_token: idToken, token_type: 'Bearer', expires_in: 3600 }) }
    }
    if (u.includes('googleapis.com/oauth2/v3/certs') || u.includes('login.microsoftonline.com/common/discovery/v2.0/keys')) {
      if (behavior.jwksError) return { ok: false, status: 500, json: async () => ({}) }
      return { ok: true, status: 200, json: async () => ({ keys: [publicJwk] }) }
    }
    throw new Error('unexpected fetch: ' + u)
  }
  return { behavior, sent, restore() { globalThis.fetch = origFetch } }
}

async function startOAuth(env, provider, ip, next) {
  const path = '/auth/' + provider + (next ? '?next=' + encodeURIComponent(next) : '')
  return call(env, path, 'GET', undefined, { ip, origin: null })
}

function stateFromRedirect(res) {
  const loc = res.res.headers.get('Location') || ''
  const u = new URL(loc)
  return { location: loc, state: u.searchParams.get('state'), challenge: u.searchParams.get('code_challenge') }
}

async function callback(env, provider, code, state, ip) {
  return call(env, '/auth/' + provider + '/callback?code=' + encodeURIComponent(code) + '&state=' + encodeURIComponent(state), 'GET', undefined, { ip, origin: null })
}

function handoffCookieFrom(res) {
  const setCookie = res.setCookie || ''
  const m = setCookie.match(/kluzar_oauth_handoff=([^;]+)/)
  return m ? m[1] : null
}

async function disableMfa(env, activated, ip) {
  advanceTotp(env)
  const res = await call(env, '/auth/mfa/disable', 'POST', { currentPassword: PW, mfaCode: await totpNow(activated.secret) }, { ip, cookie: activated.cookie, headers: { 'X-CSRF-Token': activated.csrf } })
  assert.equal(res.status, 200)
  return res
}

async function doHandoff(env, cookieValue, ip, origin = 'http://localhost:3000') {
  return call(env, '/auth/oauth/handoff', 'POST', {}, { ip, cookie: 'kluzar_oauth_handoff=' + cookieValue, origin })
}

const ERROR_LOCATION = 'https://accounts.kluzar.com/login/?oauth=error'

test('Google start redirects to Google with state, PKCE S256 and openid email profile scope', async () => {
  const { db, env } = fresh()
  const res = await startOAuth(env, 'google', '10.7.1.1')
  assert.equal(res.status, 302)
  const { location, state, challenge } = stateFromRedirect(res)
  assert.ok(location.startsWith('https://accounts.google.com/o/oauth2/v2/auth?'))
  const u = new URL(location)
  assert.equal(u.searchParams.get('client_id'), GOOGLE_CLIENT_ID)
  assert.equal(u.searchParams.get('response_type'), 'code')
  assert.equal(u.searchParams.get('redirect_uri'), 'https://account-api.kluzar.com/auth/google/callback')
  assert.equal(u.searchParams.get('scope'), 'openid email profile')
  assert.equal(u.searchParams.get('code_challenge_method'), 'S256')
  assert.ok(state && state.length >= 32)
  assert.ok(challenge && challenge.length >= 32)
  assert.equal(db.tables.oauth_states.length, 1)
  const row = db.tables.oauth_states[0]
  assert.equal(row.provider, 'google')
  assert.equal(row.state_hash, await sha256Hex(state))
  assert.ok(!('state' in row) && !row.code_challenge, 'plaintext state must never be stored')
  assert.ok(row.code_verifier && row.code_verifier.length >= 32)
  assert.equal(row.return_url, '')
})

test('Microsoft start redirects to the common v2.0 authorize endpoint', async () => {
  const { env } = fresh()
  const res = await startOAuth(env, 'microsoft', '10.7.1.2')
  assert.equal(res.status, 302)
  const { location } = stateFromRedirect(res)
  assert.ok(location.startsWith('https://login.microsoftonline.com/common/oauth2/v2.0/authorize?'))
  const u = new URL(location)
  assert.equal(u.searchParams.get('client_id'), MICROSOFT_CLIENT_ID)
  assert.equal(u.searchParams.get('redirect_uri'), 'https://account-api.kluzar.com/auth/microsoft/callback')
  assert.equal(u.searchParams.get('scope'), 'openid email profile')
  assert.equal(u.searchParams.get('code_challenge_method'), 'S256')
})

test('start keeps a valid ?next= return target and drops an invalid one', async () => {
  const { db, env } = fresh()
  const ok = await startOAuth(env, 'google', '10.7.1.3', 'https://seo.kluzar.com/')
  assert.equal(ok.status, 302)
  assert.equal(db.tables.oauth_states[0].return_url, 'https://seo.kluzar.com/')
  const evil = await startOAuth(env, 'google', '10.7.1.4', 'https://evil.com/steal')
  assert.equal(evil.status, 302)
  assert.equal(db.tables.oauth_states[1].return_url, '')
  const self = await startOAuth(env, 'microsoft', '10.7.1.5', 'https://accounts.kluzar.com/dashboard/')
  assert.equal(self.status, 302)
  assert.equal(db.tables.oauth_states[2].return_url, '')
})

test('start without configured secrets fails closed to the login error page', async () => {
  const { env } = fresh()
  delete env.GOOGLE_CLIENT_ID
  const res = await startOAuth(env, 'google', '10.7.1.6')
  assert.equal(res.status, 302)
  assert.equal(res.res.headers.get('Location'), ERROR_LOCATION)
})

test('start is rate limited per IP', async () => {
  const { env } = fresh()
  let last
  for (let i = 0; i < 21; i++) last = await startOAuth(env, 'google', '10.7.1.7')
  assert.equal(last.status, 429)
})

test('Google callback creates a new verified pending_mfa user and hands off to MFA setup', async () => {
  const { db, env } = fresh()
  const stub = await stubIdp()
  try {
    const start = await startOAuth(env, 'google', '10.7.2.1')
    const { state, challenge } = stateFromRedirect(start)
    stub.behavior.expectChallenge = challenge
    const cb = await callback(env, 'google', 'test-auth-code', state, '10.7.2.1')
    assert.equal(cb.status, 302)
    assert.equal(cb.res.headers.get('Location'), 'https://accounts.kluzar.com/mfa-setup/')
    const cookie = handoffCookieFrom(cb)
    assert.ok(cookie, 'handoff cookie must be set')
    assert.ok(cb.setCookie.includes('HttpOnly') && cb.setCookie.includes('Max-Age=300'))
    assert.equal(db.tables.users.length, 1)
    const user = db.tables.users[0]
    assert.equal(user.email, 'oauth-user@example.com')
    assert.equal(user.email_verified, 1)
    assert.equal(user.status, 'pending_mfa')
    assert.equal(user.mfa_enabled, 0)
    assert.ok(user.password_hash.startsWith('pbkdf2-sha256$'), 'OAuth-only account still gets an unusable random password hash')
    assert.equal(db.tables.oauth_identities.length, 1)
    assert.equal(db.tables.oauth_identities[0].provider, 'google')
    assert.equal(db.tables.oauth_identities[0].provider_user_id, 'google-sub-123')
    assert.equal(db.tables.oauth_states.length, 0, 'state must be consumed single-use')
    assert.equal(db.tables.sessions.length, 0, 'no session before MFA setup')
    const h = await doHandoff(env, cookie, '10.7.2.1')
    assert.equal(h.status, 200)
    assert.ok(h.data.setupToken)
    const setup = await call(env, '/auth/mfa/setup', 'POST', { setupToken: h.data.setupToken }, { ip: '10.7.2.1' })
    assert.equal(setup.status, 200)
    const secret = secretFromOtpauth(setup.data.otpauthUrl)
    const code = await totpNow(secret)
    const verify = await call(env, '/auth/mfa/verify', 'POST', { setupToken: h.data.setupToken, code }, { ip: '10.7.2.1' })
    assert.equal(verify.status, 200)
    assert.ok(verify.data.activated)
    assert.ok(verify.sessionCookie)
    const sess = await call(env, '/auth/session', 'GET', undefined, { ip: '10.7.2.1', cookie: verify.sessionCookie })
    assert.equal(sess.status, 200)
    assert.equal(sess.data.user.email, 'oauth-user@example.com')
    assert.equal(sess.data.user.emailVerified, true)
  } finally {
    stub.restore()
  }
})

test('Google callback logs in an existing active user without MFA and honours the return URL', async () => {
  const { db, env } = fresh()
  const activated = await registerAndActivate(env, 'oauth-user@example.com', PW)
  await disableMfa(env, activated, '10.7.2.2')
  assert.equal(db.tables.users.length, 1)
  const stub = await stubIdp()
  try {
    const start = await startOAuth(env, 'google', '10.7.2.2', 'https://seo.kluzar.com/')
    const { state, challenge } = stateFromRedirect(start)
    stub.behavior.expectChallenge = challenge
    const cb = await callback(env, 'google', 'test-auth-code', state, '10.7.2.2')
    assert.equal(cb.status, 302)
    assert.equal(cb.res.headers.get('Location'), 'https://seo.kluzar.com/')
    assert.ok(cb.sessionCookie, 'session cookie must be set on direct login')
    assert.equal(db.tables.users.length, 1, 'no duplicate user on link')
    assert.equal(db.tables.oauth_identities.length, 1)
    const sess = await call(env, '/auth/session', 'GET', undefined, { ip: '10.7.2.2', cookie: cb.sessionCookie })
    assert.equal(sess.status, 200)
    assert.equal(sess.data.user.id, activated.userId)
  } finally {
    stub.restore()
  }
})

test('Google callback sends an MFA-enabled user to the code page via handoff', async () => {
  const { db, env } = fresh()
  const activated = await registerAndActivate(env, 'oauth-user@example.com', PW)
  const stub = await stubIdp()
  try {
    const start = await startOAuth(env, 'google', '10.7.2.3')
    const { state, challenge } = stateFromRedirect(start)
    stub.behavior.expectChallenge = challenge
    const cb = await callback(env, 'google', 'test-auth-code', state, '10.7.2.3')
    assert.equal(cb.status, 302)
    assert.equal(cb.res.headers.get('Location'), 'https://accounts.kluzar.com/login/code/')
    const cookie = handoffCookieFrom(cb)
    assert.ok(cookie)
    const h = await doHandoff(env, cookie, '10.7.2.3')
    assert.equal(h.status, 200)
    assert.ok(h.data.challengeToken)
    advanceTotp(env)
    const code = await totpNow(activated.secret)
    const verify = await call(env, '/auth/mfa/verify', 'POST', { challengeToken: h.data.challengeToken, code }, { ip: '10.7.2.3' })
    assert.equal(verify.status, 200)
    assert.ok(verify.sessionCookie)
  } finally {
    stub.restore()
  }
})

test('second Google sign-in for the same account reuses the linked identity, no duplicate', async () => {
  const { db, env } = fresh()
  await registerAndActivate(env, 'oauth-user@example.com', PW)
  const stub = await stubIdp()
  try {
    for (let i = 0; i < 2; i++) {
      const start = await startOAuth(env, 'google', '10.7.2.4')
      const { state, challenge } = stateFromRedirect(start)
      stub.behavior.expectChallenge = challenge
      const cb = await callback(env, 'google', 'test-auth-code-' + i, state, '10.7.2.4')
      assert.equal(cb.status, 302)
      assert.equal(cb.res.headers.get('Location'), 'https://accounts.kluzar.com/login/code/')
      assert.ok(handoffCookieFrom(cb), 'MFA user gets a handoff, not a session')
    }
    assert.equal(db.tables.users.length, 1)
    assert.equal(db.tables.oauth_identities.length, 1)
  } finally {
    stub.restore()
  }
})

test('Microsoft callback creates a user from preferred_username and honours the dashboard fallback', async () => {
  const { db, env } = fresh()
  const stub = await stubIdp()
  try {
    const start = await startOAuth(env, 'microsoft', '10.7.2.5')
    const { state, challenge } = stateFromRedirect(start)
    stub.behavior.expectChallenge = challenge
    const cb = await callback(env, 'microsoft', 'test-auth-code', state, '10.7.2.5')
    assert.equal(cb.status, 302)
    assert.equal(cb.res.headers.get('Location'), 'https://accounts.kluzar.com/mfa-setup/')
    assert.equal(db.tables.users[0].email, 'ms-user@example.com')
    assert.equal(db.tables.oauth_identities[0].provider, 'microsoft')
    assert.equal(db.tables.oauth_identities[0].provider_user_id, 'ms-sub-456')
  } finally {
    stub.restore()
  }
})

test('Microsoft callback accepts the email claim when present', async () => {
  const { db, env } = fresh()
  const stub = await stubIdp()
  stub.behavior.microsoftClaims = () => microsoftClaims({ email: 'ms-claim@example.com', preferred_username: 'ms-user@example.com' })
  try {
    const start = await startOAuth(env, 'microsoft', '10.7.2.6')
    const { state, challenge } = stateFromRedirect(start)
    stub.behavior.expectChallenge = challenge
    const cb = await callback(env, 'microsoft', 'test-auth-code', state, '10.7.2.6')
    assert.equal(cb.status, 302)
    assert.equal(db.tables.users[0].email, 'ms-claim@example.com')
  } finally {
    stub.restore()
  }
})

test('callback with a wrong state fails to the generic error page and creates nothing', async () => {
  const { db, env } = fresh()
  const stub = await stubIdp()
  try {
    const start = await startOAuth(env, 'google', '10.7.3.1')
    assert.equal(start.status, 302)
    const cb = await callback(env, 'google', 'test-auth-code', 'wrong-state-token-1234567890', '10.7.3.1')
    assert.equal(cb.status, 302)
    assert.equal(cb.res.headers.get('Location'), ERROR_LOCATION)
    assert.equal(db.tables.users.length, 0)
    assert.equal(cb.sessionCookie, null)
  } finally {
    stub.restore()
  }
})

test('callback state is single-use: a second callback with the same state fails', async () => {
  const { db, env } = fresh()
  const stub = await stubIdp()
  try {
    const start = await startOAuth(env, 'google', '10.7.3.2')
    const { state, challenge } = stateFromRedirect(start)
    stub.behavior.expectChallenge = challenge
    const first = await callback(env, 'google', 'test-auth-code', state, '10.7.3.2')
    assert.equal(first.status, 302)
    assert.equal(db.tables.users.length, 1)
    const second = await callback(env, 'google', 'test-auth-code', state, '10.7.3.2')
    assert.equal(second.status, 302)
    assert.equal(second.res.headers.get('Location'), ERROR_LOCATION)
    assert.equal(db.tables.users.length, 1)
  } finally {
    stub.restore()
  }
})

test('callback with an expired state fails', async () => {
  const { db, env } = fresh()
  const stub = await stubIdp()
  try {
    const start = await startOAuth(env, 'google', '10.7.3.3')
    const { state } = stateFromRedirect(start)
    db.tables.oauth_states[0].expires_at = new Date(Date.now() - 1000).toISOString()
    const cb = await callback(env, 'google', 'test-auth-code', state, '10.7.3.3')
    assert.equal(cb.res.headers.get('Location'), ERROR_LOCATION)
    assert.equal(db.tables.users.length, 0)
  } finally {
    stub.restore()
  }
})

test('callback with a state issued for the other provider fails', async () => {
  const { db, env } = fresh()
  const stub = await stubIdp()
  try {
    const start = await startOAuth(env, 'google', '10.7.3.4')
    const { state } = stateFromRedirect(start)
    const cb = await callback(env, 'microsoft', 'test-auth-code', state, '10.7.3.4')
    assert.equal(cb.res.headers.get('Location'), ERROR_LOCATION)
    assert.equal(db.tables.users.length, 0)
  } finally {
    stub.restore()
  }
})

test('PKCE verifier mismatch is rejected by the IdP and fails the callback', async () => {
  const { db, env } = fresh()
  const stub = await stubIdp()
  try {
    const start = await startOAuth(env, 'google', '10.7.3.5')
    const { state, challenge } = stateFromRedirect(start)
    stub.behavior.expectChallenge = challenge
    db.tables.oauth_states[0].code_verifier = 'tampered-verifier-that-does-not-match'
    const cb = await callback(env, 'google', 'test-auth-code', state, '10.7.3.5')
    assert.equal(cb.res.headers.get('Location'), ERROR_LOCATION)
    assert.equal(db.tables.users.length, 0)
  } finally {
    stub.restore()
  }
})

test('callback fails when the IdP token exchange fails', async () => {
  const { db, env } = fresh()
  const stub = await stubIdp()
  stub.behavior.tokenError = true
  try {
    const start = await startOAuth(env, 'google', '10.7.3.6')
    const { state } = stateFromRedirect(start)
    const cb = await callback(env, 'google', 'test-auth-code', state, '10.7.3.6')
    assert.equal(cb.res.headers.get('Location'), ERROR_LOCATION)
    assert.equal(db.tables.users.length, 0)
  } finally {
    stub.restore()
  }
})

test('callback rejects an ID token signed with the wrong key', async () => {
  const { db, env } = fresh()
  const stub = await stubIdp()
  const { otherKey } = await testKeys()
  stub.behavior.signingKey = otherKey
  try {
    const start = await startOAuth(env, 'google', '10.7.3.7')
    const { state, challenge } = stateFromRedirect(start)
    stub.behavior.expectChallenge = challenge
    const cb = await callback(env, 'google', 'test-auth-code', state, '10.7.3.7')
    assert.equal(cb.res.headers.get('Location'), ERROR_LOCATION)
    assert.equal(db.tables.users.length, 0)
  } finally {
    stub.restore()
  }
})

test('callback rejects an ID token with the wrong audience', async () => {
  const { db, env } = fresh()
  const stub = await stubIdp()
  stub.behavior.googleClaims = () => googleClaims({ aud: 'some-other-client-id' })
  try {
    const start = await startOAuth(env, 'google', '10.7.3.8')
    const { state, challenge } = stateFromRedirect(start)
    stub.behavior.expectChallenge = challenge
    const cb = await callback(env, 'google', 'test-auth-code', state, '10.7.3.8')
    assert.equal(cb.res.headers.get('Location'), ERROR_LOCATION)
    assert.equal(db.tables.users.length, 0)
  } finally {
    stub.restore()
  }
})

test('callback rejects an ID token with the wrong issuer', async () => {
  const { db, env } = fresh()
  const stub = await stubIdp()
  stub.behavior.googleClaims = () => googleClaims({ iss: 'https://evil-issuer.example.com' })
  try {
    const start = await startOAuth(env, 'google', '10.7.3.9')
    const { state, challenge } = stateFromRedirect(start)
    stub.behavior.expectChallenge = challenge
    const cb = await callback(env, 'google', 'test-auth-code', state, '10.7.3.9')
    assert.equal(cb.res.headers.get('Location'), ERROR_LOCATION)
    assert.equal(db.tables.users.length, 0)
  } finally {
    stub.restore()
  }
})

test('callback rejects an expired ID token', async () => {
  const { db, env } = fresh()
  const stub = await stubIdp()
  const now = Math.floor(Date.now() / 1000)
  stub.behavior.googleClaims = () => googleClaims({ iat: now - 7200, exp: now - 3600 })
  try {
    const start = await startOAuth(env, 'google', '10.7.3.10')
    const { state, challenge } = stateFromRedirect(start)
    stub.behavior.expectChallenge = challenge
    const cb = await callback(env, 'google', 'test-auth-code', state, '10.7.3.10')
    assert.equal(cb.res.headers.get('Location'), ERROR_LOCATION)
    assert.equal(db.tables.users.length, 0)
  } finally {
    stub.restore()
  }
})

test('callback rejects an unsigned alg=none ID token', async () => {
  const { db, env } = fresh()
  const stub = await stubIdp()
  stub.behavior.alg = 'none'
  try {
    const start = await startOAuth(env, 'google', '10.7.3.11')
    const { state, challenge } = stateFromRedirect(start)
    stub.behavior.expectChallenge = challenge
    const cb = await callback(env, 'google', 'test-auth-code', state, '10.7.3.11')
    assert.equal(cb.res.headers.get('Location'), ERROR_LOCATION)
    assert.equal(db.tables.users.length, 0)
  } finally {
    stub.restore()
  }
})

test('callback rejects a Google token whose email is not verified', async () => {
  const { db, env } = fresh()
  const stub = await stubIdp()
  stub.behavior.googleClaims = () => googleClaims({ email_verified: false })
  try {
    const start = await startOAuth(env, 'google', '10.7.3.12')
    const { state, challenge } = stateFromRedirect(start)
    stub.behavior.expectChallenge = challenge
    const cb = await callback(env, 'google', 'test-auth-code', state, '10.7.3.12')
    assert.equal(cb.res.headers.get('Location'), ERROR_LOCATION)
    assert.equal(db.tables.users.length, 0)
  } finally {
    stub.restore()
  }
})

test('callback rejects a Microsoft token with no usable email claim', async () => {
  const { db, env } = fresh()
  const stub = await stubIdp()
  stub.behavior.microsoftClaims = () => microsoftClaims({ preferred_username: 'not-an-email' })
  try {
    const start = await startOAuth(env, 'microsoft', '10.7.3.13')
    const { state, challenge } = stateFromRedirect(start)
    stub.behavior.expectChallenge = challenge
    const cb = await callback(env, 'microsoft', 'test-auth-code', state, '10.7.3.13')
    assert.equal(cb.res.headers.get('Location'), ERROR_LOCATION)
    assert.equal(db.tables.users.length, 0)
  } finally {
    stub.restore()
  }
})

test('callback without a code fails to the generic error page', async () => {
  const { db, env } = fresh()
  const stub = await stubIdp()
  try {
    const start = await startOAuth(env, 'google', '10.7.3.14')
    const { state } = stateFromRedirect(start)
    const cb = await call(env, '/auth/google/callback?state=' + encodeURIComponent(state), 'GET', undefined, { ip: '10.7.3.14', origin: null })
    assert.equal(cb.res.headers.get('Location'), ERROR_LOCATION)
    assert.equal(db.tables.users.length, 0)
  } finally {
    stub.restore()
  }
})

test('callback for a suspended account fails generically with no session', async () => {
  const { db, env } = fresh()
  const activated = await registerAndActivate(env, 'oauth-user@example.com', PW)
  db.tables.users[0].status = 'suspended'
  db.tables.sessions = []
  const stub = await stubIdp()
  try {
    const start = await startOAuth(env, 'google', '10.7.3.15')
    const { state, challenge } = stateFromRedirect(start)
    stub.behavior.expectChallenge = challenge
    const cb = await callback(env, 'google', 'test-auth-code', state, '10.7.3.15')
    assert.equal(cb.res.headers.get('Location'), ERROR_LOCATION)
    assert.equal(cb.sessionCookie, null)
    assert.equal(db.tables.sessions.length, 0)
  } finally {
    stub.restore()
  }
})

test('callback is rate limited per IP', async () => {
  const { env } = fresh()
  const stub = await stubIdp()
  try {
    let last
    for (let i = 0; i < 21; i++) last = await callback(env, 'google', 'test-auth-code', 'wrong-state-token-1234567890', '10.7.3.16')
    assert.equal(last.status, 429)
  } finally {
    stub.restore()
  }
})

test('handoff without an Origin header is rejected', async () => {
  const { env } = fresh()
  const res = await call(env, '/auth/oauth/handoff', 'POST', {}, { ip: '10.7.4.1', origin: null })
  assert.equal(res.status, 403)
})

test('handoff with an unknown cookie fails generically', async () => {
  const { env } = fresh()
  const res = await doHandoff(env, 'unknown-handoff-token-1234567890', '10.7.4.2')
  assert.equal(res.status, 400)
  assert.equal(res.data.code, 'INVALID_HANDOFF')
})

test('handoff cookie is single-use', async () => {
  const { env } = fresh()
  const stub = await stubIdp()
  try {
    const start = await startOAuth(env, 'google', '10.7.4.3')
    const { state, challenge } = stateFromRedirect(start)
    stub.behavior.expectChallenge = challenge
    const cb = await callback(env, 'google', 'test-auth-code', state, '10.7.4.3')
    const cookie = handoffCookieFrom(cb)
    const first = await doHandoff(env, cookie, '10.7.4.3')
    assert.equal(first.status, 200)
    const second = await doHandoff(env, cookie, '10.7.4.3')
    assert.equal(second.status, 400)
  } finally {
    stub.restore()
  }
})

test('handoff for a setup kind fails once the account is already active', async () => {
  const { db, env } = fresh()
  const activated = await registerAndActivate(env, 'setup-done@example.com', PW)
  db.tables.oauth_handoffs.push({
    id: 'handoff-1',
    token_hash: await sha256Hex('stale-setup-handoff-token-1234567890'),
    user_id: activated.userId,
    kind: 'setup',
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
  })
  const res = await doHandoff(env, 'stale-setup-handoff-token-1234567890', '10.7.4.4')
  assert.equal(res.status, 400)
})

test('session contract is unchanged after an OAuth login: exact 200 and 401 shapes, same cookie', async () => {
  const { db, env } = fresh()
  const activated = await registerAndActivate(env, 'oauth-user@example.com', PW)
  await disableMfa(env, activated, '10.7.5.1')
  const stub = await stubIdp()
  try {
    const start = await startOAuth(env, 'google', '10.7.5.1')
    const { state, challenge } = stateFromRedirect(start)
    stub.behavior.expectChallenge = challenge
    const cb = await callback(env, 'google', 'test-auth-code', state, '10.7.5.1')
    assert.equal(cb.status, 302)
    assert.ok(cb.sessionCookie)
    assert.ok(cb.setCookie.includes('kluzar_session='))
    assert.ok(cb.setCookie.includes('HttpOnly'))
    assert.ok(cb.setCookie.includes('Max-Age=172800'))
    assert.ok(cb.setCookie.includes('Path=/'))
    const sess = await call(env, '/auth/session', 'GET', undefined, { ip: '10.7.5.1', cookie: cb.sessionCookie })
    assert.equal(sess.status, 200)
    assert.deepEqual(Object.keys(sess.data).sort(), ['authenticated', 'csrfToken', 'entitlement', 'ok', 'user'])
    assert.equal(sess.data.ok, true)
    assert.equal(sess.data.authenticated, true)
    assert.deepEqual(Object.keys(sess.data.user).sort(), ['email', 'emailVerified', 'firstName', 'id', 'lastName', 'mfaEnabled', 'phone', 'status'])
    assert.deepEqual(sess.data.entitlement, { plan: 'free', status: 'active', premium: false })
    assert.equal(typeof sess.data.csrfToken, 'string')
    assert.ok(sess.data.csrfToken.length >= 10)
    const anon = await call(env, '/auth/session', 'GET', undefined, { ip: '10.7.5.1' })
    assert.equal(anon.status, 401)
    assert.deepEqual(anon.data, { ok: false, authenticated: false })
    assert.equal(db.tables.sessions[0].scope, 'full', 'OAuth login must create a normal full session, never an admin session')
  } finally {
    stub.restore()
  }
})

test('OAuth never touches admin: no admin allowlist reference and no admin logic in the new code', async () => {
  const handlers = readFileSync(path.join(root, '../worker/src/handlers.js'), 'utf8')
  const oauth = readFileSync(path.join(root, '../worker/src/oauth.js'), 'utf8')
  assert.ok(!handlers.includes('admin_allowlist'), 'handlers must not reference admin_allowlist in OAuth paths')
  assert.ok(!oauth.includes('admin_allowlist') && !oauth.includes('admin'), 'oauth module must contain no admin logic')
  const oauthSection = handlers.slice(handlers.indexOf('OAuth: start'), handlers.indexOf('MFA setup (pending via setupToken'))
  assert.ok(!oauthSection.includes('admin'), 'OAuth endpoint code must contain no admin references')
})

test('login and signup pages offer Google and Microsoft sign-in with no third-party URLs', async () => {
  for (const page of ['login/index.html', 'signup/index.html']) {
    const html = readFileSync(path.join(root, '../' + page), 'utf8')
    assert.ok(html.includes('id="oauth-google"'), page + ' must have a Google button')
    assert.ok(html.includes('id="oauth-microsoft"'), page + ' must have a Microsoft button')
    assert.ok(html.includes('Continue with Google'), page + ' must label the Google button')
    assert.ok(html.includes('Continue with Microsoft'), page + ' must label the Microsoft button')
    assert.ok(!html.includes('accounts.google.com') && !html.includes('login.microsoftonline.com'), page + ' must not link to IdP endpoints directly; the Worker calls them server-side')
    assert.ok(!html.includes('.html"'), page + ' must not link to a .html file')
  }
  const shared = readFileSync(path.join(root, '../shared.js'), 'utf8')
  assert.ok(shared.includes("API + '/auth/google'"), 'shared.js must build the Google start URL from the API base')
  assert.ok(shared.includes("API + '/auth/microsoft'"), 'shared.js must build the Microsoft start URL from the API base')
  assert.ok(shared.includes('/auth/oauth/handoff'), 'shared.js must retrieve the post-callback token via the handoff endpoint')
  assert.ok(!shared.includes('accounts.google.com') && !shared.includes('login.microsoftonline.com'), 'shared.js must not call IdP endpoints')
})
