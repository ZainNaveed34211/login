import test from 'node:test'
import assert from 'node:assert/strict'
import { MockD1, testEnv } from './mock-d1.js'
import { call, registerAndActivate } from './helpers.js'
import { resetRateLimits } from '../worker/src/security.js'

const OUTREACH_ORIGIN = 'https://outreach.kluzar.com'

function b64urlDecode(str) {
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4))
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64')
}

async function freshKeypair(env) {
  const pair = await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  const jwk = await globalThis.crypto.subtle.exportKey('jwk', pair.privateKey)
  env.OUTREACH_ASSERTION_PRIVATE_KEY = JSON.stringify(jwk)
  return pair.publicKey
}

async function loggedIn(env, email = 'outreach@kluzar.test') {
  const auth = await registerAndActivate(env, email, 'Long-enough-Password-123!')
  return auth
}

function outreachCall(env, auth, opts = {}) {
  return call(env, '/auth/outreach-assertion', 'POST', undefined, {
    ip: opts.ip || '10.7.0.1',
    origin: opts.origin === undefined ? OUTREACH_ORIGIN : opts.origin,
    cookie: opts.cookie === undefined ? auth.cookie : opts.cookie,
    headers: opts.headers === undefined ? { 'X-CSRF-Token': auth.csrf } : opts.headers,
  })
}

test('outreach assertion: valid session + CSRF + origin returns a verifiable signed assertion', async () => {
  const db = new MockD1()
  const env = testEnv(db)
  env.ALLOWED_ORIGINS = 'http://localhost:3000,' + OUTREACH_ORIGIN
  const publicKey = await freshKeypair(env)
  const auth = await loggedIn(env)
  resetRateLimits()
  const out = await outreachCall(env, auth)
  assert.equal(out.status, 200, 'expected 200, got: ' + JSON.stringify(out.data))
  assert.equal(out.data.ok, true)
  assert.equal(out.data.expiresIn, 300)
  assert.equal(typeof out.data.assertion, 'string')
  const parts = out.data.assertion.split('.')
  assert.equal(parts.length, 3, 'assertion must be a 3-part JWT')
  const header = JSON.parse(Buffer.from(b64urlDecode(parts[0])).toString('utf8'))
  const payload = JSON.parse(Buffer.from(b64urlDecode(parts[1])).toString('utf8'))
  assert.equal(header.alg, 'EdDSA')
  assert.equal(header.typ, 'JWT')
  assert.equal(header.kid, 'outreach-assertion-v1')
  assert.equal(payload.aud, 'kluzar-outreach-api')
  assert.equal(payload.sub, auth.user.id)
  assert.equal(typeof payload.sid, 'string')
  assert.ok(payload.sid.length > 0)
  assert.equal(payload.exp - payload.iat, 300)
  assert.ok(Math.abs(payload.iat - Math.floor(Date.now() / 1000)) <= 5)
  assert.equal(typeof payload.jti, 'string')
  assert.ok(payload.jti.length >= 16, 'jti must carry 16 random bytes')
  const signingInput = new TextEncoder().encode(parts[0] + '.' + parts[1])
  const ok = await globalThis.crypto.subtle.verify({ name: 'Ed25519' }, publicKey, b64urlDecode(parts[2]), signingInput)
  assert.equal(ok, true, 'assertion signature must verify with the matching public key')
  const auditRows = db.tables.audit_events.filter((r) => r.event_type === 'outreach_assertion_issued')
  assert.equal(auditRows.length, 1, 'issuance must be audited once')
})

test('outreach assertion: no session returns 401', async () => {
  const db = new MockD1()
  const env = testEnv(db)
  env.ALLOWED_ORIGINS = 'http://localhost:3000,' + OUTREACH_ORIGIN
  await freshKeypair(env)
  const out = await outreachCall(env, { cookie: null, csrf: 'x'.repeat(32) }, { cookie: null })
  assert.equal(out.status, 401)
  assert.equal(out.data.ok, false)
  assert.equal(out.data.authenticated, false)
})

test('outreach assertion: admin-scope session returns 403', async () => {
  const db = new MockD1()
  const env = testEnv(db)
  env.ALLOWED_ORIGINS = 'http://localhost:3000,' + OUTREACH_ORIGIN
  await freshKeypair(env)
  const auth = await loggedIn(env)
  db.tables.sessions[0].scope = 'admin'
  resetRateLimits()
  const out = await outreachCall(env, auth)
  assert.equal(out.status, 403)
  assert.equal(out.data.code, 'FORBIDDEN')
})

test('outreach assertion: bad or missing CSRF token returns 403', async () => {
  const db = new MockD1()
  const env = testEnv(db)
  env.ALLOWED_ORIGINS = 'http://localhost:3000,' + OUTREACH_ORIGIN
  await freshKeypair(env)
  const auth = await loggedIn(env)
  resetRateLimits()
  const bad = await outreachCall(env, auth, { headers: { 'X-CSRF-Token': 'wrong-token-value' } })
  assert.equal(bad.status, 403)
  assert.equal(bad.data.code, 'FORBIDDEN')
  const missing = await outreachCall(env, auth, { headers: {} })
  assert.equal(missing.status, 403)
  assert.equal(missing.data.code, 'FORBIDDEN')
})

test('outreach assertion: wrong Origin returns 403', async () => {
  const db = new MockD1()
  const env = testEnv(db)
  env.ALLOWED_ORIGINS = 'http://localhost:3000,' + OUTREACH_ORIGIN + ',https://dash.kluzar.com'
  await freshKeypair(env)
  const auth = await loggedIn(env)
  resetRateLimits()
  const out = await outreachCall(env, auth, { origin: 'https://dash.kluzar.com' })
  assert.equal(out.status, 403)
  assert.equal(out.data.code, 'FORBIDDEN')
  const absent = await outreachCall(env, auth, { origin: null })
  assert.equal(absent.status, 403)
  assert.equal(absent.data.code, 'FORBIDDEN')
})

test('outreach assertion: missing private key returns 500 ASSERTION_UNAVAILABLE', async () => {
  const db = new MockD1()
  const env = testEnv(db)
  env.ALLOWED_ORIGINS = 'http://localhost:3000,' + OUTREACH_ORIGIN
  const auth = await loggedIn(env)
  resetRateLimits()
  const out = await outreachCall(env, auth)
  assert.equal(out.status, 500)
  assert.equal(out.data.code, 'ASSERTION_UNAVAILABLE')
  assert.equal(out.data.error, 'Assertion service is not configured.')
})

test('outreach assertion: non-POST method returns 405', async () => {
  const db = new MockD1()
  const env = testEnv(db)
  env.ALLOWED_ORIGINS = 'http://localhost:3000,' + OUTREACH_ORIGIN
  await freshKeypair(env)
  const auth = await loggedIn(env)
  const out = await call(env, '/auth/outreach-assertion', 'GET', undefined, {
    ip: '10.7.0.1',
    origin: OUTREACH_ORIGIN,
    cookie: auth.cookie,
    headers: { 'X-CSRF-Token': auth.csrf },
  })
  assert.equal(out.status, 405)
  assert.equal(out.data.code, 'METHOD_NOT_ALLOWED')
})
