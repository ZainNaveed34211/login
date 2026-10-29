// Shared test helpers: request builder, TOTP, register+activate, login.
import { handleRequest } from '../worker/src/index.js'
import { base32Decode, totpCode } from '../worker/src/crypto.js'
import { resetRateLimits } from '../worker/src/security.js'

export async function call(env, path, method = 'GET', body = undefined, opts = {}) {
  const headers = {
    Origin: opts.origin || 'http://localhost:3000',
    'CF-Connecting-IP': opts.ip || '127.0.0.1',
    'User-Agent': opts.userAgent || 'test-agent',
    ...(opts.headers || {}),
  }
  if (opts.cookie) headers.Cookie = opts.cookie
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  const req = new Request('https://account-api.kluzar.com' + path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  const res = await handleRequest(req, env)
  let data = {}
  try { data = await res.json() } catch { data = {} }
  const setCookie = res.headers.get('Set-Cookie') || ''
  const sessionCookie = setCookie ? setCookie.split(';')[0] : null
  return { status: res.status, data, res, setCookie, sessionCookie }
}
export function totpNow(secretBase32, stepOffset = 0) {
  const step = Math.floor(Date.now() / 30000) + stepOffset
  return totpCode(base32Decode(secretBase32), step)
}
export function secretFromOtpauth(url) {
  return new URL(url).searchParams.get('secret')
}
// Simulate a new TOTP step (waiting for the next 30-second window) by
// clearing last_used_step in the mock DB. Production replay protection is
// unchanged and is tested separately with manual calls that do NOT advance.
export function advanceTotp(env) {
  if (env.DB && env.DB.tables && env.DB.tables.mfa_secrets) {
    for (const row of env.DB.tables.mfa_secrets) row.last_used_step = null
  }
}
export async function registerAndActivate(env, email, password) {
  resetRateLimits()
  const reg = await call(env, '/auth/register', 'POST', { email, password }, { ip: '10.0.0.1' })
  if (reg.status !== 201) throw new Error('register failed: ' + JSON.stringify(reg.data))
  const setup = await call(env, '/auth/mfa/setup', 'POST', { setupToken: reg.data.setupToken }, { ip: '10.0.0.1' })
  if (setup.status !== 200) throw new Error('setup failed: ' + JSON.stringify(setup.data))
  const secret = secretFromOtpauth(setup.data.otpauthUrl)
  const code = await totpNow(secret)
  const verify = await call(env, '/auth/mfa/verify', 'POST', { setupToken: reg.data.setupToken, code }, { ip: '10.0.0.1' })
  if (verify.status !== 200) throw new Error('verify failed: ' + JSON.stringify(verify.data))
  return { userId: reg.data.userId, secret, recoveryCodes: verify.data.recoveryCodes, cookie: verify.sessionCookie, csrf: verify.data.csrfToken, user: verify.data.user }
}
export async function loginWithMfa(env, email, password, secret, ip = '10.0.0.2') {
  advanceTotp(env)
  resetRateLimits()
  const login = await call(env, '/auth/login', 'POST', { email, password }, { ip })
  if (!login.data.mfaRequired) throw new Error('expected mfaRequired, got: ' + JSON.stringify(login.data))
  const code = await totpNow(secret)
  const verify = await call(env, '/auth/mfa/verify', 'POST', { challengeToken: login.data.challengeToken, code }, { ip })
  if (verify.status !== 200) throw new Error('mfa verify failed: ' + JSON.stringify(verify.data))
  return { cookie: verify.sessionCookie, csrf: verify.data.csrfToken, user: verify.data.user }
}
