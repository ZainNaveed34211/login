// Security helpers: CORS, CSRF, rate limits, validation, responses.
// Rate limiting here is per-isolate in-memory (Cloudflare Workers isolates
// do not share memory). That is an honest limitation: a global limit across
// all isolates needs KV or Durable Objects, or a Cloudflare dashboard rate
// limit rule in front of the Worker. The per-isolate limit still stops a
// single client hammering one isolate, and D1 failure counters persist.
// Do NOT claim this is a global rate limit.
import { sha256Hex } from './crypto.js'

export const ALLOWED_ORIGIN_DEFAULT = 'https://accounts.kluzar.com'
export function allowedOrigins(env) {
  const fromEnv = (env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
  if (fromEnv.length > 0) return fromEnv
  const list = [ALLOWED_ORIGIN_DEFAULT]
  if (env.ALLOW_LOCALHOST === 'true') {
    list.push('http://localhost:8787', 'http://127.0.0.1:8787', 'http://localhost:3000')
  }
  return list
}
export function corsHeaders(env, request) {
  const origin = request.headers.get('Origin') || ''
  const allowed = allowedOrigins(env)
  const headers = {
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-CSRF-Token, X-Requested-With',
    'Access-Control-Allow-Credentials': 'true',
    Vary: 'Origin',
  }
  if (origin && allowed.includes(origin)) headers['Access-Control-Allow-Origin'] = origin
  return headers
}
export function securityHeaders() {
  return {
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Cache-Control': 'no-store',
  }
}
export function jsonResponse(env, request, status, body, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...securityHeaders(),
      ...corsHeaders(env, request),
      ...extraHeaders,
    },
  })
}
export function errorResponse(env, request, status, message, code = 'ERROR') {
  // Safe public errors only: no stack traces, no internals, no secrets.
  return jsonResponse(env, request, status, { ok: false, error: message, code })
}
export function clientIp(request) {
  return (
    request.headers.get('CF-Connecting-IP') ||
    (request.headers.get('X-Forwarded-For') || '').split(',')[0].trim() ||
    'unknown'
  )
}
export async function ipHash(ip) {
  return (await sha256Hex(ip)).slice(0, 32)
}
// CSRF: authenticated state-changing requests must carry the CSRF token
// issued with the session (via GET /auth/session) AND an Origin in the
// allowlist when Origin is present (browsers always send Origin on POST).
// Unauthenticated endpoints rely on Origin checking + rate limits.
export function csrfOk(env, request, session) {
  if (!session) return false
  const token = request.headers.get('X-CSRF-Token') || ''
  if (!token || token !== session.csrf_token) return false
  const origin = request.headers.get('Origin') || ''
  if (origin && !allowedOrigins(env).includes(origin)) return false
  return true
}
export function originOk(env, request) {
  const origin = request.headers.get('Origin') || ''
  if (!origin) return true // non-browser clients (curl, tests); browser POSTs always send Origin
  return allowedOrigins(env).includes(origin)
}

// Simple per-isolate rate limiter: key -> array of timestamps (ms).
const buckets = new Map()
export function rateLimit(key, limit, windowMs, nowMs = Date.now()) {
  const arr = (buckets.get(key) || []).filter((t) => nowMs - t < windowMs)
  if (arr.length >= limit) {
    buckets.set(key, arr)
    return false
  }
  arr.push(nowMs)
  buckets.set(key, arr)
  return true
}
export function resetRateLimits() {
  buckets.clear()
}
export const RATE_LIMITS = {
  register: { limit: 5, windowMs: 15 * 60 * 1000 },
  login: { limit: 10, windowMs: 15 * 60 * 1000 },
  mfaVerify: { limit: 10, windowMs: 10 * 60 * 1000 },
  forgot: { limit: 5, windowMs: 15 * 60 * 1000 },
  reset: { limit: 5, windowMs: 15 * 60 * 1000 },
  regenerate: { limit: 5, windowMs: 15 * 60 * 1000 },
  passwordChange: { limit: 10, windowMs: 15 * 60 * 1000 },
  sensitive: { limit: 20, windowMs: 15 * 60 * 1000 },
}
export function checkRate(env, request, name, extra = '') {
  const cfg = RATE_LIMITS[name] || RATE_LIMITS.sensitive
  const key = `${name}:${clientIp(request)}:${extra}`
  return rateLimit(key, cfg.limit, cfg.windowMs)
}

export async function readJson(request, maxBytes = 16384) {
  const text = await request.text()
  if (text.length > maxBytes) throw new Error('BODY_TOO_LARGE')
  if (!text) return {}
  try {
    const parsed = JSON.parse(text)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('BAD_JSON')
    return parsed
  } catch {
    throw new Error('BAD_JSON')
  }
}
export function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email.trim()) && email.length <= 254
}
export function isValidPassword(password) {
  // Length alone is not enough: a simple password like 12 repeated
  // characters must be rejected. Require mixed characters — at least one
  // lowercase, one uppercase, one digit, and one symbol (any character
  // that is not a letter or digit). The frontend uses the identical rule
  // (shared.js isPasswordOk) so the user is told before submitting, and
  // the server re-checks it — client-side checks alone are never trusted.
  return typeof password === 'string' && password.length >= 12 && password.length <= 128 &&
    /[a-z]/.test(password) && /[A-Z]/.test(password) && /[0-9]/.test(password) && /[^A-Za-z0-9]/.test(password)
}
export function isValidName(name) {
  // Length only is not enough: a name must never contain markup or
  // control characters, even though the frontend renders it with
  // textContent. Reject <, >, & and control characters outright.
  return name === undefined || name === null || name === '' ||
    (typeof name === 'string' && name.length <= 100 && !/[<>&\u0000-\u001F\u007F]/.test(name))
}
export function isValidPhone(phone) {
  // Phone is optional. If present it may contain only digits and the
  // usual phone punctuation, and must contain at least one digit.
  // This rejects markup, letters and any other injected characters.
  return phone === undefined || phone === null || phone === '' ||
    (typeof phone === 'string' && phone.length <= 50 && /[0-9]/.test(phone) && /^[0-9+\s().-]+$/.test(phone))
}
export function publicUser(user) {
  if (!user) return null
  return {
    id: user.id,
    email: user.email,
    emailVerified: user.email_verified === 1,
    status: user.status,
    firstName: user.first_name || '',
    lastName: user.last_name || '',
    phone: user.phone || '',
    mfaEnabled: user.mfa_enabled === 1,
  }
}
