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
  // CF-Connecting-IP is set by Cloudflare and is trusted first; the
  // X-Forwarded-For fallback is only for local tests without Cloudflare.
  // Either way the value is untrusted input: take only the first address
  // and cap its length before it is hashed or stored anywhere.
  const ip = (
    request.headers.get('CF-Connecting-IP') ||
    (request.headers.get('X-Forwarded-For') || '').split(',')[0].trim() ||
    'unknown'
  )
  return String(ip).slice(0, 100)
}
export async function ipHash(ip) {
  return (await sha256Hex(ip)).slice(0, 32)
}
// CSRF + Origin, fail-closed. The real frontend is a browser fetch from
// https://accounts.kluzar.com to account-api.kluzar.com with credentials,
// and browsers ALWAYS send an Origin header on such POSTs. A missing or
// disallowed Origin on a state-changing request is therefore rejected,
// not treated as "probably a non-browser client". GET endpoints do not
// use these checks (they change no state and are session-gated); CORS
// headers still restrict which origins may read their responses.
// CSRF tokens are server-issued per session (via GET /auth/session) and
// are never accepted from a query string, cookie or body — header only.
export function csrfOk(env, request, session) {
  if (!session) return false
  const token = request.headers.get('X-CSRF-Token') || ''
  if (typeof token !== 'string' || token.length < 10 || token.length > 256) return false
  if (token !== session.csrf_token) return false
  const origin = request.headers.get('Origin') || ''
  if (!origin || !allowedOrigins(env).includes(origin)) return false
  return true
}
export function originOk(env, request) {
  const origin = request.headers.get('Origin') || ''
  if (!origin) return false
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
  manageAssertion: { limit: 20, windowMs: 10 * 60 * 1000 },
  businessAssertion: { limit: 20, windowMs: 10 * 60 * 1000 },
  dashAssertion: { limit: 20, windowMs: 10 * 60 * 1000 },
  mfaVerify: { limit: 10, windowMs: 10 * 60 * 1000 },
  forgot: { limit: 5, windowMs: 15 * 60 * 1000 },
  reset: { limit: 5, windowMs: 15 * 60 * 1000 },
  regenerate: { limit: 5, windowMs: 15 * 60 * 1000 },
  passwordChange: { limit: 10, windowMs: 15 * 60 * 1000 },
  mfaDisable: { limit: 5, windowMs: 15 * 60 * 1000 },
  mfaSetup: { limit: 10, windowMs: 15 * 60 * 1000 },
  sensitive: { limit: 20, windowMs: 15 * 60 * 1000 },
}
export function checkRate(env, request, name, extra = '') {
  const cfg = RATE_LIMITS[name] || RATE_LIMITS.sensitive
  const key = `${name}:${clientIp(request)}:${extra}`
  return rateLimit(key, cfg.limit, cfg.windowMs)
}
// Persistent (D1) rate limiting — the production enforcement point.
// The in-memory Map above is per-isolate only and is kept ONLY as a
// fallback when the D1 table is unavailable (e.g. migration not yet
// applied); it is never the primary limiter in production.
// Design: fixed windows in the rate_limits table (key, window_start).
// Each check does ONE atomic increment (INSERT ... ON CONFLICT DO
// UPDATE SET count = count + 1) and then reads the count. Because the
// increment is a single SQLite statement, concurrent isolates cannot
// both slip under the limit: the count only grows within a window, so
// a check that reads over the limit blocks, even if two requests raced.
// Over-blocking at a window boundary (both blocked instead of one) is
// accepted; under-blocking is not possible via this path.
// Keys: BOTH a per-IP key and (where an account is known) a per-account
// key must pass, each at the same limit. Per-IP alone would lock out
// legitimate users behind shared IPs on targeted attacks, and
// per-account alone would let an attacker rotate IPs — neither alone
// is used where both are available. For register there is no account
// yet, so only the per-IP key applies. Account keys are hashes/IDs,
// never raw emails, so the rate table stores no plaintext PII.
async function checkRateD1Key(db, key, cfg, nowMs, windowStart) {
  await db
    .prepare('INSERT INTO rate_limits (key, window_start, count, updated_at) VALUES (?, ?, 1, ?) ON CONFLICT(key, window_start) DO UPDATE SET count = count + 1, updated_at = excluded.updated_at')
    .bind(key, windowStart, new Date(nowMs).toISOString())
    .run()
  const row = await db
    .prepare('SELECT count FROM rate_limits WHERE key = ? AND window_start = ?')
    .bind(key, windowStart)
    .first()
  return !!row && row.count <= cfg.limit
}
export async function checkRateD1(db, request, name, accountKey = '') {
  const cfg = RATE_LIMITS[name] || RATE_LIMITS.sensitive
  const nowMs = Date.now()
  const windowStart = Math.floor(nowMs / cfg.windowMs)
  const ipH = await ipHash(clientIp(request))
  try {
    if (!(await checkRateD1Key(db, `${name}:ip:${ipH}`, cfg, nowMs, windowStart))) return false
    if (accountKey && !(await checkRateD1Key(db, `${name}:acct:${accountKey}`, cfg, nowMs, windowStart))) return false
    try {
      await db.prepare('DELETE FROM rate_limits WHERE window_start < ?').bind(windowStart - 1).run()
    } catch { /* ignore cleanup errors */ }
    return true
  } catch {
    return checkRate(null, request, name, accountKey)
  }
}
// Account-only check, for two-phase endpoints (login, MFA verify,
// forgot) where the per-IP check already ran before the body was
// parsed and the account is only known afterwards. Calling the
// combined checkRateD1 again would double-count the IP key, so this
// checks only the account key.
export async function checkRateD1Account(db, name, accountKey) {
  if (!accountKey) return true
  const cfg = RATE_LIMITS[name] || RATE_LIMITS.sensitive
  const nowMs = Date.now()
  const windowStart = Math.floor(nowMs / cfg.windowMs)
  try {
    return await checkRateD1Key(db, `${name}:acct:${accountKey}`, cfg, nowMs, windowStart)
  } catch {
    return rateLimit(`${name}:acct:${accountKey}`, cfg.limit, cfg.windowMs)
  }
}

export async function readJson(request, maxBytes = 16384) {
  // Byte limit, not character limit. A body of 5,000 emoji is 5,000
  // characters but 20,000 bytes — the old text.length check would have
  // passed it. The body is read through a stream with a running byte
  // count so an oversized body is rejected while reading, not after
  // the whole body has been buffered. Content-Length, when present,
  // is checked first as a fast path but is never trusted alone
  // (it can be lied about); the stream count is authoritative.
  const declared = request.headers.get('Content-Length')
  if (declared !== null && declared !== '') {
    const n = parseInt(declared, 10)
    if (Number.isFinite(n) && n > maxBytes) throw new Error('BODY_TOO_LARGE')
    if (!Number.isFinite(n) || n < 0) throw new Error('BAD_JSON')
  }
  let text
  const body = request.body
  if (body && typeof body.getReader === 'function') {
    const reader = body.getReader()
    const chunks = []
    let total = 0
    try {
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        if (!value) continue
        total += value.byteLength
        if (total > maxBytes) {
          try { await reader.cancel() } catch { /* ignore */ }
          throw new Error('BODY_TOO_LARGE')
        }
        chunks.push(value)
      }
    } finally {
      try { reader.releaseLock() } catch { /* ignore */ }
    }
    const merged = new Uint8Array(total)
    let off = 0
    for (const c of chunks) { merged.set(c, off); off += c.byteLength }
    text = new TextDecoder().decode(merged)
  } else {
    text = await request.text()
    if (new TextEncoder().encode(text).length > maxBytes) throw new Error('BODY_TOO_LARGE')
  }
  if (!text) return {}
  try {
    const parsed = JSON.parse(text)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('BAD_JSON')
    return parsed
  } catch {
    throw new Error('BAD_JSON')
  }
}
// --- Client-supplied value validation (server side, before any use) ---
// One-time / session tokens this system issues are base64url random
// tokens (randomToken(32) -> ~43 chars, randomToken(16) -> ~22 chars).
// Anything outside that shape can never match a stored hash, so it is
// rejected before any database lookup.
export function isOneTimeToken(v) {
  return typeof v === 'string' && v.length >= 10 && v.length <= 256 && /^[A-Za-z0-9_-]+$/.test(v)
}
export function isSessionId(v) {
  return typeof v === 'string' && v.length >= 1 && v.length <= 128 && /^[A-Za-z0-9_-]+$/.test(v)
}
export function isCodeFormat(v) {
  return /^\d{6}$/.test(String(v || ''))
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
