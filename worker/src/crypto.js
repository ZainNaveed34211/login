// Crypto helpers for the account Worker. WebCrypto only — no Node APIs,
// so this file runs unchanged in Cloudflare Workers and in Node tests.
// Password hashing: PBKDF2-SHA256. Argon2id is preferred in principle, but
// Cloudflare Workers has no native Argon2id and no vetted built-in library,
// so adding an unvetted WASM Argon2 implementation would be a larger risk
// than a correctly configured PBKDF2. Production iterations are 100,000:
// Workers Free native WebCrypto rejects PBKDF2 counts above 100,000, so
// 600,000 (OWASP guidance) throws there even though it passes in Node.
// The stored hash records its own iteration count, so iterations can be
// raised again on a paid plan without breaking existing accounts.
// PBKDF2_ITERATIONS is set via env in production; tests may use a lower
// value via env for speed, never in prod.
const enc = new TextEncoder()
const dec = new TextDecoder()

// Workers Free native WebCrypto rejects PBKDF2 iteration counts above
// 100000 (NotSupportedError). This cap is enforced in BOTH directions:
// new hashes are never created above it, and a stored hash claiming more
// is never honoured — otherwise a single malicious database value could
// force unbounded CPU work on every login attempt for that account.
export const MAX_PBKDF2_ITERATIONS = 100000
export function clampPbkdf2Iterations(n) {
  const v = Math.floor(Number(n))
  if (!Number.isFinite(v) || v < 1) return MAX_PBKDF2_ITERATIONS
  return Math.min(v, MAX_PBKDF2_ITERATIONS)
}
// Strict parser for the stored hash format. Returns null for anything
// malformed or unsupported — callers must treat null as "no match",
// never throw, never return a server error for a bad stored value.
export function parsePbkdf2Hash(stored) {
  try {
    if (typeof stored !== 'string') return null
    const parts = stored.split('$')
    if (parts.length !== 4 || parts[0] !== 'pbkdf2-sha256') return null
    // Iteration count must be plain decimal digits only (no signs,
    // spaces, decimals or suffixes) and within the supported range.
    if (!/^\d+$/.test(parts[1])) return null
    const iterations = parseInt(parts[1], 10)
    if (!Number.isFinite(iterations) || iterations < 1 || iterations > MAX_PBKDF2_ITERATIONS) return null
    // Salt and hash must be base64 of exactly the expected lengths:
    // 16-byte salt, 32-byte (256-bit) derived key. Anything else cannot
    // be a hash this system produced.
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(parts[2]) || !/^[A-Za-z0-9+/]+={0,2}$/.test(parts[3])) return null
    const salt = b64decode(parts[2])
    const expected = b64decode(parts[3])
    if (salt.length !== 16 || expected.length !== 32) return null
    return { iterations, salt, expected }
  } catch {
    return null
  }
}

export function b64encode(bytes) {
  let s = ''
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode(...bytes.subarray(i, i + chunk))
  }
  return btoa(s)
}
export function b64decode(str) {
  const bin = atob(str)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}
export function b64url(bytes) {
  return b64encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
export function randomBytes(n) {
  const b = new Uint8Array(n)
  crypto.getRandomValues(b)
  return b
}
export function randomToken(n = 32) {
  return b64url(randomBytes(n))
}
export async function sha256Hex(text) {
  const hash = await crypto.subtle.digest('SHA-256', enc.encode(text))
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, '0')).join('')
}
export function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase()
}
export async function hashPassword(password, iterations) {
  // Defence in depth: even if a caller passes an env value above the
  // Workers Free maximum, the created hash is capped, never thrown.
  const it = clampPbkdf2Iterations(iterations)
  const salt = randomBytes(16)
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: it, hash: 'SHA-256' },
    key,
    256,
  )
  return `pbkdf2-sha256$${it}$${b64encode(salt)}$${b64encode(new Uint8Array(bits))}`
}
export async function verifyPassword(password, stored) {
  try {
    // Login/current-password inputs are never hashed at unbounded size:
    // every password this system creates is at most 128 characters, so a
    // longer candidate can never match and must not cost a PBKDF2 run.
    // This returns false (caller maps it to the generic 401), never an
    // error, and it does not leak account existence: the same false is
    // returned whether the account exists or not.
    if (typeof password !== 'string' || password.length === 0 || password.length > 128) return false
    const parsed = parsePbkdf2Hash(stored)
    if (!parsed) return false
    const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits'])
    const bits = new Uint8Array(
      await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: parsed.salt, iterations: parsed.iterations, hash: 'SHA-256' }, key, 256),
    )
    if (bits.length !== parsed.expected.length) return false
    let diff = 0
    for (let i = 0; i < bits.length; i++) diff |= bits[i] ^ parsed.expected[i]
    return diff === 0
  } catch {
    return false
  }
}

// --- TOTP (RFC 6238, HMAC-SHA1, 30s step, 6 digits) ---
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
export function base32Encode(bytes) {
  let out = ''
  let bits = 0
  let value = 0
  for (const b of bytes) {
    value = (value << 8) | b
    bits += 8
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31]
  while (out.length % 8 !== 0) out += '='
  return out
}
export function base32Decode(str) {
  const clean = String(str || '').toUpperCase().replace(/[^A-Z2-7]/g, '')
  const bytes = []
  let bits = 0
  let value = 0
  for (const ch of clean) {
    value = (value << 5) | B32.indexOf(ch)
    bits += 5
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255)
      bits -= 8
    }
  }
  return new Uint8Array(bytes)
}
export async function totpCode(secretBytes, step) {
  const msg = new DataView(new ArrayBuffer(8))
  msg.setBigUint64(0, BigInt(step), false)
  const key = await crypto.subtle.importKey('raw', secretBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign'])
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg.buffer))
  const offset = sig[sig.length - 1] & 0x0f
  const code =
    ((sig[offset] & 0x7f) << 24) | ((sig[offset + 1] & 0xff) << 16) | ((sig[offset + 2] & 0xff) << 8) | (sig[offset + 3] & 0xff)
  return String(code % 1000000).padStart(6, '0')
}
export async function verifyTotp(secretBytes, code, lastUsedStep, nowMs = Date.now()) {
  if (!/^\d{6}$/.test(String(code || ''))) return { ok: false, step: null }
  const step = Math.floor(nowMs / 30000)
  for (const s of [step - 1, step, step + 1]) {
    if (lastUsedStep !== null && lastUsedStep !== undefined && s <= lastUsedStep) continue
    if ((await totpCode(secretBytes, s)) === String(code)) return { ok: true, step: s }
  }
  return { ok: false, step: null }
}

// --- AES-GCM encryption for MFA secrets at rest ---
async function encryptionKey(env) {
  const raw = b64decode(env.MFA_ENCRYPTION_KEY || '')
  if (raw.length !== 32) throw new Error('MFA_ENCRYPTION_KEY must be base64 of 32 bytes')
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}
export async function encryptSecret(env, secretBytes) {
  const key = await encryptionKey(env)
  const iv = randomBytes(12)
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, secretBytes))
  return `${b64encode(iv)}:${b64encode(ct)}`
}
export async function decryptSecret(env, stored) {
  const [ivB64, ctB64] = String(stored || '').split(':')
  if (!ivB64 || !ctB64) throw new Error('Invalid encrypted secret')
  const key = await encryptionKey(env)
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64decode(ivB64) }, key, b64decode(ctB64))
  return new Uint8Array(pt)
}

// --- Recovery codes: 10 codes, 16 chars each, ~80 bits entropy each ---
const RC_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
export function generateRecoveryCodes(count = 10) {
  const codes = []
  for (let i = 0; i < count; i++) {
    const bytes = randomBytes(16)
    let code = ''
    for (const b of bytes) code += RC_ALPHABET[b % RC_ALPHABET.length]
    codes.push(`${code.slice(0, 4)}-${code.slice(4, 8)}-${code.slice(8, 12)}-${code.slice(12, 16)}`)
  }
  return codes
}
export function normalizeRecoveryCode(code) {
  return String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, '')
}
export function safeLog(event, fields = {}) {
  // Structured log with NO credentials, secrets, codes, or tokens.
  try {
    console.log(JSON.stringify({ event, ...fields }))
  } catch { /* ignore */ }
}
export { dec }
