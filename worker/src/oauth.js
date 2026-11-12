import { b64url, randomToken } from './crypto.js'
import { isValidEmail } from './security.js'

export const OAUTH_REDIRECT_BASE = 'https://accounts.kluzar.com'
export const OAUTH_STATE_TTL_MS = 10 * 60 * 1000
export const OAUTH_HANDOFF_TTL_MS = 5 * 60 * 1000

const PROVIDERS = {
  google: {
    authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    jwksUrl: 'https://www.googleapis.com/oauth2/v3/certs',
    issuers: ['https://accounts.google.com', 'accounts.google.com'],
    scopes: 'openid email profile',
    extraAuthorize: { access_type: 'online', prompt: 'select_account' },
    clientIdEnv: 'GOOGLE_CLIENT_ID',
    clientSecretEnv: 'GOOGLE_CLIENT_SECRET',
  },
  microsoft: {
    authorizeUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    jwksUrl: 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
    issuers: null,
    scopes: 'openid email profile',
    extraAuthorize: { prompt: 'select_account', response_mode: 'query' },
    clientIdEnv: 'MICROSOFT_CLIENT_ID',
    clientSecretEnv: 'MICROSOFT_CLIENT_SECRET',
  },
}

export function isOAuthProvider(v) {
  return v === 'google' || v === 'microsoft'
}

export function oauthConfig(provider, env) {
  if (!isOAuthProvider(provider)) return null
  const p = PROVIDERS[provider]
  const clientId = env[p.clientIdEnv] || ''
  const clientSecret = env[p.clientSecretEnv] || ''
  if (!clientId || !clientSecret) return null
  return {
    provider,
    clientId,
    clientSecret,
    redirectUri: OAUTH_REDIRECT_BASE + '/auth/' + provider + '/callback',
    authorizeUrl: p.authorizeUrl,
    tokenUrl: p.tokenUrl,
    jwksUrl: p.jwksUrl,
    issuers: p.issuers,
    scopes: p.scopes,
    extraAuthorize: p.extraAuthorize,
  }
}

export function validReturnUrl(raw) {
  try {
    if (!raw || typeof raw !== 'string' || raw.length > 2048) return ''
    const u = new URL(raw)
    if (u.protocol !== 'https:' || u.username || u.password) return ''
    const h = u.hostname.toLowerCase()
    if (h === 'kluzar.com' || (h.endsWith('.kluzar.com') && h !== 'accounts.kluzar.com')) return u.toString()
    return ''
  } catch {
    return ''
  }
}

export async function sha256Bytes(text) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return new Uint8Array(hash)
}

export async function pkcePair() {
  const verifier = randomToken(32)
  const challenge = b64url(await sha256Bytes(verifier))
  return { verifier, challenge }
}

export function buildAuthorizeUrl(cfg, state, challenge) {
  const u = new URL(cfg.authorizeUrl)
  u.searchParams.set('client_id', cfg.clientId)
  u.searchParams.set('response_type', 'code')
  u.searchParams.set('redirect_uri', cfg.redirectUri)
  u.searchParams.set('scope', cfg.scopes)
  u.searchParams.set('state', state)
  u.searchParams.set('code_challenge', challenge)
  u.searchParams.set('code_challenge_method', 'S256')
  for (const [k, v] of Object.entries(cfg.extraAuthorize)) u.searchParams.set(k, v)
  return u.toString()
}

export async function exchangeCode(cfg, code, verifier) {
  let res
  try {
    res = await fetch(cfg.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret,
        redirect_uri: cfg.redirectUri,
        grant_type: 'authorization_code',
        code_verifier: verifier,
      }).toString(),
    })
  } catch {
    return null
  }
  if (!res || !res.ok) return null
  let data
  try {
    data = await res.json()
  } catch {
    return null
  }
  if (!data || typeof data.id_token !== 'string' || !data.id_token) return null
  return data.id_token
}

function b64urlDecode(str) {
  const s = String(str || '').replace(/-/g, '+').replace(/_/g, '/')
  const pad = s.length % 4
  const bin = atob(pad ? s + '='.repeat(4 - pad) : s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

function jsonFromB64url(str) {
  try {
    return JSON.parse(new TextDecoder().decode(b64urlDecode(str)))
  } catch {
    return null
  }
}

const jwksCache = new Map()
export function resetJwksCache() {
  jwksCache.clear()
}

async function fetchJwks(jwksUrl) {
  const now = Date.now()
  const cached = jwksCache.get(jwksUrl)
  if (cached && now - cached.fetchedAt < 60 * 60 * 1000) return cached.keys
  let res
  try {
    res = await fetch(jwksUrl)
  } catch {
    return null
  }
  if (!res || !res.ok) return null
  let data
  try {
    data = await res.json()
  } catch {
    return null
  }
  if (!data || !Array.isArray(data.keys)) return null
  jwksCache.set(jwksUrl, { keys: data.keys, fetchedAt: now })
  return data.keys
}

function issuerOk(cfg, iss) {
  if (typeof iss !== 'string' || !iss) return false
  if (cfg.issuers) return cfg.issuers.includes(iss)
  return /^https:\/\/login\.microsoftonline\.com\/[0-9a-fA-F-]+\/v2\.0$/.test(iss)
}

function emailFromClaims(cfg, claims) {
  if (cfg.provider === 'google') {
    if (claims.email_verified !== true) return null
    const email = typeof claims.email === 'string' ? claims.email.trim().toLowerCase() : ''
    return isValidEmail(email) ? email : null
  }
  const candidates = [claims.email, claims.preferred_username]
  for (const c of candidates) {
    const email = typeof c === 'string' ? c.trim().toLowerCase() : ''
    if (isValidEmail(email)) return email
  }
  return null
}

export async function verifyIdToken(cfg, idToken) {
  try {
    if (typeof idToken !== 'string') return null
    const parts = idToken.split('.')
    if (parts.length !== 3) return null
    const header = jsonFromB64url(parts[0])
    const claims = jsonFromB64url(parts[1])
    if (!header || !claims) return null
    if (header.alg !== 'RS256' || typeof header.kid !== 'string' || !header.kid) return null
    if (typeof claims.sub !== 'string' || !claims.sub) return null
    if (claims.aud !== cfg.clientId) return null
    if (!issuerOk(cfg, claims.iss)) return null
    const nowSec = Math.floor(Date.now() / 1000)
    if (typeof claims.exp !== 'number' || claims.exp <= nowSec) return null
    if (typeof claims.iat === 'number' && claims.iat > nowSec + 300) return null
    const keys = await fetchJwks(cfg.jwksUrl)
    if (!keys) return null
    const jwk = keys.find((k) => k && k.kid === header.kid && k.kty === 'RSA')
    if (!jwk) return null
    let key
    try {
      key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'])
    } catch {
      return null
    }
    const signingInput = new TextEncoder().encode(parts[0] + '.' + parts[1])
    const signature = b64urlDecode(parts[2])
    let ok = false
    try {
      ok = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, signature, signingInput)
    } catch {
      return null
    }
    if (!ok) return null
    const email = emailFromClaims(cfg, claims)
    if (!email) return null
    return { sub: claims.sub, email }
  } catch {
    return null
  }
}
