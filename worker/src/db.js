// D1 helpers. All queries are parameterized — never interpolate user input
// into SQL. This file works against real Cloudflare D1 and against the
// in-memory mock D1 used in tests (which implements the same interface:
// prepare(sql).bind(...).first()/all()/run(), and db.batch(statements)).
import { randomToken, sha256Hex } from './crypto.js'

export function nowIso() {
  return new Date().toISOString()
}
export function isoPlus(ms) {
  return new Date(Date.now() + ms).toISOString()
}
export async function getUserByEmail(db, emailNormalized) {
  return db.prepare('SELECT * FROM users WHERE email_normalized = ?').bind(emailNormalized).first()
}
export async function getUserById(db, id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').bind(id).first()
}
export async function getSessionByHash(db, tokenHash) {
  return db.prepare('SELECT * FROM sessions WHERE token_hash = ?').bind(tokenHash).first()
}
export async function createSession(db, userId, userAgent, ipHashValue) {
  const token = randomToken(32)
  const tokenHash = await sha256Hex(token)
  const csrfToken = randomToken(24)
  const id = randomToken(16)
  const expiresAt = isoPlus(2 * 24 * 60 * 60 * 1000) // 2 days, server-enforced
  await db
    .prepare(
      'INSERT INTO sessions (id, user_id, token_hash, csrf_token, user_agent, ip_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    )
    .bind(id, userId, tokenHash, csrfToken, userAgent || '', ipHashValue || '', nowIso(), expiresAt)
    .run()
  return { id, token, csrfToken, expiresAt }
}
export async function deleteSessionByHash(db, tokenHash) {
  await db.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(tokenHash).run()
}
export async function deleteAllSessions(db, userId) {
  await db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(userId).run()
}
export async function listSessions(db, userId) {
  const res = await db
    .prepare('SELECT id, created_at, expires_at, user_agent, ip_hash FROM sessions WHERE user_id = ? ORDER BY created_at DESC')
    .bind(userId)
    .all()
  return res.results || []
}
export async function audit(db, userId, eventType, ipHashValue, ok, detail = '') {
  try {
    await db
      .prepare('INSERT INTO audit_events (id, user_id, event_type, ip_hash, ok, detail, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .bind(randomToken(16), userId || '', eventType, ipHashValue || '', ok ? 1 : 0, String(detail || '').slice(0, 200), nowIso())
      .run()
  } catch { /* audit must never break the main flow */ }
}
export async function getEntitlement(db, userId) {
  const row = await db.prepare('SELECT * FROM entitlements WHERE user_id = ?').bind(userId).first()
  if (!row) return { plan: 'free', status: 'active', premium: false }
  const premium = (row.plan === 'growth' || row.plan === 'max') && row.status === 'active'
  return { plan: row.plan, status: row.status, premium }
}
