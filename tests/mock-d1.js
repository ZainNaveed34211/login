// In-memory D1 mock implementing the subset of Cloudflare D1 used by the
// Worker: prepare(sql).bind(...).first()/all()/run(), and db.batch().
// Batch is atomic via snapshot/restore, matching D1 batch semantics.
// UNIQUE constraints are enforced for the columns the Worker relies on.
const UNIQUE = {
  users: ['email_normalized'],
  sessions: ['token_hash'],
  setup_tokens: ['token_hash'],
  login_challenges: ['token_hash'],
  recovery_codes: ['code_hash'],
  recovery_transactions: ['token_hash'],
}
export class MockD1 {
  constructor() {
    this.tables = {
      users: [], sessions: [], mfa_secrets: [], pending_mfa_secrets: [],
      setup_tokens: [], login_challenges: [], recovery_codes: [],
      recovery_transactions: [], entitlements: [], audit_events: [],
      rate_limits: [],
    }
  }
  snapshot() { return JSON.parse(JSON.stringify(this.tables)) }
  restore(snap) { this.tables = JSON.parse(JSON.stringify(snap)) }
  prepare(sql) {
    const self = this
    return {
      sql,
      params: [],
      bind(...params) { this.params = params; return this },
      first() { const rows = self._query(this.sql, this.params); return rows[0] || null },
      all() { return { results: self._query(this.sql, this.params) } },
      run() { const changes = self._exec(this.sql, this.params); return { success: true, meta: { changes } } },
    }
  }
  async batch(statements) {
    const snap = this.snapshot()
    try {
      for (const st of statements) st.run()
    } catch (e) {
      this.restore(snap)
      throw e
    }
    return []
  }
  // Faithful subset of SQLite WHERE semantics used by the Worker:
  // top-level AND, parenthesised OR groups, =, !=, <, >, <=, >=,
  // IS NULL / IS NOT NULL. NULL compared with any operator (except
  // IS NULL) is false, matching SQL three-valued logic. Parameter
  // order follows the SQL text, including inside OR groups.
  _splitTopLevel(sql, keyword) {
    const out = []
    let depth = 0
    let cur = ''
    const re = new RegExp(`\\s+${keyword}\\s+`, 'gi')
    let last = 0
    let m
    // Walk manually so AND/OR inside parentheses are not split.
    for (let i = 0; i < sql.length; i++) {
      const ch = sql[i]
      if (ch === '(') depth++
      else if (ch === ')') depth--
      if (depth === 0) {
        const rest = sql.slice(i)
        const km = rest.match(new RegExp(`^\\s+${keyword}\\s+`, 'i'))
        if (km) {
          out.push(sql.slice(last, i))
          i += km[0].length - 1
          last = i + 1
        }
      }
    }
    out.push(sql.slice(last))
    return out.map((s) => s.trim()).filter(Boolean)
  }
  _parseWhere(whereSql, params) {
    if (!whereSql) return () => true
    const state = { i: 0 }
    const parts = this._splitTopLevel(whereSql, 'AND')
    const conds = parts.map((part) => this._parseCondition(part, params, state))
    return (row) => conds.every((c) => c(row))
  }
  _parseCondition(part, params, state) {
    part = part.trim()
    if (part.startsWith('(') && part.endsWith(')')) {
      const inner = part.slice(1, -1)
      const ors = this._splitTopLevel(inner, 'OR')
      const fns = ors.map((o) => this._parseCondition(o, params, state))
      return (row) => fns.some((f) => f(row))
    }
    let m = part.match(/^(\w+)\s+IS\s+NOT\s+NULL$/i)
    if (m) { const col = m[1]; return (row) => row[col] !== null && row[col] !== undefined }
    m = part.match(/^(\w+)\s+IS\s+NULL$/i)
    if (m) { const col = m[1]; return (row) => row[col] === null || row[col] === undefined }
    m = part.match(/^(\w+)\s*(<=|>=|!=|=|<|>)\s*(\?|(\d+))$/)
    if (!m) throw new Error('Unsupported WHERE: ' + part)
    const col = m[1]
    const op = m[2]
    const value = m[3] === '?' ? params[state.i++] : Number(m[4])
    return (row) => {
      const v = row[col]
      if (v === null || v === undefined) return false
      if (op === '=') return v === value
      if (op === '!=') return v !== value
      if (op === '<') return v < value
      if (op === '>') return v > value
      if (op === '<=') return v <= value
      if (op === '>=') return v >= value
      return false
    }
  }
  _query(sql, params) {
    const m = sql.match(/^SELECT\s+(.+?)\s+FROM\s+(\w+)(?:\s+WHERE\s+(.+?))?(?:\s+ORDER BY\s+\w+\s+(?:ASC|DESC))?$/i)
    if (!m) throw new Error('Unsupported SELECT: ' + sql)
    const cols = m[1].trim()
    const table = m[2]
    const filter = this._parseWhere(m[3], params)
    let rows = (this.tables[table] || []).filter(filter)
    if (/ORDER BY/i.test(sql)) {
      rows = [...rows].sort((a, b) => (a.created_at < b.created_at ? 1 : -1))
    }
    if (cols === '*') return rows.map((r) => ({ ...r }))
    const wanted = cols.split(',').map((c) => c.trim())
    return rows.map((r) => { const o = {}; for (const c of wanted) o[c] = r[c]; return o })
  }
  _applySet(row, setSql, newRow, params, pi) {
    // Returns next param index. Supports: col = ?, col = N,
    // col = col + N, col = excluded.col (ON CONFLICT upsert).
    for (const part of setSql.split(',').map((s) => s.trim())) {
      let sm = part.match(/^(\w+)\s*=\s*(\w+)\s*\+\s*(\d+)$/)
      if (sm) { row[sm[1]] = (row[sm[1]] || 0) + Number(sm[3]); continue }
      sm = part.match(/^(\w+)\s*=\s*excluded\.(\w+)$/i)
      if (sm) { row[sm[1]] = newRow ? newRow[sm[2]] : row[sm[1]]; continue }
      sm = part.match(/^(\w+)\s*=\s*(\?|(\d+))$/)
      if (!sm) throw new Error('Unsupported SET: ' + part)
      row[sm[1]] = sm[2] === '?' ? params[pi.value++] : Number(sm[3])
    }
    return pi.value
  }
  _exec(sql, params) {
    let m = sql.match(/^INSERT INTO (\w+)\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)(?:\s+ON CONFLICT\s*\(([^)]+)\)\s+DO UPDATE SET\s+(.+))?$/i)
    if (m) {
      const table = m[1]
      const cols = m[2].split(',').map((c) => c.trim())
      // VALUES entries may be ? placeholders OR literals (e.g. the
      // rate-limit upsert uses VALUES (?, ?, 1, ?)). Placeholders
      // consume params in order; literals are used as-is. Assuming
      // 1:1 column-to-param alignment here would shift every value
      // after the first literal — a real mock bug, now fixed.
      const valueParts = m[3].split(',').map((s) => s.trim())
      const row = {}
      let vi = 0
      cols.forEach((c, i) => {
        const part = valueParts[i]
        if (part === '?') row[c] = params[vi++]
        else if (/^-?\d+$/.test(part)) row[c] = Number(part)
        else if (/^'[^']*'$/.test(part)) row[c] = part.slice(1, -1)
        else row[c] = part
      })
      const valuesParamCount = vi
      const conflictCols = m[4] ? m[4].split(',').map((c) => c.trim()) : null
      if (conflictCols) {
        const existing = (this.tables[table] || []).find((r) => conflictCols.every((c) => r[c] === row[c]))
        if (existing) {
          const pi = { value: valuesParamCount }
          this._applySet(existing, m[5], row, params, pi)
          return 1
        }
        this.tables[table].push(row)
        return 1
      }
      if (table === 'rate_limits') {
        if ((this.tables[table] || []).some((r) => r.key === row.key && r.window_start === row.window_start)) {
          throw new Error('UNIQUE constraint failed: rate_limits.key, rate_limits.window_start')
        }
      }
      for (const u of UNIQUE[table] || []) {
        if ((this.tables[table] || []).some((r) => r[u] === row[u])) throw new Error('UNIQUE constraint failed: ' + u)
      }
      this.tables[table].push(row)
      return 1
    }
    m = sql.match(/^UPDATE (\w+)\s+SET\s+(.+?)\s+WHERE\s+(.+)$/i)
    if (m) {
      const table = m[1]
      // SET values are computed per-row for col+N forms; ? params are
      // consumed once in SQL order (all our UPDATEs use ? or literals).
      const setParts = m[2].split(',').map((s) => s.trim())
      let pi = 0
      const updates = {}
      const increments = {}
      for (const part of setParts) {
        let sm = part.match(/^(\w+)\s*=\s*(\w+)\s*\+\s*(\d+)$/)
        if (sm) { increments[sm[1]] = Number(sm[3]); continue }
        sm = part.match(/^(\w+)\s*=\s*(\?|(\d+))$/)
        if (!sm) throw new Error('Unsupported SET: ' + part)
        updates[sm[1]] = sm[2] === '?' ? params[pi++] : Number(sm[3])
      }
      const filter = this._parseWhere(m[3], params.slice(pi))
      let count = 0
      for (const row of this.tables[table] || []) {
        if (!filter(row)) continue
        Object.assign(row, updates)
        for (const [c, n] of Object.entries(increments)) row[c] = (row[c] || 0) + n
        count++
      }
      return count
    }
    m = sql.match(/^DELETE FROM (\w+)(?:\s+WHERE\s+(.+))?$/i)
    if (m) {
      const table = m[1]
      const filter = this._parseWhere(m[2], params)
      const before = (this.tables[table] || []).length
      this.tables[table] = (this.tables[table] || []).filter((r) => !filter(r))
      return before - this.tables[table].length
    }
    throw new Error('Unsupported SQL: ' + sql)
  }
}
// Test encryption key: generated FRESH on every test run, never
// hardcoded, never a production key. The production key is generated by
// the owner and set via the Worker secret flow only (see the chat guide,
// never a GitHub md file).
export function testEnv(db) {
  const freshKey = new Uint8Array(32)
  globalThis.crypto.getRandomValues(freshKey)
  return {
    DB: db,
    MFA_ENCRYPTION_KEY: Buffer.from(freshKey).toString('base64'),
    ALLOWED_ORIGINS: 'http://localhost:3000',
    ALLOW_LOCALHOST: 'false',
    ALLOW_INSECURE_COOKIE: 'true',
    PBKDF2_ITERATIONS: '1000',
  }
}
