-- 0004: persistent rate-limit counters for the account Worker.
-- Why: the previous limiter lived in a per-isolate in-memory Map, so
-- limits were not shared across Worker isolates. These counters live
-- in D1 (the same database the Worker already binds as DB), so every
-- isolate increments and reads the same counters.
-- A row is one (limit key, fixed window). The Worker increments with
-- INSERT ... ON CONFLICT DO UPDATE SET count = count + 1 (a single
-- atomic SQLite statement) and blocks when count exceeds the limit.
-- Keys are hashes/IDs, never raw emails, so no plaintext PII is stored.
-- Old windows are deleted opportunistically by the Worker; this table
-- is append-only within a window and never holds credentials, tokens
-- or hashes of passwords.
CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (key, window_start)
);
CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start);
