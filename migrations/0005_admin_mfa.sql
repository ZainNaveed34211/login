ALTER TABLE sessions ADD COLUMN scope TEXT NOT NULL DEFAULT 'full';
CREATE TABLE IF NOT EXISTS admin_challenges (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_mfa_secrets (
  user_id TEXT PRIMARY KEY,
  encrypted_secret TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0,
  last_used_step INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_admin_mfa_secrets (
  user_id TEXT PRIMARY KEY,
  encrypted_secret TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_recovery_codes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  code_hash TEXT NOT NULL UNIQUE,
  used INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_admin_recovery_codes_user ON admin_recovery_codes (user_id);
