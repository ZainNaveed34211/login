CREATE TABLE IF NOT EXISTS admin_allowlist (
  user_id TEXT PRIMARY KEY,
  role TEXT NOT NULL CHECK (role = 'super_admin'),
  created_at TEXT NOT NULL,
  created_by TEXT,
  note TEXT
);

DELETE FROM admin_mfa_secrets WHERE user_id NOT IN (SELECT user_id FROM admin_allowlist);
DELETE FROM pending_admin_mfa_secrets WHERE user_id NOT IN (SELECT user_id FROM admin_allowlist);
DELETE FROM admin_recovery_codes WHERE user_id NOT IN (SELECT user_id FROM admin_allowlist);
DELETE FROM admin_challenges WHERE user_id NOT IN (SELECT user_id FROM admin_allowlist);
DELETE FROM sessions WHERE scope = 'admin' AND user_id NOT IN (SELECT user_id FROM admin_allowlist);
