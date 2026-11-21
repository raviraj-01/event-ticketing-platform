-- H6 (part 3): second factor for admin login. A correct password creates a
-- challenge; the admin must also enter the 6-digit code sent by email.

-- Up Migration
CREATE TABLE admin_login_challenges (
  id TEXT PRIMARY KEY,
  admin_type TEXT NOT NULL CHECK (admin_type IN ('admin', 'super')),
  admin_id TEXT NOT NULL,
  code_hash TEXT NOT NULL,          -- sha256(id:code); the code itself is never stored
  attempts INTEGER NOT NULL DEFAULT 0,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX admin_login_challenges_admin_idx ON admin_login_challenges (admin_type, admin_id);

-- Down Migration
DROP TABLE admin_login_challenges;
