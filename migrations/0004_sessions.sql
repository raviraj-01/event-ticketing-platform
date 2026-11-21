-- H5: short-lived access tokens + rotating refresh tokens + instant revocation.

-- Up Migration

-- Every access token carries the account's token_version ("tv"). Bumping it
-- (logout everywhere, password reset) makes all existing access tokens
-- invalid on their next request.
ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE creator_accounts ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE staff_accounts ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE admin_accounts ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE super_admin_accounts ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0;

-- Refresh tokens are random strings given to the client once; only their
-- SHA-256 hash is stored, so a database leak does not leak usable tokens.
-- Each login starts a "family"; every refresh marks the old token used and
-- adds a new one to the same family. A used token showing up again means it
-- was stolen, so the whole family is revoked.
CREATE TABLE refresh_tokens (
  id BIGSERIAL PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  family_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('buyer', 'creator', 'staff', 'admin')),
  account_id TEXT NOT NULL,
  admin_type TEXT CHECK (admin_type IN ('admin', 'super')),
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_account_idx ON refresh_tokens (role, account_id);

-- Down Migration
DROP TABLE refresh_tokens;
ALTER TABLE super_admin_accounts DROP COLUMN token_version;
ALTER TABLE admin_accounts DROP COLUMN token_version;
ALTER TABLE staff_accounts DROP COLUMN token_version;
ALTER TABLE creator_accounts DROP COLUMN token_version;
ALTER TABLE users DROP COLUMN token_version;
