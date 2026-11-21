-- H2: password reset links must work only once.
-- The reset token carries the user's password_version; a successful reset
-- increments it, so any older (or reused) token no longer matches.

-- Up Migration
ALTER TABLE users ADD COLUMN password_version INTEGER NOT NULL DEFAULT 0;

-- Down Migration
ALTER TABLE users DROP COLUMN password_version;
