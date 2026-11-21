-- H6 (part 2): lock an admin account after repeated wrong passwords.

-- Up Migration
ALTER TABLE admin_accounts
  ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN locked_until TIMESTAMPTZ;
ALTER TABLE super_admin_accounts
  ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN locked_until TIMESTAMPTZ;

-- Down Migration
ALTER TABLE super_admin_accounts DROP COLUMN locked_until, DROP COLUMN failed_login_count;
ALTER TABLE admin_accounts DROP COLUMN locked_until, DROP COLUMN failed_login_count;
