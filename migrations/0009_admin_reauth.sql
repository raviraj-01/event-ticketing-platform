-- H6 (part 4): destructive admin actions need the password again within the
-- last 5 minutes ("step-up" confirmation).

-- Up Migration
ALTER TABLE admin_accounts ADD COLUMN reauth_until TIMESTAMPTZ;
ALTER TABLE super_admin_accounts ADD COLUMN reauth_until TIMESTAMPTZ;

-- Down Migration
ALTER TABLE super_admin_accounts DROP COLUMN reauth_until;
ALTER TABLE admin_accounts DROP COLUMN reauth_until;
