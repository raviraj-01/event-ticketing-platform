-- Q4: accounts reset by someone else get a temporary password and must choose
-- a new one before they can do anything else.

-- Up Migration
ALTER TABLE staff_accounts ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE admin_accounts ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE super_admin_accounts ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE;

-- Down Migration
ALTER TABLE super_admin_accounts DROP COLUMN must_change_password;
ALTER TABLE admin_accounts DROP COLUMN must_change_password;
ALTER TABLE staff_accounts DROP COLUMN must_change_password;
