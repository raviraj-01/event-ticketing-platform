-- Q4: organizers (creators) and staff with an email can reset their password
-- through the same emailed single-use link as buyers (see H2).

-- Up Migration
ALTER TABLE creator_accounts ADD COLUMN password_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE staff_accounts ADD COLUMN password_version INTEGER NOT NULL DEFAULT 0;

-- Down Migration
ALTER TABLE staff_accounts DROP COLUMN password_version;
ALTER TABLE creator_accounts DROP COLUMN password_version;
