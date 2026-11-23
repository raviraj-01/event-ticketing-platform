-- Q12 / D23 step 2 and M3: the unique rules that needed the duplicate report
-- first. Run `npm run report-duplicates` before this migration on a database
-- with existing accounts: if it lists anything, CREATE UNIQUE INDEX fails, the
-- whole migration rolls back and nothing changes (it never edits rows).
--
-- The older non-unique LOWER(email) indexes from 0014 stay; they are now
-- redundant but harmless.

-- Up Migration

-- Postgres builds and maintains indexes with a fixed search_path (pg_catalog
-- only, since PG 17), so a function used in an index must not call our own
-- phone_key() by its unqualified name. Same rule as before, with phone_key()'s
-- body written out (built-in functions only). Same signature, same results.
CREATE OR REPLACE FUNCTION verified_phone_key(phone_verified BOOLEAN, country_code TEXT, phone TEXT) RETURNS TEXT
LANGUAGE SQL IMMUTABLE AS $$
  SELECT CASE
    WHEN NOT COALESCE(phone_verified, TRUE) THEN NULL
    WHEN COALESCE(REGEXP_REPLACE(phone, '\D', '', 'g'), '') = '' THEN NULL
    ELSE COALESCE(NULLIF(REGEXP_REPLACE(COALESCE(country_code, ''), '\D', '', 'g'), ''), '91')
      || RIGHT(REGEXP_REPLACE(phone, '\D', '', 'g'), 10)
  END
$$;

-- One buyer account per verified phone. verified_phone_key() (0015) is NULL
-- for a missing or unverified phone, so Google-only buyers without a phone and
-- phones typed in before a payment (Q14) are never blocked.
CREATE UNIQUE INDEX users_verified_phone_unique
  ON users (verified_phone_key(phone_verified, country_code, phone))
  WHERE verified_phone_key(phone_verified, country_code, phone) IS NOT NULL;

-- One account per email per table, ignoring case (A@x.com = a@x.com).
CREATE UNIQUE INDEX users_email_lower_unique ON users (LOWER(email));
CREATE UNIQUE INDEX creator_accounts_email_lower_unique ON creator_accounts (LOWER(email));
CREATE UNIQUE INDEX admin_accounts_email_lower_unique ON admin_accounts (LOWER(email));
CREATE UNIQUE INDEX super_admin_accounts_email_lower_unique ON super_admin_accounts (LOWER(email));
-- Not staff_accounts: several staff logins may share one email on purpose
-- (D18: the reset email lists each of them). Staff log in by login ID, which
-- is already unique.

-- Down Migration
DROP INDEX super_admin_accounts_email_lower_unique;
DROP INDEX admin_accounts_email_lower_unique;
DROP INDEX creator_accounts_email_lower_unique;
DROP INDEX users_email_lower_unique;
DROP INDEX users_verified_phone_unique;
CREATE OR REPLACE FUNCTION verified_phone_key(phone_verified BOOLEAN, country_code TEXT, phone TEXT) RETURNS TEXT
LANGUAGE SQL IMMUTABLE AS $$
  SELECT CASE WHEN COALESCE(phone_verified, TRUE) THEN phone_key(country_code, phone) END
$$;
