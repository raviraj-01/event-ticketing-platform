-- Q12 / D23, step 1: one buyer account per VERIFIED phone.
-- This migration only adds the flag and the "same phone" rule. The partial
-- unique index comes in a later migration, after Ravi has reviewed the
-- duplicate report (npm run report-duplicate-phones).

-- Up Migration

-- Two phones are the same when their phone_key is equal. Signup only accepts
-- +91 numbers (Twilio Verify), but old rows store the number in different
-- shapes ("98765 43210" + "+91", "+919876543210" + no country code), so the
-- key is: country digits (default 91) + the last 10 digits of the phone.
-- NULL for an empty phone, so phoneless accounts never collide.
CREATE FUNCTION phone_key(country_code TEXT, phone TEXT) RETURNS TEXT
LANGUAGE SQL IMMUTABLE AS $$
  SELECT CASE
    WHEN COALESCE(REGEXP_REPLACE(phone, '\D', '', 'g'), '') = '' THEN NULL
    ELSE COALESCE(NULLIF(REGEXP_REPLACE(COALESCE(country_code, ''), '\D', '', 'g'), ''), '91')
      || RIGHT(REGEXP_REPLACE(phone, '\D', '', 'g'), 10)
  END
$$;

ALTER TABLE users ADD COLUMN phone_verified BOOLEAN NOT NULL DEFAULT FALSE;

-- Backfill: users.phone is only ever written by POST /signup, and signup
-- requires a Twilio OTP for that exact phone. So every account with a phone
-- verified it. (Accounts made by older code without OTP cannot be told apart;
-- the duplicate report shows them for a manual decision.)
UPDATE users SET phone_verified = TRUE WHERE phone_key(country_code, phone) IS NOT NULL;

-- Down Migration
ALTER TABLE users DROP COLUMN phone_verified;
DROP FUNCTION phone_key(TEXT, TEXT);
