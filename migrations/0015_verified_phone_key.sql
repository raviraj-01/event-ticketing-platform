-- M22 / Q12: one definition of "this account's verified phone", without
-- touching existing rows. Returns phone_key() when the phone counts as
-- verified, else NULL:
--   phone_verified TRUE  -> verified (OTP at signup)
--   phone_verified FALSE -> not verified (typed in before a payment, Q14)
--   phone_verified NULL  -> account from before the flag existed; its phone came
--                           from OTP signup, so it counts as verified
-- Used by the signup check, phone login, the duplicate report and (later) the
-- partial unique index.

-- Up Migration
CREATE OR REPLACE FUNCTION verified_phone_key(phone_verified BOOLEAN, country_code TEXT, phone TEXT) RETURNS TEXT
LANGUAGE SQL IMMUTABLE AS $$
  SELECT CASE WHEN COALESCE(phone_verified, TRUE) THEN phone_key(country_code, phone) END
$$;

-- Down Migration
DROP FUNCTION verified_phone_key(BOOLEAN, TEXT, TEXT);
