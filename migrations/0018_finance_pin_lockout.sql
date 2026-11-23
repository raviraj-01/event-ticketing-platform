-- M16: finance PIN brute-force protection. Consecutive wrong PINs are counted;
-- 5 in a row lock finance unlock for 15 minutes. New columns only: existing
-- rows are not modified (M22).

-- Up Migration
ALTER TABLE creator_accounts
  ADD COLUMN finance_pin_failures INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN finance_pin_locked_until TIMESTAMPTZ;

-- Down Migration
ALTER TABLE creator_accounts
  DROP COLUMN finance_pin_locked_until,
  DROP COLUMN finance_pin_failures;
