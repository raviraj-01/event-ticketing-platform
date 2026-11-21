-- H10 / D4: cash a staff member collects belongs to the organizer.
-- cash owed = cash collected in creator-quota sales - cash handed over here.
-- Only commission is withdrawable (staff_withdrawals).

-- Up Migration
CREATE TABLE staff_cash_settlements (
  id TEXT PRIMARY KEY,
  creator_id INTEGER NOT NULL REFERENCES creator_accounts(id) ON DELETE CASCADE,
  staff_id TEXT NOT NULL REFERENCES staff_accounts(id) ON DELETE CASCADE,
  amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
  note TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX staff_cash_settlements_staff_idx ON staff_cash_settlements (staff_id);

-- Withdrawals are money: make sure no zero/negative amount can be stored.
ALTER TABLE staff_withdrawals ADD CONSTRAINT staff_withdrawals_amount_positive CHECK (amount > 0);

-- Down Migration
ALTER TABLE staff_withdrawals DROP CONSTRAINT staff_withdrawals_amount_positive;
DROP TABLE staff_cash_settlements;
