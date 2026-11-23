-- M3: constraints the database never had. All of them are NOT VALID: Postgres
-- enforces them for every new or changed row, but does not check (or need to
-- change) rows that already exist, so this migration cannot fail on old data
-- and modifies nothing (M22). `npm run report-duplicates` lists old rows that
-- break a rule, if Ravi wants to clean them up and then VALIDATE.
--
-- Not added here: CHECKs on status columns (every write path sets a known
-- value and each column has a default; a wrong list would break a write path),
-- and unique case-insensitive emails / phones, which need the duplicate report
-- first (Q12, D23).

-- Up Migration
ALTER TABLE bookings
  ADD CONSTRAINT bookings_event_fk FOREIGN KEY (event_id) REFERENCES creator_events(id) NOT VALID,
  ADD CONSTRAINT bookings_qty_positive CHECK (qty > 0) NOT VALID,
  ADD CONSTRAINT bookings_price_not_negative CHECK (price >= 0) NOT VALID,
  ADD CONSTRAINT bookings_total_not_negative CHECK (total >= 0) NOT VALID;

ALTER TABLE staff_sales
  ADD CONSTRAINT staff_sales_qty_positive CHECK (qty > 0) NOT VALID,
  ADD CONSTRAINT staff_sales_amounts_not_negative CHECK (price >= 0 AND total >= 0 AND commission >= 0) NOT VALID;

ALTER TABLE staff_assignments
  ADD CONSTRAINT staff_assignments_counts_valid CHECK (qty >= 0 AND sold_count >= 0 AND sold_count <= qty) NOT VALID,
  ADD CONSTRAINT staff_assignments_commission_range CHECK (commission_rate >= 0 AND commission_rate <= 100) NOT VALID;

ALTER TABLE payment_transactions
  ADD CONSTRAINT payment_transactions_amount_not_negative CHECK (amount >= 0) NOT VALID;

ALTER TABLE creator_events
  ADD CONSTRAINT creator_events_capacity_positive CHECK (capacity > 0) NOT VALID;

-- Down Migration
ALTER TABLE creator_events DROP CONSTRAINT creator_events_capacity_positive;
ALTER TABLE payment_transactions DROP CONSTRAINT payment_transactions_amount_not_negative;
ALTER TABLE staff_assignments DROP CONSTRAINT staff_assignments_commission_range;
ALTER TABLE staff_assignments DROP CONSTRAINT staff_assignments_counts_valid;
ALTER TABLE staff_sales DROP CONSTRAINT staff_sales_amounts_not_negative;
ALTER TABLE staff_sales DROP CONSTRAINT staff_sales_qty_positive;
ALTER TABLE bookings DROP CONSTRAINT bookings_total_not_negative;
ALTER TABLE bookings DROP CONSTRAINT bookings_price_not_negative;
ALTER TABLE bookings DROP CONSTRAINT bookings_qty_positive;
ALTER TABLE bookings DROP CONSTRAINT bookings_event_fk;
