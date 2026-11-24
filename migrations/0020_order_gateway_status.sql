-- H19: what PayU's verify API last said about an order, so the reconciliation
-- poll knows which orders are settled at PayU and stops asking about them.
-- New nullable columns only; no existing row is changed (M22).

-- Up Migration
ALTER TABLE orders
  ADD COLUMN gateway_status TEXT,
  ADD COLUMN gateway_checked_at TIMESTAMPTZ;

-- The poll looks for recent PayU orders that are pending or expired.
CREATE INDEX orders_reconcile_idx ON orders (created_at) WHERE payment_method = 'payu' AND status IN ('pending', 'expired');

-- Down Migration
DROP INDEX orders_reconcile_idx;
ALTER TABLE orders DROP COLUMN gateway_checked_at, DROP COLUMN gateway_status;
