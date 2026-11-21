-- C4: server-side orders. The server decides price and inventory; a booking
-- (ticket) is issued only for a free order or after a verified PayU callback.

-- Up Migration

-- One row per checkout attempt.
--   pending           : PayU checkout started, seats held until expires_at (15 min)
--   paid              : payment verified (or free tier); exactly one booking issued
--   expired           : hold ran out or payment failed; seats released
--   paid_needs_refund : PayU confirmed a payment after the hold expired and the
--                       seats were gone; no ticket issued, admin must refund
CREATE TABLE orders (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  event_id TEXT NOT NULL REFERENCES creator_events(id),
  tier_name TEXT NOT NULL,
  qty INTEGER NOT NULL CHECK (qty > 0),
  unit_price NUMERIC(12,2) NOT NULL CHECK (unit_price >= 0),
  subtotal NUMERIC(12,2) NOT NULL CHECK (subtotal >= 0),
  platform_fee NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (platform_fee >= 0),
  gst NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (gst >= 0),
  amount NUMERIC(12,2) NOT NULL CHECK (amount >= 0),
  status TEXT NOT NULL CHECK (status IN ('pending', 'paid', 'expired', 'paid_needs_refund')),
  payment_method TEXT NOT NULL CHECK (payment_method IN ('payu', 'free')),
  txnid TEXT UNIQUE,
  gateway_payment_id TEXT,
  referral_staff_id TEXT REFERENCES staff_accounts(id) ON DELETE SET NULL,
  expires_at TIMESTAMPTZ,
  paid_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (payment_method <> 'payu' OR txnid IS NOT NULL)
);

CREATE INDEX orders_event_status_idx ON orders (event_id, status);
CREATE INDEX orders_user_event_idx ON orders (user_id, event_id);

-- A booking issued from an order. The unique index makes ticket issuing
-- idempotent: a retried PayU callback can never create a second ticket.
ALTER TABLE bookings ADD COLUMN order_id TEXT REFERENCES orders(id);
CREATE UNIQUE INDEX bookings_order_id_key ON bookings (order_id) WHERE order_id IS NOT NULL;

-- Staff commission rows are reversed by status (never deleted), e.g. on refund.
ALTER TABLE staff_sales
  ADD COLUMN status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'reversed')),
  ADD COLUMN order_id TEXT REFERENCES orders(id);
CREATE UNIQUE INDEX staff_sales_order_id_key ON staff_sales (order_id) WHERE order_id IS NOT NULL;

-- Fixed-window rate limiting shared by all server instances.
CREATE TABLE rate_limit_hits (
  bucket TEXT NOT NULL,
  window_start TIMESTAMPTZ NOT NULL,
  hits INTEGER NOT NULL,
  PRIMARY KEY (bucket, window_start)
);

-- Down Migration
DROP TABLE rate_limit_hits;
DROP INDEX staff_sales_order_id_key;
ALTER TABLE staff_sales DROP COLUMN order_id, DROP COLUMN status;
DROP INDEX bookings_order_id_key;
ALTER TABLE bookings DROP COLUMN order_id;
DROP TABLE orders;
