-- M2: indexes for the lookups the routes actually run (until now only primary
-- keys, UNIQUE columns and the indexes added with orders/sessions/audit existed,
-- so every dashboard query scanned whole tables).
-- Plain CREATE INDEX briefly blocks writes on each table while it builds; fine
-- at the current data size. On a big live table use CREATE INDEX CONCURRENTLY
-- in its own (non-transactional) migration instead.

-- Up Migration

-- Bookings: per event (analytics, scan, recounts), a buyer's tickets, and the
-- admin snapshot's legacy guest match by email.
CREATE INDEX bookings_event_idx ON bookings (event_id);
CREATE INDEX bookings_user_booked_idx ON bookings (user_id, booked_at DESC);
CREATE INDEX bookings_buyer_email_lower_idx ON bookings (LOWER(buyer_email));

-- Events by creator (creator dashboard, analytics) and the public listing.
CREATE INDEX creator_events_creator_idx ON creator_events (creator_id);
CREATE INDEX creator_events_status_idx ON creator_events (status);

-- Staff: assignments per staff member and event, per creator; sales and
-- withdrawals per staff member; sales per booking; staff per creator.
CREATE INDEX staff_assignments_staff_event_idx ON staff_assignments (staff_id, event_id);
CREATE INDEX staff_assignments_creator_idx ON staff_assignments (creator_id);
CREATE INDEX staff_sales_staff_idx ON staff_sales (staff_id);
CREATE INDEX staff_sales_booking_idx ON staff_sales (booking_id);
CREATE INDEX staff_withdrawals_staff_idx ON staff_withdrawals (staff_id);
CREATE INDEX staff_accounts_creator_idx ON staff_accounts (creator_id);

-- KYC documents per creator; payment records per order (booking_id holds the order id).
CREATE INDEX creator_kyc_documents_creator_idx ON creator_kyc_documents (creator_id);
CREATE INDEX payment_transactions_booking_idx ON payment_transactions (booking_id);

-- Logins and resets look accounts up with LOWER(email); the UNIQUE(email)
-- index can't serve that, an expression index can.
CREATE INDEX users_email_lower_idx ON users (LOWER(email));
CREATE INDEX creator_accounts_email_lower_idx ON creator_accounts (LOWER(email));
CREATE INDEX admin_accounts_email_lower_idx ON admin_accounts (LOWER(email));
CREATE INDEX super_admin_accounts_email_lower_idx ON super_admin_accounts (LOWER(email));
CREATE INDEX staff_accounts_email_lower_idx ON staff_accounts (LOWER(email));

-- Housekeeping: expiring unpaid holds.
CREATE INDEX orders_pending_expiry_idx ON orders (expires_at) WHERE status = 'pending';

-- Down Migration
DROP INDEX orders_pending_expiry_idx;
DROP INDEX staff_accounts_email_lower_idx;
DROP INDEX super_admin_accounts_email_lower_idx;
DROP INDEX admin_accounts_email_lower_idx;
DROP INDEX creator_accounts_email_lower_idx;
DROP INDEX users_email_lower_idx;
DROP INDEX payment_transactions_booking_idx;
DROP INDEX creator_kyc_documents_creator_idx;
DROP INDEX staff_accounts_creator_idx;
DROP INDEX staff_withdrawals_staff_idx;
DROP INDEX staff_sales_booking_idx;
DROP INDEX staff_sales_staff_idx;
DROP INDEX staff_assignments_creator_idx;
DROP INDEX staff_assignments_staff_event_idx;
DROP INDEX creator_events_status_idx;
DROP INDEX creator_events_creator_idx;
DROP INDEX bookings_buyer_email_lower_idx;
DROP INDEX bookings_user_booked_idx;
DROP INDEX bookings_event_idx;
