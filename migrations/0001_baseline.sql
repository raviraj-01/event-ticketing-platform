-- Baseline schema: the exact CREATE TABLE / ALTER TABLE statements that
-- server.js used to run on every startup (initDb), moved here unchanged.
-- Every statement uses IF NOT EXISTS, so this is safe on a fresh database and
-- on a database that the old startup code already created.

-- Up Migration
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS first_name TEXT,
  ADD COLUMN IF NOT EXISTS last_name TEXT,
  ADD COLUMN IF NOT EXISTS phone TEXT,
  ADD COLUMN IF NOT EXISTS country_code TEXT,
  ADD COLUMN IF NOT EXISTS city TEXT,
  ADD COLUMN IF NOT EXISTS profile_image_url TEXT,
  ADD COLUMN IF NOT EXISTS profile_image_key TEXT,
  ADD COLUMN IF NOT EXISTS profile_image_storage TEXT,
  ADD COLUMN IF NOT EXISTS auth_provider TEXT DEFAULT 'email',
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'Active';

CREATE TABLE IF NOT EXISTS bookings (
  id TEXT PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  buyer_email TEXT,
  event_id TEXT,
  event_name TEXT,
  event_date TEXT,
  event_venue TEXT,
  event_banner TEXT,
  ticket_type TEXT,
  price NUMERIC,
  qty INTEGER,
  total NUMERIC,
  status TEXT DEFAULT 'upcoming',
  ticket_record_url TEXT,
  ticket_record_key TEXT,
  ticket_record_storage TEXT,
  booked_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE bookings
  ADD COLUMN IF NOT EXISTS buyer_name TEXT,
  ADD COLUMN IF NOT EXISTS qr_token TEXT,
  ADD COLUMN IF NOT EXISTS scanned_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS staff_id TEXT,
  ADD COLUMN IF NOT EXISTS staff_ref TEXT;

CREATE TABLE IF NOT EXISTS creator_accounts (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  phone TEXT NOT NULL,
  category TEXT NOT NULL,
  about TEXT NOT NULL,
  password TEXT NOT NULL,
  kyc_status TEXT NOT NULL DEFAULT 'Pending',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE creator_accounts
  ADD COLUMN IF NOT EXISTS finance_pin TEXT;

CREATE TABLE IF NOT EXISTS creator_kyc_documents (
  id SERIAL PRIMARY KEY,
  creator_id INTEGER NOT NULL REFERENCES creator_accounts(id) ON DELETE CASCADE,
  document_type TEXT NOT NULL,
  file_name TEXT NOT NULL,
  object_key TEXT NOT NULL,
  storage TEXT NOT NULL,
  content_type TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE creator_kyc_documents
  ADD COLUMN IF NOT EXISTS verification_status TEXT NOT NULL DEFAULT 'Pending',
  ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS verified_by TEXT;

CREATE TABLE IF NOT EXISTS creator_events (
  id TEXT PRIMARY KEY,
  creator_id INTEGER NOT NULL REFERENCES creator_accounts(id) ON DELETE CASCADE,
  creator_name TEXT NOT NULL,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  description TEXT NOT NULL,
  event_date TEXT NOT NULL,
  start_time TEXT NOT NULL,
  end_time TEXT,
  venue TEXT NOT NULL,
  city TEXT NOT NULL,
  capacity INTEGER NOT NULL,
  latitude NUMERIC,
  longitude NUMERIC,
  banner_url TEXT NOT NULL,
  banner_key TEXT NOT NULL,
  visibility TEXT NOT NULL DEFAULT 'Public',
  status TEXT NOT NULL DEFAULT 'live',
  tickets JSONB NOT NULL DEFAULT '[]'::jsonb,
  booking_count INTEGER NOT NULL DEFAULT 0,
  revenue NUMERIC NOT NULL DEFAULT 0,
  checkins INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS admin_accounts (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'Admin',
  status TEXT NOT NULL DEFAULT 'Active',
  last_login TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS super_admin_accounts (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Active',
  last_login TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS staff_accounts (
  id TEXT PRIMARY KEY,
  creator_id INTEGER REFERENCES creator_accounts(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  staff_id TEXT UNIQUE NOT NULL,
  email TEXT,
  phone TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  assigned_tickets INTEGER NOT NULL DEFAULT 0,
  sold_tickets INTEGER NOT NULL DEFAULT 0,
  earnings NUMERIC NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE staff_accounts
  ADD COLUMN IF NOT EXISTS password TEXT,
  ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'Scanner',
  ADD COLUMN IF NOT EXISTS assigned_gate TEXT,
  ADD COLUMN IF NOT EXISTS primary_event_id TEXT,
  ADD COLUMN IF NOT EXISTS share_token TEXT UNIQUE,
  ADD COLUMN IF NOT EXISTS created_by_admin_email TEXT;

CREATE TABLE IF NOT EXISTS staff_assignments (
  id TEXT PRIMARY KEY,
  creator_id INTEGER NOT NULL REFERENCES creator_accounts(id) ON DELETE CASCADE,
  staff_id TEXT NOT NULL REFERENCES staff_accounts(id) ON DELETE CASCADE,
  event_id TEXT NOT NULL REFERENCES creator_events(id) ON DELETE CASCADE,
  event_name TEXT NOT NULL,
  tier_name TEXT NOT NULL,
  qty INTEGER NOT NULL,
  sold_count INTEGER NOT NULL DEFAULT 0,
  price NUMERIC NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE staff_assignments
  ADD COLUMN IF NOT EXISTS allocation_mode TEXT NOT NULL DEFAULT 'creator_quota',
  ADD COLUMN IF NOT EXISTS commission_rate NUMERIC NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS purchase_price NUMERIC NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS resale_price NUMERIC NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS staff_sales (
  id TEXT PRIMARY KEY,
  creator_id INTEGER NOT NULL REFERENCES creator_accounts(id) ON DELETE CASCADE,
  staff_id TEXT NOT NULL REFERENCES staff_accounts(id) ON DELETE CASCADE,
  assignment_id TEXT REFERENCES staff_assignments(id) ON DELETE SET NULL,
  event_id TEXT NOT NULL REFERENCES creator_events(id) ON DELETE CASCADE,
  event_name TEXT NOT NULL,
  tier_name TEXT NOT NULL,
  buyer_name TEXT,
  buyer_phone TEXT,
  buyer_email TEXT,
  qty INTEGER NOT NULL DEFAULT 1,
  price NUMERIC NOT NULL DEFAULT 0,
  total NUMERIC NOT NULL DEFAULT 0,
  payment_mode TEXT NOT NULL DEFAULT 'cash',
  booking_id TEXT REFERENCES bookings(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE staff_sales
  ADD COLUMN IF NOT EXISTS commission NUMERIC NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS revenue_owner TEXT NOT NULL DEFAULT 'staff',
  ADD COLUMN IF NOT EXISTS allocation_mode TEXT NOT NULL DEFAULT 'creator_quota';

CREATE TABLE IF NOT EXISTS staff_withdrawals (
  id TEXT PRIMARY KEY,
  creator_id INTEGER NOT NULL REFERENCES creator_accounts(id) ON DELETE CASCADE,
  staff_id TEXT NOT NULL REFERENCES staff_accounts(id) ON DELETE CASCADE,
  amount NUMERIC NOT NULL,
  method TEXT NOT NULL DEFAULT 'upi',
  bank_account_name TEXT,
  bank_account_number TEXT,
  bank_ifsc TEXT,
  upi_id TEXT,
  status TEXT NOT NULL DEFAULT 'Pending',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS payment_transactions (
  txnid TEXT PRIMARY KEY,
  booking_id TEXT,
  event_id TEXT,
  ticket_type TEXT,
  qty INTEGER,
  buyer_email TEXT,
  amount NUMERIC NOT NULL DEFAULT 0,
  gateway_payment_id TEXT,
  status TEXT NOT NULL DEFAULT 'Pending',
  verified BOOLEAN NOT NULL DEFAULT FALSE,
  error TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Down Migration
-- Irreversible: the baseline is the starting point.
