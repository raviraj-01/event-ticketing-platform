-- H6 (part 1): who did what in the admin panel. Append-only.

-- Up Migration
CREATE TABLE admin_audit_log (
  id BIGSERIAL PRIMARY KEY,
  admin_type TEXT,               -- 'admin' | 'super' | NULL (failed login)
  admin_id TEXT,
  admin_email TEXT,
  action TEXT NOT NULL,          -- e.g. 'login.success', 'creator.status'
  target_type TEXT,
  target_id TEXT,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  ip TEXT,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX admin_audit_log_created_idx ON admin_audit_log (created_at DESC);
CREATE INDEX admin_audit_log_admin_idx ON admin_audit_log (admin_type, admin_id);

-- Down Migration
DROP TABLE admin_audit_log;
