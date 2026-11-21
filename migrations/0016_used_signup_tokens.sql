-- M17: a signup verification token (issued after the phone OTP) works once.
-- Its unique id (jti) is recorded here in the same transaction that creates the
-- account; a second signup with the same token finds the id and is refused.
-- Rows are only needed while the token is still valid (10 minutes); the
-- housekeeping timer deletes rows older than a day.

-- Up Migration
CREATE TABLE used_signup_tokens (
  jti TEXT PRIMARY KEY,
  used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Down Migration
DROP TABLE used_signup_tokens;
