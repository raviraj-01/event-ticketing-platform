-- Q6 / D20: new events wait for an admin before buyers can see or book them.
-- Existing events keep their current status (no data is changed).

-- Up Migration
ALTER TABLE creator_events ALTER COLUMN status SET DEFAULT 'pending';
-- Why an admin rejected the event; shown to the creator.
ALTER TABLE creator_events ADD COLUMN review_note TEXT;

-- Down Migration
ALTER TABLE creator_events DROP COLUMN review_note;
ALTER TABLE creator_events ALTER COLUMN status SET DEFAULT 'live';
