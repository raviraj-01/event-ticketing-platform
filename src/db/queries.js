// SQL fragments shared by several route files.
const creatorEventSalesQuery = `
  SELECT e.*,
    COALESCE(SUM(CASE WHEN b.status <> 'refunded' THEN b.qty ELSE 0 END),0)::INTEGER AS booking_count,
    COALESCE(SUM(CASE WHEN b.status <> 'refunded' THEN b.total ELSE 0 END),0)::NUMERIC AS revenue
  FROM creator_events e
  LEFT JOIN bookings b ON b.event_id=e.id
`;

module.exports = { creatorEventSalesQuery };
