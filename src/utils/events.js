// Rules about whether an event can still sell tickets.

const EVENT_AVAILABLE_STATUSES = new Set(["live", "upcoming"]);

// Status set by the creator/admin: only live or upcoming events sell.
const isEventBookable = (status) =>
  EVENT_AVAILABLE_STATUSES.has(String(status || "").trim().toLowerCase());

// Sales close after the event day (event_date is stored as YYYY-MM-DD text).
const eventSalesClosed = (event) => {
  const value = String((event && event.event_date) || "").trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const eventDate = new Date(`${value}T23:59:59.999Z`);
  return Number.isFinite(eventDate.getTime()) && eventDate < new Date();
};

module.exports = { isEventBookable, eventSalesClosed };
