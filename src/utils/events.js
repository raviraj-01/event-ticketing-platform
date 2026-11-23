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

// L5: checks for a new event, before it is saved. Returns a message for the
// organizer, or null. Pure (no database), so it is easy to test.
const EVENT_LIMITS = { maxCapacity: 100000, maxTiers: 20, maxPrice: 1000000 };
const VISIBILITIES = ["Public", "Private", "Invite Only"];
// "19:00" or "7:30 PM" (the app sends "07:30 PM").
const TIME_RE = /^(([01]?\d|2[0-3]):[0-5]\d|(0?[1-9]|1[0-2]):[0-5]\d ?[AaPp][Mm])$/;

function todayInIndia(now = new Date()) {
  return new Date(now.getTime() + 330 * 60 * 1000).toISOString().slice(0, 10);
}

function isRealDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00Z`);
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

function eventInputProblem(input, { creatorId, now } = {}) {
  const text = (v) => String(v == null ? "" : v).trim();
  const tooLong = [["name", 120], ["category", 60], ["venue", 200], ["city", 100], ["description", 5000]]
    .find(([field, max]) => text(input[field]).length > max);
  if (tooLong) return `The ${tooLong[0]} is too long (at most ${tooLong[1]} characters)`;

  const date = text(input.date);
  if (!isRealDate(date)) return "Pick a valid event date";
  if (date < todayInIndia(now)) return "The event date is in the past";
  if (!TIME_RE.test(text(input.time))) return "Enter a valid start time";
  if (text(input.endTime) && !TIME_RE.test(text(input.endTime))) return "Enter a valid end time";

  const capacity = Number(input.capacity);
  if (!Number.isInteger(capacity) || capacity < 1 || capacity > EVENT_LIMITS.maxCapacity) {
    return `Capacity must be a whole number from 1 to ${EVENT_LIMITS.maxCapacity}`;
  }
  for (const [field, limit] of [["latitude", 90], ["longitude", 180]]) {
    const value = input[field];
    if (value === undefined || value === null || value === "") continue;
    const n = Number(value);
    if (!Number.isFinite(n) || Math.abs(n) > limit) return `The ${field} is not valid`;
  }

  const visibility = text(input.visibility) || "Public";
  if (!VISIBILITIES.includes(visibility)) return `Visibility must be one of: ${VISIBILITIES.join(", ")}`;

  // The banner must be one this organizer uploaded (POST /creator/events/banner),
  // served from our own media routes: no outside or javascript: URLs.
  const bannerKey = text(input.bannerKey);
  const banner = text(input.banner);
  if (creatorId !== undefined && !bannerKey.startsWith(`event-banners/creator-${creatorId}/`)) {
    return "Upload the event banner again";
  }
  if (!/^\/(r2\/media|uploads)\/event-banners(\/|%2F)/i.test(banner)) return "Upload the event banner again";

  const tiers = Array.isArray(input.tickets) ? input.tickets : [];
  if (!tiers.length) return "Add at least one ticket tier";
  if (tiers.length > EVENT_LIMITS.maxTiers) return `At most ${EVENT_LIMITS.maxTiers} ticket tiers`;
  const names = new Set();
  let total = 0;
  for (const tier of tiers) {
    const name = text(tier.name);
    const price = Number(tier.price);
    const qty = Number(tier.qty);
    if (!name || name.length > 60) return "Each ticket tier needs a name (at most 60 characters)";
    if (names.has(name.toLowerCase())) return `Two ticket tiers are both called "${name}"`;
    names.add(name.toLowerCase());
    if (!Number.isFinite(price) || price < 0 || price > EVENT_LIMITS.maxPrice) return `The price for "${name}" is not valid`;
    if (!Number.isInteger(qty) || qty < 1) return `The quantity for "${name}" must be a whole number of at least 1`;
    total += qty;
  }
  if (total > capacity) return `The ticket tiers add up to ${total}, more than the capacity of ${capacity}`;
  return null;
}

module.exports = { isEventBookable, eventSalesClosed, eventInputProblem, todayInIndia };
