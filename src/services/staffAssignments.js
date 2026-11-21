// Allocate tier inventory to a staff member inside the caller's transaction
// (locks the event row so two allocations can't oversell a tier).
const crypto = require("crypto");
const { HttpError } = require("../utils/httpError");

const createStaffAssignment = async (
  client,
  {
    creatorId,
    staffId,
    eventId,
    tierName,
    qty,
    allocationMode,
    mode,
    commissionRate,
    purchasePrice,
    resalePrice,
  },
) => {
  const cleanQty = Number(qty);
  if (!Number.isInteger(cleanQty) || cleanQty < 1)
    throw new HttpError(400, "Enter a valid ticket quantity");
  // Q5b: staff resale ("staff_owned") is out of scope for now; only
  // commission-based selling for the creator is allowed.
  if (String(allocationMode || mode || "creator_quota") === "staff_owned") {
    throw new HttpError(400, "Staff resale is not available yet");
  }
  const cleanMode = "creator_quota";
  const cleanCommissionRate = Math.max(0, Number(commissionRate || 0));
  const staff = await client.query(
    "SELECT id FROM staff_accounts WHERE id=$1 AND creator_id=$2",
    [staffId, creatorId],
  );
  if (!staff.rows.length) throw new HttpError(400, "Staff member not found");
  const event = await client.query(
    "SELECT * FROM creator_events WHERE id=$1 AND creator_id=$2 FOR UPDATE",
    [eventId, creatorId],
  );
  if (!event.rows.length) throw new HttpError(400, "Creator event not found");
  const tickets = Array.isArray(event.rows[0].tickets)
    ? event.rows[0].tickets
    : [];
  const tier = tickets.find((ticket) => ticket.name === tierName);
  if (!tier) throw new HttpError(400, "Ticket tier not found");
  if (Number(tier.qty || 0) < cleanQty)
    throw new HttpError(400, "Not enough tickets available");
  const basePrice = Number(tier.price || 0);
  const cleanPurchasePrice =
    Number.isFinite(Number(purchasePrice)) && Number(purchasePrice) >= 0
      ? Number(purchasePrice)
      : basePrice;
  const cleanResalePrice =
    Number.isFinite(Number(resalePrice)) && Number(resalePrice) >= 0
      ? Number(resalePrice)
      : basePrice;
  tier.qty = Number(tier.qty || 0) - cleanQty;
  await client.query("UPDATE creator_events SET tickets=$1 WHERE id=$2", [
    JSON.stringify(tickets),
    eventId,
  ]);
  await client.query(
    "UPDATE staff_accounts SET assigned_tickets=assigned_tickets+$1, primary_event_id=COALESCE(primary_event_id,$3) WHERE id=$2",
    [cleanQty, staffId, eventId],
  );
  const id = `ASN-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
  const result = await client.query(
    `INSERT INTO staff_assignments (
       id, creator_id, staff_id, event_id, event_name, tier_name, qty, price,
       allocation_mode, commission_rate, purchase_price, resale_price
     )
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
     RETURNING *`,
    [
      id,
      creatorId,
      staffId,
      eventId,
      event.rows[0].name,
      tierName,
      cleanQty,
      basePrice,
      cleanMode,
      cleanCommissionRate,
      cleanPurchasePrice,
      cleanResalePrice,
    ],
  );
  if (cleanMode === "staff_owned") {
    await client.query(
      "UPDATE creator_events SET revenue=COALESCE(revenue,0)+$1 WHERE id=$2",
      [cleanPurchasePrice * cleanQty, eventId],
    );
  }
  return result.rows[0];
};

module.exports = { createStaffAssignment };
