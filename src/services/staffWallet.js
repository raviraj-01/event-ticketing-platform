// Staff money (H10, decision D4).
//
//   commissionEarned = commission on active sales (cash, online, referrals)
//   availableBalance = commissionEarned - withdrawals that were not rejected
//                      -> the ONLY money a staff member can withdraw
//   cashCollected    = cash taken from buyers in creator-quota sales; it
//                      belongs to the organizer
//   cashOwed         = cashCollected - cash the organizer recorded as received
//
// Staff-owned resale (staff bought the tickets) is neither withdrawable nor
// owed: the staff member keeps that money (open question Q5b).
//
// Withdrawals and settlements lock the staff row (SELECT ... FOR UPDATE) and
// recompute the numbers inside the same transaction, so parallel requests
// cannot both spend the same balance.
const crypto = require("crypto");

class WalletError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const roundMoney = (value) => Math.round(Number(value) * 100) / 100;

// db can be the pool or a client inside a transaction.
async function staffWallet(db, staffId) {
  const sales = await db.query(
    `SELECT
       COALESCE(SUM(commission), 0)::NUMERIC AS commission_earned,
       COALESCE(SUM(CASE WHEN payment_mode = 'online' THEN total ELSE 0 END), 0)::NUMERIC AS online_sales,
       COALESCE(SUM(CASE WHEN payment_mode = 'cash' THEN total ELSE 0 END), 0)::NUMERIC AS cash_sales,
       COALESCE(SUM(CASE WHEN payment_mode = 'cash' AND revenue_owner = 'creator' THEN total ELSE 0 END), 0)::NUMERIC AS cash_collected,
       COALESCE(SUM(qty), 0)::INTEGER AS tickets_sold
     FROM staff_sales
     WHERE staff_id = $1 AND status = 'active'`,
    [staffId],
  );
  const withdrawals = await db.query(
    "SELECT COALESCE(SUM(amount), 0)::NUMERIC AS withdrawn FROM staff_withdrawals WHERE staff_id = $1 AND status <> 'Rejected'",
    [staffId],
  );
  const settlements = await db.query(
    "SELECT COALESCE(SUM(amount), 0)::NUMERIC AS settled FROM staff_cash_settlements WHERE staff_id = $1",
    [staffId],
  );
  const row = sales.rows[0];
  const commissionEarned = roundMoney(row.commission_earned);
  const withdrawn = roundMoney(withdrawals.rows[0].withdrawn);
  const cashCollected = roundMoney(row.cash_collected);
  const cashSettled = roundMoney(settlements.rows[0].settled);
  return {
    commissionEarned,
    totalEarned: commissionEarned, // kept for the existing wallet screen
    withdrawn,
    availableBalance: Math.max(0, roundMoney(commissionEarned - withdrawn)),
    onlineRevenue: roundMoney(row.online_sales), // sales value, informational
    cashRevenue: roundMoney(row.cash_sales), // sales value, informational
    cashCollected,
    cashSettled,
    cashOwed: Math.max(0, roundMoney(cashCollected - cashSettled)),
    ticketsSold: Number(row.tickets_sold || 0),
  };
}

function cleanAmount(value) {
  const amount = roundMoney(value);
  if (!Number.isFinite(amount) || amount <= 0) throw new WalletError(400, "Enter a valid amount");
  return amount;
}

// POST /staff/withdrawals
async function requestWithdrawal(pool, staffId, { amount, method, bankAccountName, bankAccountNumber, bankIfsc, upiId }) {
  const cleanValue = cleanAmount(amount);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    // The row lock makes concurrent withdrawals for this staff member wait
    // here, so each one sees the balance after the previous one.
    const staff = await client.query(
      "SELECT id, creator_id FROM staff_accounts WHERE id = $1 AND status = 'active' FOR UPDATE",
      [staffId],
    );
    if (!staff.rows.length) throw new WalletError(404, "Staff account not found");
    const wallet = await staffWallet(client, staffId);
    if (cleanValue > wallet.availableBalance) throw new WalletError(400, "Amount exceeds available balance");
    const inserted = await client.query(
      `INSERT INTO staff_withdrawals (
         id, creator_id, staff_id, amount, method, bank_account_name, bank_account_number, bank_ifsc, upi_id
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       RETURNING *`,
      [
        `WD-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`,
        staff.rows[0].creator_id,
        staffId,
        cleanValue,
        method,
        bankAccountName || null,
        bankAccountNumber || null,
        bankIfsc || null,
        upiId || null,
      ],
    );
    const after = await staffWallet(client, staffId);
    await client.query("COMMIT");
    return { withdrawal: inserted.rows[0], wallet: after };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// POST /creator/staff/:staffId/cash-settlements: the organizer records cash
// the staff member handed over.
async function recordCashSettlement(pool, creatorId, staffId, { amount, note }) {
  const cleanValue = cleanAmount(amount);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const staff = await client.query(
      "SELECT id FROM staff_accounts WHERE id = $1 AND creator_id = $2 FOR UPDATE",
      [staffId, creatorId],
    );
    if (!staff.rows.length) throw new WalletError(404, "Staff member not found");
    const wallet = await staffWallet(client, staffId);
    if (cleanValue > wallet.cashOwed) throw new WalletError(400, "Amount is more than the cash this staff member owes");
    await client.query(
      "INSERT INTO staff_cash_settlements (id, creator_id, staff_id, amount, note) VALUES ($1,$2,$3,$4,$5)",
      [`CS-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`, creatorId, staffId, cleanValue, String(note || "").slice(0, 200) || null],
    );
    const after = await staffWallet(client, staffId);
    await client.query("COMMIT");
    return after;
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { WalletError, staffWallet, requestWithdrawal, recordCashSettlement };
