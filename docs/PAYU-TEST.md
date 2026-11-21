# PayU test-mode checkout — test plan

Goal: one real round trip through PayU's **test** environment, proving that the
server-side order flow (C4) works with the real gateway, not only with the
signed callbacks the automated tests generate.

## 1. Setup (Ravi)

1. In the PayU dashboard switch to **Test mode** and copy the test **merchant key** and **salt**.
2. In `.env` (never commit it):
   ```
   PAYU_KEY=<test key>
   PAYU_SALT=<test salt>
   PAYU_ENV=test
   APP_BASE_URL=http://localhost:3003
   ```
   `localhost` is fine: PayU sends the buyer's **browser** back to `APP_BASE_URL/payments/payu/success`, it does not call the server directly.
3. For the buyer signup OTP without Twilio, local development returns the code on screen.
4. `npm start`, open http://localhost:3003.

## 2. Data

- An approved organizer with one **live** event that has a **paid** tier (e.g. ₹100) and a capacity of 2.
- A buyer account.
(Organizer approval needs KYC documents in R2; if R2 is not set up yet, Claude can seed the organizer and event directly in the dev database.)

## 3. Happy path

| # | Step | Expected |
|---|---|---|
| 1 | Logged out, open the event, pick the paid tier, press Pay | Sent to login; after login you are back on the same event and tier |
| 2 | Press "Pay via PayU" | Browser goes to `test.payu.in`; the amount equals price × qty + 8% fee + 18% GST on the fee (₹100 → ₹109.44) |
| 3 | Pay with one of the **test cards / test UPI** listed in PayU's test-mode documentation | PayU success page, then back to the app |
| 4 | App after return | "Booking Confirmed!" with a QR code; URL shows no order data anymore |
| 5 | Profile → My tickets | The ticket is listed |
| 6 | Admin → Payments | The transaction shows **Success** |
| 7 | DB check (Claude) | `orders.status = 'paid'`, exactly one `bookings` row with that `order_id`, `payment_transactions.verified = true` |

## 4. Failure and edge cases

| # | Step | Expected |
|---|---|---|
| 8 | Start a payment, then cancel / choose failure on the PayU page | Back in the app: "Payment failed or was cancelled"; `orders.status = 'expired'`; the seat is free again |
| 9 | Start a payment and wait > 15 minutes before paying | If seats are still free: ticket issued. If another buyer took the last seat meanwhile: "tickets sold out… full refund", order `paid_needs_refund`, listed in Admin → Payments → Refunds |
| 10 | Reload the success page / press back | No second ticket (idempotent callback) |
| 11 | Server log | No "PayU callback rejected: bad key or hash" for genuine payments. If it appears, PayU sent a field we do not hash yet (e.g. `additionalCharges` is handled; report anything else) |

## 5. What to send back

The order ID, the PayU transaction ID (`mihpayid`) and whether each row above passed.
Claude then records the result in CLAUDE.md and ticks the acceptance item.
