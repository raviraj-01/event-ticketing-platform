# Android device test — checklist

Run on a real Android phone (Android 10+), ideally one with a **screen lock**
set (the secure storage plugin needs it). Tick each line; note the phone
model and Android version.

## 0. Build

1. Backend reachable from the phone over **https** (your Render deploy). A
   local backend through a tunnel also works, but its origin must be added to
   `vybera-cordova/config.xml` `<access origin="…">` first (the build checks this).
2. `CORDOVA_API_BASE=https://<your-backend> npm run build:cordova`
3. `cd vybera-cordova && npx cordova prepare android && npx cordova build android`
4. Google sign-in in the app needs an **Android OAuth client** for the app's
   signing SHA-1, and the **web** client ID must equal the server's `GOOGLE_CLIENT_ID`.
5. Install the APK (`adb install -r …apk`).

## 1. Start and browse
- [ ] App opens, splash then home; black/grey app palette (not the web's brick red)
- [ ] Events load; images and map tiles load
- [ ] Android back button closes open dialogs first, then navigates back, and does not exit unexpectedly

## 2. Accounts and sessions (H5)
- [ ] Buyer signup with phone OTP
- [ ] Buyer login; close the app completely, reopen → still logged in
- [ ] Leave the app idle > 15 minutes, use it again → still works (automatic refresh)
- [ ] Logout → reopening shows logged out
- [ ] Organizer, Staff and Admin login via the role switch (admin: emailed code step)
- [ ] Google sign-in (native account picker) → logged in as buyer
- [ ] Phone without a screen lock: login still works (falls back to normal storage); note it

## 3. Checkout (C4)
- [ ] Logged-out "Book" → login → back on the same event
- [ ] Free tier: confirmed instantly, QR shown
- [ ] Paid tier: PayU opens inside the app (in-app browser), pay with a test card, returns to the app with the ticket
- [ ] Cancel on the PayU page → back in the app, "Payment failed or was cancelled"

## 4. Staff and scanning
- [ ] Staff dashboard loads; wallet shows Commission earned / Cash owed
- [ ] Scanner: camera permission prompt, camera opens, scanning a valid ticket → VALID; same ticket again → duplicate
- [ ] Ticket for another event → "not assigned to this event"

## 5. Security checks
- [ ] Links to outside sites open the system browser, not inside the app
- [ ] Forced password change: organizer resets a staff password → staff logs in on the phone → must choose a new one first
- [ ] Admin KYC document links: known limitation — they may not open in the app (web admin panel works)

## 6. Report
Phone model, Android version, APK build time, and every unticked line with what happened (a screenshot helps).
