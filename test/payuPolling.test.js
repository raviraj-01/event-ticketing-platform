// PayU in its own window: the waiting tab's polling decisions (pure function
// taken from public/index.html) and the rules that keep the buyer's tab on our site.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const html = fs.readFileSync(path.join(__dirname, "..", "public", "index.html"), "utf8").replace(/\r\n/g, "\n");
const source = html.slice(html.indexOf("// BEGIN payuPollDecision"), html.indexOf("// END payuPollDecision"));
const sandbox = {};
vm.runInNewContext(`${source}\nthis.payuPollDecision = payuPollDecision;`, sandbox);
const decide = sandbox.payuPollDecision;

const ctx = (extra = {}) => ({ windowClosed: false, timedOut: false, cancelled: false, finalAttempts: 0, maxFinalAttempts: 5, ...extra });
const answer = (status, extra = {}) => ({ order: { id: "ORD-1", status }, booking: null, checkedWithPayu: false, ...extra });

test("polling: final order states end the wait, whatever the window is doing", () => {
  const paid = answer("paid", { booking: { id: "BKG-1" } });
  assert.equal(decide(paid, ctx()), "paid");
  assert.equal(decide(paid, ctx({ windowClosed: true })), "paid", "paid wins over a closed window");
  assert.equal(decide(answer("paid_needs_refund"), ctx()), "refund");
  assert.equal(decide(answer("expired"), ctx()), "not_completed", "failed / cancelled at PayU");
  assert.equal(decide(answer("paid"), ctx()), "keep_waiting", "paid without the ticket yet: next poll");
});

test("polling: a pending order keeps waiting while the PayU window is open", () => {
  assert.equal(decide(answer("pending"), ctx()), "keep_waiting");
  assert.equal(decide(answer("pending", { checkedWithPayu: true }), ctx()), "keep_waiting");
  assert.equal(decide(null, ctx()), "keep_waiting", "a failed call (network, 429) is retried");
});

test("polling: window closed, Cancel or 15 minutes -> one more real PayU check, then 'not completed'", () => {
  for (const reason of ["windowClosed", "cancelled", "timedOut"]) {
    // The throttled answer did not ask PayU: ask again (next tick), a few times at most.
    assert.equal(decide(answer("pending"), ctx({ [reason]: true })), "check_again", reason);
    assert.equal(decide(null, ctx({ [reason]: true, finalAttempts: 2 })), "check_again", reason);
    // PayU was asked and still no payment: stop.
    assert.equal(decide(answer("pending", { checkedWithPayu: true }), ctx({ [reason]: true })), "not_completed", reason);
    // Never loops forever.
    assert.equal(decide(answer("pending"), ctx({ [reason]: true, finalAttempts: 5 })), "not_completed", reason);
    // ...but a payment that arrives during the last check still wins.
    assert.equal(decide(answer("paid", { booking: { id: "B" } }), ctx({ [reason]: true, finalAttempts: 5 })), "paid", reason);
  }
});

test("popup checkout: the window opens before any await in the click, blocked -> full redirect", () => {
  const body = html.slice(html.indexOf("async function payWithPayU(){"), html.indexOf("// Show a ticket the server has confirmed."));
  const opened = body.indexOf("var payuWin=isPaidTier?openPayuWindow():null;");
  assert.ok(opened > 0);
  assert.ok(opened < body.indexOf("await "), "window.open must run synchronously in the click handler");
  assert.match(body, /if\(payuWin&&!payuWin\.closed\)\{\s*submitPayUForm\(data\.payment\.action, data\.payment\.fields, PAYU_WINDOW_NAME\);[^]*?waitForPayuWindow\(data\.order, payuWin\);\s*return;\s*\}[^]*?submitPayUForm\(data\.payment\.action, data\.payment\.fields\);/);
  assert.match(body, /finally\{\s*if\(!handedOver&&payuWin&&!payuWin\.closed\)/, "an unused window is closed again");
  assert.match(html, /if\(targetName\)form\.target=targetName;/);
});

test("popup checkout: messages are same-origin only, both ways; the app keeps InAppBrowser + instant check", () => {
  assert.match(html, /window\.opener\.postMessage\(\{type:'vybera:payu-return',orderId:orderId\|\|''\},window\.location\.origin\);/);
  assert.match(html, /addEventListener\('message',function\(event\)\{\s*if\(event\.origin!==window\.location\.origin\)return;/);
  assert.match(html, /if\(PAYU_WAIT\.win&&event\.source!==PAYU_WAIT\.win\)return;/);
  assert.match(html, /if\(fromUrl&&notifyPayuOpener\(orderId\)\)return;/);
  assert.match(html, /function openPayuWindow\(\)\{\s*if\(isNativeApp\(\)\|\|\(window\.cordova&&window\.cordova\.InAppBrowser\)\)return null;/);
  assert.match(html, /addEventListener\('exit',function\(\)\{\s*if\(completed\)return;\s*resetPayButton\(\);[^]*?resumePendingPaymentCheck\(\);/);
  assert.match(html, /var PAYU_POLL=\{intervalMs:4000,maxMs:15\*60\*1000,maxFinalAttempts:5\};/);
});
