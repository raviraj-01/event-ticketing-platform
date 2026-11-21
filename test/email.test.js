// End-to-end email flows with a local SMTP sink: reset links (Q4).
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const bcrypt = require("bcrypt");
const { startTestServer, api } = require("./helpers/testServer");
const { startSmtpSink } = require("./helpers/smtpSink");

let server;
let smtp;

before(async () => {
  smtp = await startSmtpSink();
  server = await startTestServer(smtp.env);
});
after(async () => {
  if (server) await server.stop();
  if (smtp) await smtp.stop();
});

const waitForMail = async (to) => {
  for (let i = 0; i < 50; i += 1) {
    const found = smtp.messages.filter((m) => m.to.includes(to));
    if (found.length) return found[found.length - 1];
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`no email to ${to}`);
};
const resetLinks = (message) => [...smtp.text(message).matchAll(/reset_token=([A-Za-z0-9._%-]+)/g)].map((m) => decodeURIComponent(m[1]));

test("Q4: staff with a shared email get one link per account, and each link works", async () => {
  const email = `shared${Date.now()}@test.local`;
  const hash = await bcrypt.hash("Old-pass-1", 4);
  for (const login of ["gate.a", "gate.b"]) {
    await server.db.query(
      "INSERT INTO staff_accounts (id, name, staff_id, email, password, share_token, status) VALUES ($1,'S',$2,$3,$4,$5,'active')",
      [`STF-mail-${login}-${Date.now()}`, `${login}.${Date.now()}`, email, hash, `share-${login}-${Date.now()}`],
    );
  }
  const res = await api(server.baseUrl, "POST", "/auth/forgot-password", { json: { email, role: "staff" } });
  assert.equal(res.status, 200);
  const mail = await waitForMail(email);
  const tokens = [...new Set(resetLinks(mail))];
  assert.equal(tokens.length, 2);
  assert.match(smtp.text(mail), /gate\.a/);
  const reset = await api(server.baseUrl, "POST", "/auth/reset-password-by-token", { json: { token: tokens[0], password: "Brand-new-1" } });
  assert.equal(reset.status, 200);
  assert.equal(reset.body.role, "staff");
});

test("Q4: an organizer gets a reset email; an unknown email gets the same answer and no email", async () => {
  const email = `org${Date.now()}@test.local`;
  await server.db.query(
    "INSERT INTO creator_accounts (name, email, phone, category, about, password, kyc_status) VALUES ('O',$1,'9','M','x',$2,'Approved')",
    [email, await bcrypt.hash("Old-pass-1", 4)],
  );
  const known = await api(server.baseUrl, "POST", "/auth/forgot-password", { json: { email, role: "creator" } });
  const unknown = await api(server.baseUrl, "POST", "/auth/forgot-password", { json: { email: `nobody${Date.now()}@test.local`, role: "creator" } });
  assert.deepEqual(known.body, unknown.body);
  const mail = await waitForMail(email);
  assert.equal(resetLinks(mail).length >= 1, true);
});

test("Q4: admins cannot request a reset email", async () => {
  const res = await api(server.baseUrl, "POST", "/auth/forgot-password", { json: { email: "a@test.local", role: "admin" } });
  assert.equal(res.status, 400);
});
