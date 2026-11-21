// M7: the development OTP (code returned in the response) only with an
// explicit OTP_DEV_MODE=true, never in production, never from a Host header.
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { startTestServer, startApp, api } = require("./helpers/testServer");

let server;
before(async () => {
  server = await startTestServer();
});
after(async () => {
  if (server) await server.stop();
});

const send = (baseUrl, phone) => api(baseUrl, "POST", "/otp/twilio/send", { json: { identifier: phone } });

test("M7: with OTP_DEV_MODE=true (local) the code comes back for development", async () => {
  await server.db.query("DELETE FROM rate_limit_hits");
  const res = await send(server.baseUrl, "919800000101");
  assert.equal(res.status, 200);
  assert.match(String(res.body.devOtp), /^\d{4,8}$/);
});

test("M7: without OTP_DEV_MODE, or in production, no code is ever returned (even on localhost)", async () => {
  for (const env of [{ OTP_DEV_MODE: "" }, { OTP_DEV_MODE: "true", NODE_ENV: "production" }]) {
    await server.db.query("DELETE FROM rate_limit_hits");
    const app = await startApp(server.databaseUrl, env);
    try {
      const res = await send(app.baseUrl, "919800000102");
      assert.equal(res.status, 503, JSON.stringify(env));
      assert.equal(res.body.devOtp, undefined);
      assert.doesNotMatch(JSON.stringify(res.body), /TWILIO_|\.env/, "no config details");
    } finally {
      app.stop();
    }
  }
});
