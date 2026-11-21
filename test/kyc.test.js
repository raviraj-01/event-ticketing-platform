// Integration tests for H14: KYC documents are never public.
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { startTestServer, api } = require("./helpers/testServer");
const { makeFixtures } = require("./helpers/fixtures");

let server;
let fx;

before(async () => {
  // Fake R2 settings: presigning is local maths, no request ever reaches R2.
  server = await startTestServer({
    R2_ENDPOINT: "https://r2.example.test",
    R2_BUCKET: "test-bucket",
    R2_ACCESS_KEY_ID: "test-access-key",
    R2_SECRET_ACCESS_KEY: "test-secret-key",
  });
  fx = makeFixtures(server.db);
});
after(async () => {
  if (server) await server.stop();
});

async function creatorWithDocument() {
  const creator = await fx.createCreator({ kycStatus: "Pending" });
  const doc = await server.db.query(
    `INSERT INTO creator_kyc_documents (creator_id, document_type, file_name, object_key, storage, content_type)
     VALUES ($1, 'pan', 'pan.pdf', $2, 'r2', 'application/pdf') RETURNING id, object_key`,
    [creator.id, `kyc-documents/creator${fx.uid()}/pan/123-pan.pdf`],
  );
  return { creator, doc: doc.rows[0] };
}

test("H14: KYC keys are not served by the public media route", async () => {
  const { doc } = await creatorWithDocument();
  assert.equal((await api(server.baseUrl, "GET", `/r2/media/${doc.object_key}`)).status, 404);
  const banner = await api(server.baseUrl, "GET", "/r2/media/event-banners/creator-1/banner.png");
  assert.equal(banner.status, 302, "public banners still work");
});

test("H14: KYC files open only for super admins, via a 60-second link, and each view is audited", async () => {
  const { doc } = await creatorWithDocument();
  const path = `/admin/kyc-documents/${doc.id}/file`;
  assert.equal((await api(server.baseUrl, "GET", path)).status, 401);
  const admin = await fx.createAdmin();
  assert.equal((await api(server.baseUrl, "GET", path, { token: admin.token })).status, 403);
  const superAdmin = await fx.createAdmin({ superAdmin: true });
  const ok = await api(server.baseUrl, "GET", path, { token: superAdmin.token });
  assert.equal(ok.status, 302);
  assert.match(ok.headers.get("location"), /^https:\/\/r2\.example\.test\/.*X-Amz-Expires=60/);
  await new Promise((r) => setTimeout(r, 200));
  const audit = await server.db.query("SELECT * FROM admin_audit_log WHERE action='kyc.view' AND target_id=$1", [String(doc.id)]);
  assert.equal(audit.rows.length, 1);
});

test("H14: the admin snapshot shows KYC documents to super admins only", async () => {
  const { creator } = await creatorWithDocument();
  const find = (body) => body.creators.find((c) => c.creatorId === creator.id);
  const admin = await fx.createAdmin();
  const superAdmin = await fx.createAdmin({ superAdmin: true });
  const asAdmin = await api(server.baseUrl, "GET", "/admin/snapshot", { token: admin.token });
  assert.deepEqual(find(asAdmin.body).documents, []);
  const asSuper = await api(server.baseUrl, "GET", "/admin/snapshot", { token: superAdmin.token });
  assert.equal(find(asSuper.body).documents.length, 1);
  assert.match(find(asSuper.body).documents[0].url, /^\/admin\/kyc-documents\/\d+\/file$/);
});
