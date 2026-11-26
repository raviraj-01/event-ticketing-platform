// Embedded Postgres and test servers must never outlive the test process,
// however it ends. Each case runs a real startTestServer() in a child process.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const { listProcesses } = require("../scripts/lib/processes");
const { scan } = require("../scripts/check-orphans");

const HELPER = path.join(__dirname, "helpers", "testServer.js");
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Starts a child that runs `body` after startTestServer() and reports the data directory.
function runChild(body, extraEnv = {}) {
  const code = `
    const { startTestServer } = require(${JSON.stringify(HELPER)});
    (async () => {
      let server;
      try { server = await startTestServer(${JSON.stringify(extraEnv)}); }
      catch (err) { console.log("START_FAILED"); return; }
      console.log("READY " + JSON.stringify({ dataDir: server.dataDir, baseUrl: server.baseUrl }));
      ${body}
    })();`;
  const child = spawn(process.execPath, ["-e", code], { stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", (chunk) => { output += chunk; });
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`child did not start:\n${output}`)), 90000);
    const check = setInterval(() => {
      const match = output.match(/READY (\{.*\})/);
      if (match || output.includes("START_FAILED")) {
        clearInterval(check); clearTimeout(timer);
        resolve(match ? JSON.parse(match[1]) : null);
      }
    }, 100);
  });
  const exited = new Promise((resolve) => child.on("exit", resolve));
  return { child, ready, exited, output: () => output };
}

function processesFor(marker) {
  return listProcesses(["postgres", "initdb", "node"]).filter((proc) => proc.cmd.includes(marker));
}

async function expectCleanedUp(dataDir, timeoutMs = 20000) {
  const marker = path.basename(dataDir);
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const left = processesFor(marker);
    if (!left.length && !fs.existsSync(dataDir)) return;
    if (Date.now() > deadline) assert.fail(`left over: ${left.length} process(es), dir exists: ${fs.existsSync(dataDir)}`);
    await sleep(500);
  }
}

test("hard kill of the test process: the watchdog stops Postgres and the server, and deletes the data", async () => {
  const run = runChild("setInterval(() => {}, 1 << 30);");
  const info = await run.ready;
  assert.ok(info, run.output());
  assert.ok(processesFor(path.basename(info.dataDir)).length > 0, "Postgres is running before the kill");
  run.child.kill("SIGKILL"); // no handler runs (TerminateProcess on Windows)
  await run.exited;
  await expectCleanedUp(info.dataDir);
  const health = await fetch(info.baseUrl + "/health").then(() => "up", () => "down");
  assert.equal(health, "down", "test server.js stopped too");
});

test("process.exit without stop() (crash, --test-force-exit): exit handler + watchdog clean up", async () => {
  const run = runChild("process.exit(1);");
  const info = await run.ready;
  assert.ok(info, run.output());
  await run.exited;
  await expectCleanedUp(info.dataDir);
});

test("the app fails to boot: startTestServer stops the Postgres it already started", async () => {
  const before = scan().runningPostgres.length + scan().orphanPostgres.length;
  const run = runChild("", { JWT_SECRET: "" }); // server.js refuses to start without it
  assert.equal(await run.ready, null, "start failed as intended");
  await run.exited;
  const after = scan();
  assert.equal(after.runningPostgres.length + after.orphanPostgres.length, before);
});

test("a run killed together with its watchdog (process-tree kill) is cleaned up by the next run", async () => {
  const os = require("os");
  // A test process that is gone, with its registry and data directory left behind.
  const dead = spawn(process.execPath, ["-e", ""]);
  await new Promise((resolve) => dead.on("exit", resolve));
  const leftoverDir = fs.mkdtempSync(path.join(os.tmpdir(), "ticketing-test-pg-"));
  const registry = path.join(os.tmpdir(), `ticketing-test-guard-${dead.pid}.json`);
  fs.writeFileSync(registry, JSON.stringify([{ marker: path.basename(leftoverDir), dir: leftoverDir }]));

  const run = runChild("await server.stop();");
  assert.ok(await run.ready, run.output());
  await run.exited;
  const deadline = Date.now() + 20000;
  while ((fs.existsSync(leftoverDir) || fs.existsSync(registry)) && Date.now() < deadline) await sleep(500);
  assert.equal(fs.existsSync(leftoverDir), false, "leftover data directory deleted");
  assert.equal(fs.existsSync(registry), false, "stale registry deleted");
});
