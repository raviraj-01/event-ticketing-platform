// Detached watchdog started by processGuard.js, one per test process.
// usage: node orphanWatchdog.js <parentPid> <registryFile>
//
// Waits for the test process to end. If it ended without cleaning up (hard
// kill), it kills every process whose command line carries a registered
// marker and deletes the registered temp directories. Exits right after.
const fs = require("fs");
const path = require("path");
const { listProcesses, isAlive, killTree } = require("../../scripts/lib/processes");

const parentPid = Number(process.argv[2]);
const registry = process.argv[3];
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function removeDir(dir) {
  for (let attempt = 0; attempt < 20; attempt++) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
      return;
    } catch (_) {
      await sleep(500); // Postgres may still be releasing its files
    }
  }
}

async function cleanUp(registryFile) {
  let leftovers = [];
  try {
    leftovers = JSON.parse(fs.readFileSync(registryFile, "utf8"));
  } catch (_) {
    // no registry: the test process cleaned up after itself
  }
  if (leftovers.length) {
    const processes = listProcesses(["postgres", "initdb", "pg_ctl", "node", "chrome", "msedge", "chromium"]);
    for (const proc of processes) {
      if (proc.pid !== process.pid && leftovers.some((entry) => proc.cmd.includes(entry.marker))) killTree(proc.pid);
    }
    for (const entry of leftovers) if (entry.dir) await removeDir(entry.dir);
  }
  fs.rmSync(registryFile, { force: true });
}

// A tree kill (e.g. a Windows job object) also kills the watchdog of that run.
// Its registry stays behind, so every new watchdog first cleans up after test
// processes that are gone.
async function sweepStale() {
  const dir = path.dirname(registry);
  for (const name of fs.readdirSync(dir)) {
    const match = name.match(/^ticketing-test-guard-(\d+)\.json$/);
    if (!match || Number(match[1]) === parentPid || isAlive(Number(match[1]))) continue;
    await cleanUp(path.join(dir, name)).catch(() => {});
  }
}

sweepStale().catch(() => {}).finally(() => {
  const timer = setInterval(() => {
    if (isAlive(parentPid)) return;
    clearInterval(timer);
    cleanUp(registry).catch(() => {}).finally(() => process.exit(0));
  }, 1000);
});
