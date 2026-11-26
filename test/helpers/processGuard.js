// Makes sure the processes a test run starts (embedded Postgres, server.js)
// never outlive it, however the test process ends.
//
//   normal end / failure  -> the test's after() hook calls stop()
//   process.exit, crash,   -> the "exit" handler below kills tracked children
//   Ctrl+C, SIGTERM           synchronously (signals exit through it)
//   hard kill (Task        -> nothing in this process runs, so a small detached
//   Manager, timeout kill)    watchdog notices the parent is gone, kills every
//                             process whose command line carries one of our
//                             markers and deletes the temp data directories.
//   process-tree kill      -> kills the watchdog too (its registry file stays);
//                             the next run's watchdog sweeps registries of dead
//                             test processes first. `npm run check:orphans` lists
//                             anything left; `-- --clean` removes it.
//
// The watchdog finds processes by a unique marker in their command line (the
// Postgres data directory, a --test-instance= argument on server.js), not by
// PID, so it also covers the second while Postgres is starting and can never
// kill an unrelated process that reused a PID.
const { spawn, execFileSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const isWindows = process.platform === "win32";
const REGISTRY = path.join(os.tmpdir(), `ticketing-test-guard-${process.pid}.json`);
const WATCHDOG = path.join(__dirname, "orphanWatchdog.js");

const entries = new Map(); // id -> { marker, dir }
const children = new Set(); // { child, signal }
let nextId = 1;
let installed = false;

function writeRegistry() {
  if (entries.size === 0) {
    fs.rmSync(REGISTRY, { force: true });
    return;
  }
  fs.writeFileSync(REGISTRY, JSON.stringify([...entries.values()]));
}

function killChildNow({ child, signal }) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  try {
    // taskkill /t also ends the processes Postgres started (backends).
    if (isWindows) execFileSync("taskkill", ["/pid", String(child.pid), "/f", "/t"], { stdio: "ignore", windowsHide: true });
    else child.kill(signal);
  } catch (_) {
    // already gone
  }
}

function killAllNow() {
  for (const tracked of children) killChildNow(tracked);
  children.clear();
}

function install() {
  if (installed) return;
  installed = true;
  process.on("exit", killAllNow);
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP", "SIGBREAK"]) {
    process.on(signal, () => {
      killAllNow();
      process.exit(128 + (os.constants.signals[signal] || 0));
    });
  }
  const watchdog = spawn(process.execPath, [WATCHDOG, String(process.pid), REGISTRY], {
    detached: true,
    stdio: "ignore",
    windowsHide: true,
  });
  watchdog.unref();
}

// Register a marker (and an optional temp directory to delete) before the
// process that carries it is started. Returns an id for untrack().
function track({ marker, dir }) {
  install();
  const id = nextId++;
  entries.set(id, { marker, dir: dir || null });
  writeRegistry();
  return id;
}

function untrack(id) {
  entries.delete(id);
  writeRegistry();
}

// Kill this child synchronously if the test process exits before stop().
function trackChild(child, signal = "SIGKILL") {
  const tracked = { child, signal };
  children.add(tracked);
  child.once("exit", () => children.delete(tracked));
  return () => children.delete(tracked);
}

module.exports = { track, untrack, trackChild, REGISTRY };
