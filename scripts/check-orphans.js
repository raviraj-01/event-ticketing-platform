// Lists test leftovers from THIS project only:
//   - embedded Postgres processes started from this project's node_modules
//     whose owning test process is gone,
//   - test server.js instances (started with --test-instance=) whose owner is gone,
//   - temp data directories (ticketing-test-pg-*, ticketing-test-browser-*) no running test uses,
//   - stale watchdog registry files.
// Usage: npm run check:orphans            (exit code 1 if anything is left over)
//        npm run check:orphans -- --clean (stop those processes, delete those directories)
// Other Postgres installations on the machine are never listed or touched.
const fs = require("fs");
const os = require("os");
const path = require("path");
const { listProcesses, isAlive, killTree } = require("./lib/processes");

const ROOT = path.join(__dirname, "..");
const EMBEDDED_BIN = path.join(ROOT, "node_modules", "@embedded-postgres").toLowerCase();
const TMP = os.tmpdir();
const DATA_PREFIX = "ticketing-test-pg-";
const BROWSER_PREFIX = "ticketing-test-browser-"; // headless browser profiles (test/helpers/browser.js)

function scan() {
  const processes = listProcesses(["postgres", "node"]);
  const pids = new Set(processes.map((proc) => proc.pid));
  const ours = processes.filter((proc) => path.normalize(proc.exe).toLowerCase().startsWith(EMBEDDED_BIN));
  // Postmasters only: backends are children of a postmaster and go with it.
  const postmasters = ours.filter((proc) => !ours.some((parent) => parent.pid === proc.ppid));
  const inUse = new Set(postmasters.map((proc) => (proc.cmd.match(new RegExp(`${DATA_PREFIX}[A-Za-z0-9]+`)) || [])[0]).filter(Boolean));
  const orphanPostgres = postmasters.filter((proc) => !isAlive(proc.ppid));
  const runningPostgres = postmasters.filter((proc) => isAlive(proc.ppid));
  const orphanServers = processes.filter((proc) => /server\.js"?\s+--test-instance=/.test(proc.cmd)
    && !pids.has(proc.ppid) && !isAlive(proc.ppid));
  const registries = [];
  for (const name of fs.readdirSync(TMP)) {
    const match = name.match(/^ticketing-test-guard-(\d+)\.json$/);
    if (!match) continue;
    if (!isAlive(Number(match[1]))) { registries.push(name); continue; }
    // A running test registers its directory before Postgres exists (initdb): still in use.
    try {
      for (const entry of JSON.parse(fs.readFileSync(path.join(TMP, name), "utf8"))) {
        if (entry.dir) inUse.add(path.basename(entry.dir));
      }
    } catch (_) {
      // being rewritten right now; the next run will see it
    }
  }
  const dirs = fs.readdirSync(TMP).filter((name) => (name.startsWith(DATA_PREFIX) || name.startsWith(BROWSER_PREFIX)) && !inUse.has(name));
  return { orphanPostgres, runningPostgres, orphanServers, dirs, registries };
}

function main() {
  const clean = process.argv.includes("--clean");
  const found = scan();
  const describe = (proc) => `  pid ${proc.pid}  ${proc.cmd.slice(0, 140)}`;

  console.log(`Embedded Postgres for this project: ${found.runningPostgres.length} in use by a running test, ${found.orphanPostgres.length} orphaned`);
  found.orphanPostgres.forEach((proc) => console.log(describe(proc)));
  console.log(`Orphaned test servers (server.js --test-instance): ${found.orphanServers.length}`);
  found.orphanServers.forEach((proc) => console.log(describe(proc)));
  console.log(`Leftover data directories in ${TMP}: ${found.dirs.length}`);
  console.log(`Stale watchdog registry files: ${found.registries.length}`);

  const leftovers = found.orphanPostgres.length + found.orphanServers.length + found.dirs.length + found.registries.length;
  if (!leftovers) {
    console.log("Nothing left over.");
    return;
  }
  if (!clean) {
    console.log("Run `npm run check:orphans -- --clean` to stop them and delete the directories.");
    process.exitCode = 1;
    return;
  }
  [...found.orphanPostgres, ...found.orphanServers].forEach((proc) => killTree(proc.pid));
  let removed = 0;
  for (const name of [...found.dirs, ...found.registries]) {
    try {
      fs.rmSync(path.join(TMP, name), { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
      removed++;
    } catch (err) {
      console.log(`  could not delete ${name}: ${err.code || err.message}`);
    }
  }
  console.log(`Stopped ${found.orphanPostgres.length + found.orphanServers.length} process(es), deleted ${removed} file(s)/directories.`);
}

if (require.main === module) main();

module.exports = { scan };
