// Cross-platform process listing for the test-cleanup tools
// (test/helpers/orphanWatchdog.js, scripts/check-orphans.js).
const { execFileSync } = require("child_process");

const isWindows = process.platform === "win32";

// [{ pid, ppid, exe, cmd }] for the given executable names (e.g. "postgres").
function listProcesses(names) {
  if (isWindows) {
    const filter = names.map((name) => `Name='${name}.exe'`).join(" OR ");
    const script = `Get-CimInstance Win32_Process -Filter "${filter}" | `
      + "Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine | ConvertTo-Json -Compress";
    const out = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
      encoding: "utf8",
      windowsHide: true,
      maxBuffer: 16 * 1024 * 1024,
    }).trim();
    if (!out) return [];
    const rows = [].concat(JSON.parse(out));
    return rows.map((row) => ({
      pid: row.ProcessId,
      ppid: row.ParentProcessId,
      exe: row.ExecutablePath || "",
      cmd: row.CommandLine || "",
    }));
  }
  const out = execFileSync("ps", ["-eo", "pid=,ppid=,args="], { encoding: "utf8" });
  return out.split("\n").map((line) => line.trim().match(/^(\d+)\s+(\d+)\s+(.*)$/)).filter(Boolean)
    .map(([, pid, ppid, cmd]) => ({ pid: Number(pid), ppid: Number(ppid), exe: cmd.split(/\s+/)[0], cmd }))
    .filter((row) => names.some((name) => row.exe.endsWith(`/${name}`) || row.exe === name));
}

function isAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === "EPERM";
  }
}

// Kill a process and everything it started.
function killTree(pid) {
  try {
    if (isWindows) execFileSync("taskkill", ["/pid", String(pid), "/f", "/t"], { stdio: "ignore", windowsHide: true });
    else process.kill(pid, "SIGKILL");
    return true;
  } catch (_) {
    return false;
  }
}

module.exports = { listProcesses, isAlive, killTree };
