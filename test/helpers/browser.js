// Minimal headless browser for end-to-end checks: the locally installed Chrome
// or Edge, driven over the DevTools protocol with Node's own fetch and
// WebSocket (no extra npm dependency, nothing downloaded). Set CHROME_PATH to
// use another browser. launchBrowser() returns null when none is found, so the
// test can skip instead of failing on a machine without a browser.
// The browser is tracked by processGuard.js like embedded Postgres.
const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const guard = require("./processGuard");
const { killTree } = require("../../scripts/lib/processes");

const CANDIDATES = [
  process.env.CHROME_PATH,
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
  "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
];

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function findBrowser() {
  return CANDIDATES.find((candidate) => candidate && fs.existsSync(candidate)) || null;
}

async function launchBrowser({ width = 375, height = 812 } = {}) {
  const exe = findBrowser();
  if (!exe || typeof WebSocket !== "function") return null;
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "ticketing-test-browser-"));
  const guardId = guard.track({ marker: path.basename(profile), dir: profile });
  const child = spawn(exe, [
    "--headless=new", "--remote-debugging-port=0", `--user-data-dir=${profile}`,
    "--no-first-run", "--no-default-browser-check", "--disable-gpu", "--disable-extensions",
    `--window-size=${width},${height}`, "about:blank",
  ], { stdio: "ignore" });
  guard.trackChild(child);

  const close = async () => {
    if (child.exitCode === null) {
      killTree(child.pid);
      await Promise.race([new Promise((resolve) => child.once("exit", resolve)), sleep(5000)]);
    }
    fs.rmSync(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
    guard.untrack(guardId);
  };

  try {
    const portFile = path.join(profile, "DevToolsActivePort");
    for (let waited = 0; !fs.existsSync(portFile); waited += 100) {
      if (waited > 20000) throw new Error("browser did not start");
      await sleep(100);
    }
    let port = "";
    while (!port) {
      port = fs.readFileSync(portFile, "utf8").split("\n")[0].trim();
      if (!port) await sleep(100);
    }
    const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    const target = targets.find((t) => t.type === "page");
    const ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });

    let nextId = 1;
    const pending = new Map();
    const waiters = [];
    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.id && pending.has(msg.id)) {
        const { resolve, reject } = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.error) reject(new Error(msg.error.message)); else resolve(msg.result);
      } else if (msg.method) {
        for (const waiter of waiters.filter((w) => w.method === msg.method)) {
          waiters.splice(waiters.indexOf(waiter), 1);
          waiter.resolve(msg.params);
        }
      }
    };
    const send = (method, params = {}) => new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params }));
    });
    const nextEvent = (method) => new Promise((resolve) => waiters.push({ method, resolve }));
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: false });

    return {
      async goto(url) {
        const loaded = nextEvent("Page.loadEventFired");
        await send("Page.navigate", { url });
        await loaded;
      },
      async reload() {
        const loaded = nextEvent("Page.loadEventFired");
        await send("Page.reload", { ignoreCache: true });
        await loaded;
      },
      // Runs `body` as an async function in the page and returns its value.
      async run(body) {
        const result = await send("Runtime.evaluate", {
          expression: `(async () => { ${body} })()`,
          awaitPromise: true,
          returnByValue: true,
        });
        if (result.exceptionDetails) {
          throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
        }
        return result.result.value;
      },
      async close() {
        try { ws.close(); } catch (_) { /* already closed */ }
        await close();
      },
    };
  } catch (err) {
    await close();
    throw err;
  }
}

module.exports = { launchBrowser, findBrowser };
