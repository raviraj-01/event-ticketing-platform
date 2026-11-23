// M5: a request ID ties what a user sees to the server log.
//   - every response carries X-Request-Id;
//   - 5xx JSON responses also include { requestId } so a user can quote it;
//   - console.error / console.warn lines written while handling a request are
//     prefixed with "[req <id>]".
// AsyncLocalStorage keeps the ID available through every await of that
// request, so the existing catch blocks need no changes.
const { AsyncLocalStorage } = require("async_hooks");
const crypto = require("crypto");

const requestContext = new AsyncLocalStorage();

function requestId(req, res, next) {
  const id = crypto.randomUUID();
  req.id = id;
  res.setHeader("X-Request-Id", id);
  const json = res.json.bind(res);
  res.json = (body) => {
    const isPlainObject = body && typeof body === "object" && !Array.isArray(body);
    return json(res.statusCode >= 500 && isPlainObject ? { ...body, requestId: id } : body);
  };
  requestContext.run({ requestId: id }, next);
}

// Called once at startup (server.js).
function tagServerLogsWithRequestId() {
  for (const level of ["error", "warn"]) {
    const original = console[level].bind(console);
    console[level] = (...args) => {
      const context = requestContext.getStore();
      return context ? original(`[req ${context.requestId}]`, ...args) : original(...args);
    };
  }
}

module.exports = { requestId, tagServerLogsWithRequestId };
