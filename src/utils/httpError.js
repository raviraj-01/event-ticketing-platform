// M5: an error whose message is meant for the client (validation, not found,
// conflict). Everything else is an internal error: logged in full on the
// server, and the client only gets a generic message.
class HttpError extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code;
    this.expose = true;
  }
}

// Send `err` if it is client-facing; otherwise log it and send `message`.
// `body` adds fields some clients expect (e.g. { sent: false }).
function sendError(res, err, { status = 500, message = "Something went wrong", log = "Request failed", body = {} } = {}) {
  if (err && err.expose && err.status >= 400 && err.status < 500) {
    return res.status(err.status).json({ ...body, error: err.message, ...(err.code ? { code: err.code } : {}) });
  }
  console.error(`${log}:`, err);
  return res.status(status).json({ ...body, error: message });
}

module.exports = { HttpError, sendError };
