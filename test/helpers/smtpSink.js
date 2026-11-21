// A local SMTP server that just stores received emails, so tests can read
// password-reset links and login codes without a real mail provider.
const { SMTPServer } = require("smtp-server");

async function startSmtpSink() {
  const messages = [];
  const server = new SMTPServer({
    authOptional: true,
    disabledCommands: ["STARTTLS"],
    onAuth: (auth, session, callback) => callback(null, { user: auth.username }),
    onData(stream, session, callback) {
      let raw = "";
      stream.on("data", (chunk) => { raw += chunk.toString("utf8"); });
      stream.on("end", () => {
        messages.push({ to: session.envelope.rcptTo.map((r) => r.address), raw });
        callback();
      });
    },
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.server.address().port;
  return {
    port,
    messages,
    env: { SMTP_HOST: "127.0.0.1", SMTP_PORT: String(port), SMTP_SECURE: "false", SMTP_USER: "test", SMTP_PASS: "test", SMTP_FROM: "noreply@test.local", SMTP_SERVICE: "" },
    // Quoted-printable bodies wrap lines with "=\r\n" and encode "=" as "=3D".
    text: (message) => message.raw.replace(/=\r?\n/g, "").replace(/=3D/g, "="),
    stop: () => new Promise((resolve) => server.close(resolve)),
  };
}

module.exports = { startSmtpSink };
