// SMTP transport for outgoing email (password reset, admin login codes).
// ── Email transporter ───────────────────────────────────────────────────────
const nodemailer = require("nodemailer");

const createMailTransporter = () => {
  if (process.env.SMTP_SERVICE) {
    return nodemailer.createTransport({
      service: process.env.SMTP_SERVICE,
      port: Number(process.env.SMTP_PORT || 465),
      secure: process.env.SMTP_SECURE === "true",
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  }
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === "true",
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
};

const hasSmtpConfig = () =>
  (process.env.SMTP_SERVICE || process.env.SMTP_HOST) &&
  process.env.SMTP_USER &&
  process.env.SMTP_PASS;

if (!hasSmtpConfig()) {
  console.warn(
    "Email (forgot password) is disabled until SMTP_SERVICE/SMTP_HOST, SMTP_USER, and SMTP_PASS are added to .env.",
  );
}

const escapeEmailHtml = (value) =>
  String(value == null ? "" : value).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]);

// One email; for staff there can be several accounts with the same address,
// so each gets its own link labelled with its login ID.
function resetEmailHtml(links, ttlMinutes, accountLabel) {
  const buttons = links
    .map((link) => `<p style="margin:16px 0;"><a href="${escapeEmailHtml(link.url)}" style="display:inline-block;padding:12px 24px;background:#ffffff;color:#000000;font-weight:700;text-decoration:none;border-radius:8px;">Reset password${link.loginId ? ` for ${escapeEmailHtml(link.loginId)}` : ""}</a></p>`)
    .join("");
  return `<!doctype html><html><body style="margin:0;padding:24px;background:#0a0a0a;font-family:Arial,sans-serif;color:#ffffff;">
    <div style="max-width:520px;margin:0 auto;background:#141414;border-radius:12px;padding:32px;">
      <h1 style="margin:0 0 16px;font-size:20px;">BLAK Tickets</h1>
      <p style="color:#aaaaaa;line-height:1.6;">We received a request to reset the password of your ${escapeEmailHtml(accountLabel)}. The link expires in <strong style="color:#fff;">${ttlMinutes} minutes</strong> and works once.</p>
      ${buttons}
      <p style="color:#666666;font-size:12px;line-height:1.6;">If you didn't ask for this, ignore this email; your password stays the same.</p>
    </div></body></html>`;
}

// Step 1: email a single-use reset link (buyers, organizers, staff with email).

module.exports = { hasSmtpConfig, createMailTransporter, resetEmailHtml };
