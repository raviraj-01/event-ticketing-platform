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

module.exports = { hasSmtpConfig, createMailTransporter };
