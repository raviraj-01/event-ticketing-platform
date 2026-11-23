// M15: security headers (helmet) and the Content-Security-Policy.
// No dependency on config, so it can be loaded and tested on its own.
const helmet = require("helmet");

// The page uses inline <script> blocks and onclick="" handlers everywhere, so
// scripts must allow 'unsafe-inline'. The CSP still limits WHERE scripts,
// images, fonts, connections and frames may come from, where forms may post
// (us and PayU only), and forbids framing the app (clickjacking) and plugins.
// Moving the inline code into files would allow a strict script-src (Future work).
const originOf = (url) => {
  try {
    return url ? new URL(url).origin : null;
  } catch (err) {
    return null;
  }
};
// /r2/media/* redirects to a presigned URL on the R2 endpoint.
const r2Origin = originOf(process.env.R2_ENDPOINT);

const contentSecurityPolicy = {
  useDefaults: false,
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'", "https://accounts.google.com", "https://apis.google.com", "https://www.gstatic.com"],
    scriptSrcAttr: ["'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://accounts.google.com"],
    fontSrc: ["'self'", "data:", "https://fonts.gstatic.com"],
    imgSrc: ["'self'", "data:", "blob:", "https://images.unsplash.com", "https://tile.openstreetmap.org",
      "https://*.googleusercontent.com", ...(r2Origin ? [r2Origin] : [])],
    connectSrc: ["'self'", "https://nominatim.openstreetmap.org", "https://*.googleapis.com",
      "https://accounts.google.com", "https://www.gstatic.com"],
    frameSrc: ["https://accounts.google.com", "https://*.firebaseapp.com"],
    // form-action also covers redirects after the post: PayU answers the
    // checkout form with a 302 to its payment page (test.payu.in/_payment ->
    // apitest.payu.in, seen in the real test checkout 2026-11-24), so every
    // PayU subdomain is allowed, not only the two /_payment hosts.
    formAction: ["'self'", "https://test.payu.in", "https://secure.payu.in", "https://*.payu.in"],
    frameAncestors: ["'none'"],
    objectSrc: ["'none'"],
    baseUri: ["'self'"],
    // No upgrade-insecure-requests: it would break http://localhost development.
  },
};

const securityHeaders = helmet({
  contentSecurityPolicy,
  // The Google sign-in popup needs same-origin-allow-popups (openerPolicy above).
  crossOriginOpenerPolicy: false,
  // The Android app (another origin) loads our images and uploads.
  crossOriginResourcePolicy: { policy: "cross-origin" },
  // Google Identity Services needs the origin in the Referer header.
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
});


module.exports = { securityHeaders, contentSecurityPolicy };
