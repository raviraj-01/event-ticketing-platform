// Fixed-window rate limiting stored in Postgres (table rate_limit_hits), so the
// limit holds across restarts and across several server instances.
//
// Usage:
//   const { rateLimit } = require("../middleware/rateLimit");
//   router.post("/x", rateLimit({ name: "x-ip", windowSeconds: 600, max: 30, key: (req) => req.ip }), handler);
//
// Fixed window = count hits per bucket in the current N-second window. Simple
// and good enough here; the trade-off is that a client can do up to 2×max
// around a window boundary.
const db = require("../db/pool");

function createRateLimiter(pool) {
  return function rateLimit({ name, windowSeconds, max, key, message }) {
    return async (req, res, next) => {
      const id = key(req);
      if (!id) return next();
      const windowMs = windowSeconds * 1000;
      const windowStart = new Date(Math.floor(Date.now() / windowMs) * windowMs);
      try {
        const result = await pool.query(
          `INSERT INTO rate_limit_hits (bucket, window_start, hits) VALUES ($1, $2, 1)
           ON CONFLICT (bucket, window_start) DO UPDATE SET hits = rate_limit_hits.hits + 1
           RETURNING hits`,
          [`${name}:${id}`, windowStart],
        );
        if (result.rows[0].hits > max) {
          const retryAfter = Math.ceil((windowStart.getTime() + windowMs - Date.now()) / 1000);
          res.set("Retry-After", String(Math.max(1, retryAfter)));
          return res.status(429).json({ error: message || "Too many requests. Please try again later." });
        }
        return next();
      } catch (err) {
        // Fail open: a broken limiter should not take the whole endpoint down.
        console.error(`Rate limit check failed (${name}):`, err.message);
        return next();
      }
    };
  };
}

// Old windows are useless after a day; called from a periodic cleanup.
async function pruneRateLimitHits(pool) {
  await pool.query("DELETE FROM rate_limit_hits WHERE window_start < NOW() - INTERVAL '1 day'");
}

// The shared limiter used by the routes.
const rateLimit = createRateLimiter(db.pool);

module.exports = { createRateLimiter, pruneRateLimitHits, rateLimit };
