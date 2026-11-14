/* Maximum inactivity before a session dies (automatic logoff). Every session stores its own computed `expiresAt`, so changing this affects a session the next time it slides. To enforce a SHORTER value on live sessions immediately, cap them once with an updateMany/$min on `expiresAt`. */
export const SESSION_IDLE_TIMEOUT_MS = 15 * 60 * 1_000; // 15 minutes

/* How often a session's activity is written. Between writes the stored expiry lags the real one, so the effective idle window is between (timeout - throttle) and timeout: it errs towards logging out EARLY, never late. */
export const SESSION_ACTIVITY_THROTTLE_MS = 60 * 1_000; // 1 minute

/* Fail at import, not in production: a throttle that is a large fraction of the timeout would make the idle window meaningless. */
if (SESSION_ACTIVITY_THROTTLE_MS * 10 > SESSION_IDLE_TIMEOUT_MS) {
   throw new RangeError(
      `SESSION_ACTIVITY_THROTTLE_MS must be at most a tenth of SESSION_IDLE_TIMEOUT_MS.`
   );
}

/* Hard ceiling on concurrent sessions per user. A new login beyond it evicts the oldest session(s), never the new one. Must be a positive integer: 1 means single-session mode. */
export const MAX_SESSIONS_PER_USER = 5 as const;
