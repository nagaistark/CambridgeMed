export const JWT_ACCESS_TOKEN_EXPIRY_MS: number = 60_000; // I.e., 1 minute

/* The window within which a previousTokenHash match is treated as a benign multi-tab race condition rather than a reuse attack. Must be long enough to cover the network round-trip difference between two simultaneous tab requests, but short enough to be useless to an attacker sitting on a stolen token. */
export const SESSION_REUSE_GRACE_WINDOW_MS: number = 10_000;

/* Hard ceiling on concurrent sessions per user. A new login beyond it evicts the oldest session(s), never the new one. Must be a positive integer: 1 means single-session mode. */
export const MAX_SESSIONS_PER_USER = 5 as const;
