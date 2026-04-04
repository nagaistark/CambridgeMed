export const JWT_ACCESS_TOKEN_EXPIRY_MS: number = 60_000; // I.e., 1 minute
export const JWT_REFRESH_TOKEN_RESET_WEEKDAY: number = 1; // Luxon-based weekdays: 1 — Monday, 7 — Sunday;

/* The window within which a previousTokenHash match is treated as a benign multi-tab race condition rather than a reuse attack. Must be long enough to cover the network round-trip difference between two simultaneous tab requests, but short enough to be useless to an attacker sitting on a stolen token. */
export const SESSION_REUSE_GRACE_WINDOW_MS: number = 10_000;
