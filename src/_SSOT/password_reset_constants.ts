/* The window is intentionally short. */
export const PASSWORD_RESET_TOKEN_EXPIRY_MS = 30 * 60 * 1_000; // 30 minutes

/* Minimum gap between two reset emails for the same account */
export const PASSWORD_RESET_COOLDOWN_MS = 60 * 1_000; // 1 minute
