// ── Password change (PATCH /api/users/me/password) ───────────────────────────────
/* The current limit: 5 attempts in an hour */
export const PASSWORD_CHANGE_WINDOW_MS = 1 * 60 * 60 * 1_000; // 1 hour
export const PASSWORD_CHANGE_MAX_REQUESTS = 5;

// ── Name change (PATCH /api/users/me/name) ───────────────────────────────────────
/* The current limit: 2 attempts a day */
export const NAME_CHANGE_WINDOW_MS = 24 * 60 * 60 * 1_000; // 1 day
export const NAME_CHANGE_MAX_REQUESTS = 2;

// ── Email change initiation (POST /api/users/me/email) ───────────────────────────
/* Each successful request fires two Resend API calls (one to the old address, one to the new), making this endpoint a cost-amplification and inbox-bombing vector if left unthrottled.
   The current limit: 2 attempts a day */
export const EMAIL_CHANGE_INITIATE_WINDOW_MS = 24 * 60 * 60 * 1_000; // 1 day
export const EMAIL_CHANGE_INITIATE_MAX_REQUESTS = 2;

// ── Email token endpoints (confirm and cancel) ───────────────────────────────────
/* These are fully public routes — no authentication required, because the user clicking the link in their email client may not have a session. The token itself is the credential, but we still rate-limit to prevent brute-force enumeration of valid token hashes. */
export const EMAIL_TOKEN_WINDOW_MS = 15 * 60 * 1_000; // 15 minutes
export const EMAIL_TOKEN_MAX_REQUESTS = 10;
