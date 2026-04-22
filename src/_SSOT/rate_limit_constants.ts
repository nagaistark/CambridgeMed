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

// ── Forgot password (POST /api/auth/forgot-password) ─────────────────────────────
/* This is a fully public, unauthenticated endpoint. Without a tight limiter, an attacker could use it to spam arbitrary inboxes at our expense. Three attempts per 15-minute window is generous for a legitimate user who mistyped their email, while being restrictive enough to make bulk abuse impractical. */
export const FORGOT_PASSWORD_WINDOW_MS = 15 * 60 * 1_000; // 15 minutes
export const FORGOT_PASSWORD_MAX_REQUESTS = 3;

// ── Reset password (POST /api/auth/reset-password/:token) ────────────────────────
/* The token itself is the credential, but we still limit redemption attempts to prevent brute-force enumeration of valid token hashes. */
export const RESET_PASSWORD_WINDOW_MS = 15 * 60 * 1_000; // 15 minutes
export const RESET_PASSWORD_MAX_REQUESTS = 10;
