/* The audience claim embedded in TOTP challenge tokens. Mirrors the ACCESS_TOKEN_AUDIENCE pattern. Each token type is only accepted by the specific endpoints it was issued for. */
export const TOTP_CHALLENGE_AUDIENCE = 'totp-challenge' as const;

/* Scoped to /api/auth/totp so the browser never sends it to any other path. */
export const TOTP_CHALLENGE_COOKIE_NAME = 'totp_challenge' as const;

/* User has 5 minutes to confirm the challenge. */
export const TOTP_CHALLENGE_EXPIRY_SECONDS = 300 as const;

export const TOTP_RECOVERY_CODE_COUNT = 10 as const;

/* The human-readable label shown in the authenticator app next to the account. */
export const TOTP_ISSUER = 'CambridgeMed' as const;
