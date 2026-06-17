import { escapeRegex } from '@utils/escapeRegex.ts';

/* The audience claim embedded in TOTP challenge tokens. Mirrors the ACCESS_TOKEN_AUDIENCE pattern. Each token type is only accepted by the specific endpoints it was issued for. */
export const TOTP_CHALLENGE_AUDIENCE = 'totp-challenge' as const;

/* Scoped to /api/auth/totp so the browser never sends it to any other path. */
export const TOTP_CHALLENGE_COOKIE_NAME = 'totp_challenge' as const;

/* User has 5 minutes to confirm the challenge. */
export const TOTP_CHALLENGE_EXPIRY_SECONDS = 300 as const;

/* The human-readable label shown in the authenticator app next to the account. */
export const TOTP_ISSUER = 'CambridgeMed' as const;

// ── RECOVERY CODE CONFIG ─────────────────────────────────────────────────────────
/* Each part of a recovery code is 10-character long hex string */
export const TOTP_RECOVERY_CODE_COUNT = 10 as const;
export const RECOVERY_CODE_PART_BYTE_LENGTH = 5 as const;
export const RECOVERY_CODE_PART_HEX_LENGTH = RECOVERY_CODE_PART_BYTE_LENGTH * 2; // 10
export const RECOVERY_CODE_SEPARATOR = '-' as const;

// ── CRYPTO CIPHER CONFIG (Dictated by AES-256-GCM) ───────────────────────────────
export const CIPHER_ALGORITHM = 'aes-256-gcm' as const;
export const AES_KEY_BYTE_LENGTH = 32 as const; // Required for AES-256 (Passed to hkdfSync)
export const IV_BYTE_LENGTH = 12 as const; // 96 bits: Standard for GCM
export const IV_HEX_LENGTH = IV_BYTE_LENGTH * 2; // 24 hex characters
export const AUTH_TAG_HEX_LENGTH = 32 as const; // 16 bytes auth tag = 32 hex characters
export const TOTP_SECRET_SEPARATOR = ':' as const;

// ── HMAC CONFIG (Dictated by SHA-256) ────────────────────────────────────────────
export const HMAC_KEY_BYTE_LENGTH = 32 as const; // Recommended key length for HMAC-SHA256

// ── TOTP SECRET CONFIG ───────────────────────────────────────────────────────────
export const TOTP_SECRET_BYTES = 20 as const; // Changing this safely updates everything below
export const TOTP_BITS_PER_BASE32_CHAR = 5 as const;

// Formula: (20 bytes * 8 bits) / 5 bits = 32 characters
export const TOTP_PLAINTEXT_CHAR_LENGTH =
   (TOTP_SECRET_BYTES * 8) / TOTP_BITS_PER_BASE32_CHAR;

// Because 1 char = 1 byte in UTF-8, plaintext bytes === character length
export const CIPHERTEXT_BYTE_LENGTH = TOTP_PLAINTEXT_CHAR_LENGTH;
export const CIPHERTEXT_HEX_LENGTH = CIPHERTEXT_BYTE_LENGTH * 2; // 64 characters

// ── REGULAR EXPRESSIONS ──────────────────────────────────────────────────────────
const escapedTotpSecretSeparator = escapeRegex(TOTP_SECRET_SEPARATOR);
export const totpSecretRegex = new RegExp(
   `^[0-9a-f]{${IV_HEX_LENGTH}}${escapedTotpSecretSeparator}[0-9a-f]{${AUTH_TAG_HEX_LENGTH}}${escapedTotpSecretSeparator}[0-9a-f]{${CIPHERTEXT_HEX_LENGTH}}$`
);
const escapedRecoveryCodeSeparator = escapeRegex(RECOVERY_CODE_SEPARATOR);
export const recoveryCodeRegex = new RegExp(
   `^[0-9A-F]{${RECOVERY_CODE_PART_HEX_LENGTH}}${escapedRecoveryCodeSeparator}[0-9A-F]{${RECOVERY_CODE_PART_HEX_LENGTH}}$`
);
