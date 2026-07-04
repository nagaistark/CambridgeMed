import {
   createCipheriv,
   createDecipheriv,
   createHmac,
   hkdfSync,
   randomBytes,
} from 'node:crypto';
import { myEnv } from 'validateConfig.ts';
import { Redacted } from 'effect';
import {
   AES_KEY_BYTE_LENGTH,
   CIPHER_ALGORITHM,
   HMAC_KEY_BYTE_LENGTH,
   IV_BYTE_LENGTH,
   RECOVERY_CODE_PART_BYTE_LENGTH,
   RECOVERY_CODE_SEPARATOR,
   TOTP_RECOVERY_CODE_COUNT,
   TOTP_SECRET_SEPARATOR,
} from '@ssot/totp_constants.ts';

// ── Key derivation ───────────────────────────────────────────────────────────────
/* Computed once when this module is first imported and cached for the lifetime of the process. HKDF extracts two distinct sub-keys from the single master key. The `info` string is the domain-separation label — even if the algorithm and salt are the same, different `info` values produce completely different keys. */
const ENCRYPTION_KEY: Buffer = Buffer.from(
   hkdfSync(
      'sha256',
      Redacted.value(myEnv.totpEncryptionKey),
      Buffer.alloc(0), // empty salt: RFC 5869 §3.1 says this is fine when the IKM is already a strong key
      'cambridge-med:totp:secret-encryption:v1',
      AES_KEY_BYTE_LENGTH
   )
);

const HMAC_KEY: Buffer = Buffer.from(
   hkdfSync(
      'sha256',
      Redacted.value(myEnv.totpEncryptionKey),
      Buffer.alloc(0),
      'cambridge-med:totp:recovery-code-hmac:v1',
      HMAC_KEY_BYTE_LENGTH
   )
);

// ── TOTP secret encryption ───────────────────────────────────────────────────────
/* Encrypts the raw base32 TOTP secret before writing it to MongoDB. Output format: iv_hex:authTag_hex:ciphertext_hex. A fresh random IV is generated for every encryption, so two identical secrets encrypted separately will produce different ciphertexts. */
export function encryptTotpSecret(plaintext: string): string {
   const iv = randomBytes(IV_BYTE_LENGTH);
   const cipher = createCipheriv(CIPHER_ALGORITHM, ENCRYPTION_KEY, iv);
   const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
   ]);
   const authTag = cipher.getAuthTag(); // GCM's integrity tag — detects tampering

   return [
      iv.toString('hex'),
      authTag.toString('hex'),
      encrypted.toString('hex'),
   ].join(TOTP_SECRET_SEPARATOR);
}

/* Decrypts a stored TOTP secret back to its raw base32 form. If the ciphertext was tampered with, `decipher.final()` throws an error because the GCM auth tag won't match — this is AES-GCM's built-in integrity guarantee. We let that error propagate naturally. */
export function decryptTotpSecret(stored: string): string {
   const parts = stored.split(TOTP_SECRET_SEPARATOR);
   if (parts.length !== 3) {
      throw new Error(`Malformed stored TOTP secret: unexpected format.`);
   }

   const [ivHex, authTagHex, encryptedHex] = parts;
   const iv = Buffer.from(ivHex, 'hex');
   const authTag = Buffer.from(authTagHex, 'hex');
   const encrypted = Buffer.from(encryptedHex, 'hex');

   const decipher = createDecipheriv(CIPHER_ALGORITHM, ENCRYPTION_KEY, iv);
   decipher.setAuthTag(authTag);

   return Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
   ]).toString('utf8');
}

// ── Recovery codes ───────────────────────────────────────────────────────────────

/* Generates the plaintext recovery codes. Call this once at enrollment confirmation time, return the plaintext to the user immediately, then hash every code before persisting. The plaintext is never stored anywhere. */
export function generateRecoveryCodes(): string[] {
   return Array.from({ length: TOTP_RECOVERY_CODE_COUNT }, () => {
      const a = randomBytes(RECOVERY_CODE_PART_BYTE_LENGTH)
         .toString('hex')
         .toUpperCase(); // 10 hex chars
      const b = randomBytes(RECOVERY_CODE_PART_BYTE_LENGTH)
         .toString('hex')
         .toUpperCase(); // 10 hex chars
      return `${a}${RECOVERY_CODE_SEPARATOR}${b}`; // e.g. "3F9A2B1C4D-8E7F6A5B2C"
   });
}

/* Hashes a single recovery code for storage. We normalize to uppercase before hashing so that case-insensitive submission from the user still matches. The HMAC key is the domain-separated sub-key derived above. */
export function hashRecoveryCode(code: string): string {
   return createHmac('sha256', HMAC_KEY)
      .update(code.toUpperCase().trim())
      .digest('hex');
}
