import {
   createCipheriv,
   createDecipheriv,
   hkdfSync,
   randomBytes,
} from 'node:crypto';
import { myEnv } from '../validateConfig.ts';
import { Redacted } from 'effect';
import {
   AES_KEY_BYTE_LENGTH,
   CIPHER_ALGORITHM,
   IV_BYTE_LENGTH,
   RECOVERY_CODE_PART_BYTE_LENGTH,
   RECOVERY_CODE_SEPARATOR,
   TOTP_RECOVERY_CODE_COUNT,
   TOTP_SECRET_SEPARATOR,
   AUTH_TAG_BYTE_LENGTH,
   totpSecretRegex,
} from '@ssot/totp_constants.ts';
import { generateStandardHash } from '@ssot/node_crypto_constants.ts';

// ── Key ring ─────────────────────────────────────────────────────────────────────
/* Stored format: keyId:iv:authTag:ciphertext. The key id travels WITH the data, so any number of keys can be live at once: new encryptions use the active key, old ciphertexts keep decrypting under the key that made them. That is what makes rotation possible without a big-bang re-encryption.

The `v1` inside the HKDF label is the version of THIS SCHEME (algorithm + derivation). It is unrelated to key ids and changes only if the scheme itself changes. */
const ENCRYPTION_KEY_INFO = 'cambridge-med:totp:secret-encryption:v1';

function deriveEncryptionKey(masterKey: Buffer): Buffer {
   return Buffer.from(
      hkdfSync(
         'sha256',
         masterKey,
         Buffer.alloc(0), // empty salt: RFC 5869 §3.1 allows it when the IKM is already a strong key
         ENCRYPTION_KEY_INFO,
         AES_KEY_BYTE_LENGTH
      )
   );
}

const { keyring, activeKeyId } = myEnv.totpEncryption;

/* Derived once at import and held for the process lifetime. */
const ENCRYPTION_KEYS: ReadonlyMap<string, Buffer> = new Map(
   [...Redacted.value(keyring)].map(([id, masterKey]): [string, Buffer] => [
      id,
      deriveEncryptionKey(masterKey),
   ])
);

function requireKey(keyId: string): Buffer {
   const key = ENCRYPTION_KEYS.get(keyId);
   if (key === undefined) {
      throw new Error(
         `TOTP encryption key "${keyId}" is not in the configured key ring.`
      );
   }
   return key;
}

/* Fail fast at startup rather than on the first enrollment. (validateConfig already guarantees it; this keeps the guarantee local.) */
requireKey(activeKeyId);

// ── TOTP secret encryption ───────────────────────────────────────────────────────
export function encryptTotpSecret(plaintext: string): string {
   const iv = randomBytes(IV_BYTE_LENGTH);
   const cipher = createCipheriv(
      CIPHER_ALGORITHM,
      requireKey(activeKeyId),
      iv,
      { authTagLength: AUTH_TAG_BYTE_LENGTH }
   );
   const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
   ]);
   const authTag = cipher.getAuthTag();

   const stored = [
      activeKeyId,
      iv.toString('hex'),
      authTag.toString('hex'),
      encrypted.toString('hex'),
   ].join(TOTP_SECRET_SEPARATOR);

   /* Fail at the source: a value that does not match the storage format would only surface at the next validated read. */
   if (!totpSecretRegex.test(stored)) {
      throw new Error(
         `Encrypted TOTP secret does not match the storage format.`
      );
   }
   return stored;
}

/* If the ciphertext was tampered with, `decipher.final()` throws (GCM integrity). An unknown key id also throws. Both are operational/security problems and are meant to surface as 500s. */
export function decryptTotpSecret(stored: string): string {
   const groups = totpSecretRegex.exec(stored)?.groups;
   if (groups === undefined) {
      throw new Error(`Malformed stored TOTP secret: unexpected format.`);
   }
   const { keyId, iv, authTag, ciphertext } = groups;

   const decipher = createDecipheriv(
      CIPHER_ALGORITHM,
      requireKey(keyId),
      Buffer.from(iv, 'hex'),
      { authTagLength: AUTH_TAG_BYTE_LENGTH }
   );
   decipher.setAuthTag(Buffer.from(authTag, 'hex'));

   return Buffer.concat([
      decipher.update(Buffer.from(ciphertext, 'hex')),
      decipher.final(),
   ]).toString('utf8');
}

/* Rotation helper: true while a stored secret is still under the active key. Once no stored secret says `false`, an old key can be retired from the ring. */
export function isEncryptedWithActiveKey(stored: string): boolean {
   return stored.startsWith(`${activeKeyId}${TOTP_SECRET_SEPARATOR}`);
}

// ── Recovery codes ───────────────────────────────────────────────────────────────
/* Plaintext codes: generate once, show once, store only their hashes. */
export function generateRecoveryCodes(): string[] {
   return Array.from({ length: TOTP_RECOVERY_CODE_COUNT }, () => {
      const a = randomBytes(RECOVERY_CODE_PART_BYTE_LENGTH)
         .toString('hex')
         .toUpperCase();
      const b = randomBytes(RECOVERY_CODE_PART_BYTE_LENGTH)
         .toString('hex')
         .toUpperCase();
      return `${a}${RECOVERY_CODE_SEPARATOR}${b}`;
   });
}

/* A plain SHA-256 of an 80-bit random code. It is deliberately NOT keyed with the TOTP encryption key: if it were, rotating that key would silently invalidate every stored recovery code. An 80-bit random input cannot be brute-forced offline, so a keyed hash would buy nothing here. Canonicalised (upper-case, trimmed) so case-insensitive entry still matches. */
export function hashRecoveryCode(code: string): string {
   return generateStandardHash(code.toUpperCase().trim());
}
