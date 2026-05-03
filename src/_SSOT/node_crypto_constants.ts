import { randomBytes, createHash } from 'node:crypto';

// All the deterministic hashes across the projects are 48 bytes from crypto.randomBytes (that produce 96 character long string)

const TOKEN_BYTE_SIZE = 48 as const;
const CRYPTO_HASH_ALGO = 'sha256' as const;

export function generateRandomToken(): string {
   return randomBytes(TOKEN_BYTE_SIZE).toString('hex');
}

export function generateStandardHash(input: string): string {
   return createHash(CRYPTO_HASH_ALGO).update(input).digest('hex');
}

// Validates the raw token (96 chars)
export const HEX96_REGEX = /^[a-f0-9]{96}$/i;

// Validates a stored hash (64 chars)
const HEX64_REGEX = /^[a-f0-9]{64}$/i;

export const hexHashValidator = {
   validator: (str: string) => {
      if (str === null) return true;
      return HEX64_REGEX.test(str);
   },
   message: `Must be a 64-character hex string (SHA-256 digest).`,
};
