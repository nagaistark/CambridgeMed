import { randomBytes } from 'node:crypto';

// All the deterministic hashes across the projects are 48 bytes from crypto.randomBytes (that produce 96 character long string)

const TOKEN_BYTE_SIZE: number = 48;

export function generateRandomToken(): string {
   return randomBytes(TOKEN_BYTE_SIZE).toString('hex');
}

export const HEX96_REGEX = /^[a-f0-9]{96}$/i;

export const hexHashValidator = {
   validator: (str: string) => HEX96_REGEX.test(str),
   message: `Must be a 64-character hex string (SHA-256 digest).`,
};
