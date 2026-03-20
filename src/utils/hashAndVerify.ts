import argon2 from 'argon2';
import { ARGON2_CONFIG } from '@ssot/argon2_config_constants.ts';

export async function hashPassword(password: string): Promise<string> {
   return await argon2.hash(password, ARGON2_CONFIG);
}

export async function verifyPassword(
   hash: string,
   password: string
): Promise<boolean> {
   if (!hash || !password || !hash.startsWith('$argon2')) return false;
   return await argon2.verify(hash, password);
}
