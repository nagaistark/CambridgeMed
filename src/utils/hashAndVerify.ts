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
   return await argon2.verify(hash, password, { secret: ARGON2_CONFIG.secret });
}

/* True when the parameters embedded in `hash` differ from the current config. Only the four comparable parameters are passed, so the pepper never enters this call. The library throws on a malformed digest; such a hash cannot be upgraded anyway, so we answer "no". */
export function needsRehash(hash: string): boolean {
   try {
      return argon2.needsRehash(hash, {
         memoryCost: ARGON2_CONFIG.memoryCost,
         timeCost: ARGON2_CONFIG.timeCost,
         parallelism: ARGON2_CONFIG.parallelism,
         version: ARGON2_CONFIG.version,
      });
   } catch {
      return false;
   }
}
