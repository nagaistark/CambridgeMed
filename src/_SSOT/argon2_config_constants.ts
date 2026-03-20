import argon2, { Options } from 'argon2';
import { randomBytes } from 'node:crypto';
import { myEnv } from '@/validateConfig.ts';

export const ARGON2_CONFIG: Options & { type: 2 } = {
   type: argon2.argon2id,
   version: 19,
   memoryCost: 65536, // 64 MB
   timeCost: 3, // iterations
   parallelism: 4, // threads
   hashLength: 32,
   salt: randomBytes(32),
   secret: myEnv.argon2Secret,
};
