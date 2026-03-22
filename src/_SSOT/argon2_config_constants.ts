import argon2, { Options } from 'argon2';
import { myEnv } from '@/validateConfig.ts';

export const ARGON2_CONFIG: Options & { type: 2 } = {
   type: argon2.argon2id,
   version: 19,
   memoryCost: 65536, // 64 MB
   timeCost: 3, // iterations
   parallelism: 4, // threads
   hashLength: 32,
   secret: myEnv.argon2Secret,
};

export const argon2Regex =
   /^\$argon2id\$v=19\$m=65536,t=3,p=4\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/;
