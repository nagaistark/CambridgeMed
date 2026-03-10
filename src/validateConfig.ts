import 'dotenv/config';
import logger from '@/logger.ts';
import {
   strictObject,
   pipe,
   string,
   transform,
   array,
   parse,
   InferOutput,
   minLength,
   trim,
   boolean,
   maxLength,
   check,
   regex,
   digits,
} from 'valibot';

const nonEmptyReasonablyLongString = pipe(
   string('Variable is not a string'),
   trim(),
   minLength(1),
   maxLength(512)
);

const pemPrivateKey = pipe(
   string('JWT_PRIVATE_KEY must be a string.'),
   minLength(1, 'JWT_PRIVATE_KEY cannot be empty.'),
   maxLength(2048),
   check(str => {
      return (
         str.startsWith('-----BEGIN PRIVATE KEY-----') &&
         str.endsWith('-----END PRIVATE KEY-----\n')
      );
   }, 'JWT_PRIVATE_KEY does not look like a valid PKCS#8 PEM private key.')
);

const pemPublicKey = pipe(
   string('JWT_PUBLIC_KEY must be a string.'),
   minLength(1, 'JWT_PUBLIC_KEY cannot be empty.'),
   maxLength(2048),
   check(str => {
      return (
         str.startsWith('-----BEGIN PUBLIC KEY-----') &&
         str.endsWith('-----END PUBLIC KEY-----\n')
      );
   }, 'JWT_PUBLIC_KEY does not look like a valid SPKI PEM public key')
);

const stringContainingPositiveInteger = pipe(
   nonEmptyReasonablyLongString,
   digits(),
   transform(str => Number(str)),
   check(val => val > 0 && val <= Number.MAX_SAFE_INTEGER)
);

const mongoConnStrPattern = regex(
   /^mongodb(\+srv)?:\/\/(?:[^:@]+:[^:@]+@)?[^/]+(?:\/[^?]*)?(?:\?.*)?$/,
   `Connection string doesn't conform to the pattern.`
);

const ConfigSchema = strictObject({
   database: strictObject({
      appUri: pipe(nonEmptyReasonablyLongString, mongoConnStrPattern),
      authUri: pipe(nonEmptyReasonablyLongString, mongoConnStrPattern),
      maxPoolSize: stringContainingPositiveInteger,
      serverSelectionTimeoutMS: stringContainingPositiveInteger,
      socketTimeoutMS: stringContainingPositiveInteger,
      autoIndex: boolean(),
      maxRetries: stringContainingPositiveInteger,
      baseDelay: stringContainingPositiveInteger,
      gracePeriodMS: stringContainingPositiveInteger,
   }),
   server: strictObject({
      host: nonEmptyReasonablyLongString,
      port: pipe(
         stringContainingPositiveInteger,
         check(v => {
            return v <= 65535;
         })
      ),
   }),
   cors: strictObject({
      origins: pipe(
         nonEmptyReasonablyLongString,
         transform(v =>
            v
               .split(',')
               .map(v => v.trim())
               .filter(Boolean)
         ),
         array(string())
      ),
   }),
   jwt: strictObject({
      privateKey: pemPrivateKey,
      publicKey: pemPublicKey,
      accessTokenExpiryMinutes: stringContainingPositiveInteger,
      refreshTokenExpiryDays: stringContainingPositiveInteger,
   }),
});

const rawConfig = {
   database: {
      appUri: process.env.DB_APP_URI,
      authUri: process.env.DB_AUTH_URI,
      maxPoolSize: process.env.MAX_POOL_SIZE,
      serverSelectionTimeoutMS: process.env.DB_SERVER_SELECTION_TIMEOUT_MS,
      socketTimeoutMS: process.env.SOCKET_TIMEOUT_MS,
      autoIndex: process.env.NODE_ENV === 'development',
      maxRetries: process.env.MAX_RETRIES,
      baseDelay: process.env.BASE_DELAY_MS,
      gracePeriodMS: process.env.GRACE_PERIOD_MS,
   },
   server: {
      host: process.env.HOST,
      port: process.env.PORT,
   },
   cors: {
      origins: process.env.CORS_ORIGINS,
   },
   jwt: {
      privateKey: process.env.JWT_PRIVATE_KEY,
      publicKey: process.env.JWT_PUBLIC_KEY,
      accessTokenExpiryMinutes: process.env.JWT_ACCESS_TOKEN_EXPIRY_MIN,
      refreshTokenExpiryDays: process.env.JWT_REFRESH_TOKEN_EXPIRY_DAYS,
   },
};

type Env = InferOutput<typeof ConfigSchema>;

function validateConfig(): Env {
   try {
      return parse(ConfigSchema, rawConfig);
   } catch (err) {
      logger.error(`Configuration validation error: ${err}`);
      process.exit(1);
   }
}

export const myEnv: Env = validateConfig();
