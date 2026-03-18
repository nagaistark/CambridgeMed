import 'dotenv/config';
import { env } from 'node:process';
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
   number,
   parseJson,
   email,
   picklist,
   record,
   url,
} from 'valibot';
import { userRoles, type UserRole } from '@/_SSOT/user_roles_constants.ts';
import { makePicklist } from '@/utils/arrayToValPicklist.ts';

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
   transform(Number),
   number(`Must be a numeric value`),
   check(val => val > 0 && val <= Number.MAX_SAFE_INTEGER)
);

const mongoConnStrPattern = regex(
   /^mongodb(\+srv)?:\/\/(?:[^:@]+:[^:@]+@)?[^/]+(?:\/[^?]*)?(?:\?.*)?$/,
   `Connection string doesn't conform to the pattern.`
);

const resendApiKeys = pipe(
   string(`Must be a string.`),
   trim(),
   regex(/^[a-zA-Z0-9\-\._]{36}$/, `String doesn't conform to the pattern.`)
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
   apiKeys: strictObject({
      resend: resendApiKeys,
   }),
   whiteList: pipe(
      string(`The Whitelist must be a string.`),
      parseJson(),
      record(
         pipe(
            string(`The key must be a string.`),
            email(`The email is badly formatted.`),
            transform(str => str.toLowerCase())
         ),
         makePicklist(userRoles)
      )
   ),
   appBaseUrl: pipe(
      nonEmptyReasonablyLongString,
      url(`The URL is badly formatted.`)
   ),
});

const rawConfig = {
   database: {
      appUri: env.DB_APP_URI,
      authUri: env.DB_AUTH_URI,
      maxPoolSize: env.MAX_POOL_SIZE,
      serverSelectionTimeoutMS: env.DB_SERVER_SELECTION_TIMEOUT_MS,
      socketTimeoutMS: env.SOCKET_TIMEOUT_MS,
      autoIndex: env.NODE_ENV === 'development',
      maxRetries: env.MAX_RETRIES,
      baseDelay: env.BASE_DELAY_MS,
      gracePeriodMS: env.GRACE_PERIOD_MS,
   },
   server: {
      host: env.HOST,
      port: env.PORT,
   },
   cors: {
      origins: env.CORS_ORIGINS,
   },
   jwt: {
      privateKey: env.JWT_PRIVATE_KEY,
      publicKey: env.JWT_PUBLIC_KEY,
      accessTokenExpiryMinutes: env.JWT_ACCESS_TOKEN_EXPIRY_MIN,
      refreshTokenExpiryDays: env.JWT_REFRESH_TOKEN_EXPIRY_DAYS,
   },
   apiKeys: {
      resend: env.RESEND_API_KEY,
   },
   whiteList: env.STAFF_WHITELIST,
   appBaseUrl: env.APP_BASE_URL,
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
export const staffWhiteList = new Map<string, UserRole>(
   Object.entries(myEnv.whiteList)
);
