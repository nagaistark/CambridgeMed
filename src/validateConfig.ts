import 'dotenv/config';
import { env } from 'node:process';
import logger from 'logger.ts';
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
   maxLength,
   check,
   regex,
   digits,
   number,
   url,
   picklist,
   email,
   forward,
} from 'valibot';
import { Buffer } from 'node:buffer';

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

const stringContainingpositiveIntegerInputString = pipe(
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
   regex(/^[a-zA-Z0-9\-._]{36}$/, `String doesn't conform to the pattern.`)
);

const ConfigSchema = strictObject({
   environment: picklist(
      ['development', 'production', 'test'],
      `Must be 'development', 'production' or 'test'.`
   ),
   database: pipe(
      strictObject({
         appUri: pipe(nonEmptyReasonablyLongString, mongoConnStrPattern),
         authUri: pipe(nonEmptyReasonablyLongString, mongoConnStrPattern),
         auditUri: pipe(nonEmptyReasonablyLongString, mongoConnStrPattern),
         maxPoolSize: stringContainingpositiveIntegerInputString,
         serverSelectionTimeoutMS: stringContainingpositiveIntegerInputString,
         socketTimeoutMS: stringContainingpositiveIntegerInputString,
         heartbeatFrequencyMS: stringContainingpositiveIntegerInputString,
         maxRetries: stringContainingpositiveIntegerInputString,
         baseDelay: stringContainingpositiveIntegerInputString,
         gracePeriodMS: stringContainingpositiveIntegerInputString,
      }),
      forward(
         check(({ heartbeatFrequencyMS, gracePeriodMS }) => {
            return gracePeriodMS >= heartbeatFrequencyMS * 3;
         }, `Grace period should be at least a few multiples of the heartbeat frequency.`),
         ['gracePeriodMS']
      )
   ),
   server: strictObject({
      host: nonEmptyReasonablyLongString,
      port: pipe(
         stringContainingpositiveIntegerInputString,
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
   }),
   resend: strictObject({
      apiKey: resendApiKeys,
      from: pipe(
         nonEmptyReasonablyLongString,
         email(`Email is badly formatted.`)
      ),
   }),
   argon2Secret: pipe(
      nonEmptyReasonablyLongString,
      transform(str => Buffer.from(str))
   ),
   appBaseUrl: pipe(
      nonEmptyReasonablyLongString,
      url(`The URL is badly formatted.`)
   ),
   totpEncryptionKey: pipe(
      string(`TOTP_ENCRYPTION_KEY must be a string.`),
      trim(),
      check(str => {
         const buf = Buffer.from(str, 'base64');
         return buf.length === 32;
      }, `TOTP_ENCRYPTION_KEY must be a base64 string that decodes to exactly 32 bytes.`),
      transform(str => Buffer.from(str, 'base64'))
   ),
});

const rawConfig = {
   environment: env.NODE_ENV,
   database: {
      appUri: env.DB_APP_URI,
      authUri: env.DB_AUTH_URI,
      auditUri: env.DB_AUDIT_URI,
      maxPoolSize: env.MAX_POOL_SIZE,
      serverSelectionTimeoutMS: env.DB_SERVER_SELECTION_TIMEOUT_MS,
      socketTimeoutMS: env.SOCKET_TIMEOUT_MS,
      heartbeatFrequencyMS: env.HEARTBEAT_FREQUENCY_MS,
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
   },
   resend: {
      apiKey: env.RESEND_API_KEY,
      from: env.RESEND_FROM,
   },
   argon2Secret: env.ARGON2_SECRET,
   appBaseUrl: env.APP_BASE_URL,
   totpEncryptionKey: env.TOTP_ENCRYPTION_KEY,
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
