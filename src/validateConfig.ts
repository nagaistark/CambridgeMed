import 'dotenv/config';
import { env } from 'node:process';
import { Buffer } from 'node:buffer';
import { Schema, ParseResult, Either, Redacted } from 'effect';
import { TOTP_KEY_ID_PATTERN, totpKeyIdRegex } from '@ssot/totp_constants.ts';
import {
   customTrim,
   positiveIntegerStringToNumber,
} from '@utils/effectSchemaReusables.ts';

// ===== BASIC LEAF SCHEMAS ========================================================
const nonEmptyReasonablyLongString = customTrim.pipe(
   Schema.minLength(1, { message: () => `Variable is empty or missing.` }),
   Schema.maxLength(512, {
      message: () => `Variable exceeds the maximum allowed length (512).`,
   })
);

/* Deliberately not trimmed! A PEM key's format is anchored on a literal trailing '\n' after '-----END ... KEY-----' — trimming it would silently strip the very character the shape-check below requires. */
const boundedString = Schema.String.pipe(
   Schema.minLength(1, { message: () => `Variable is empty or missing.` }),
   Schema.maxLength(4096, {
      message: () => `Variable exceeds the maximum allowed length.`,
   })
);

const portNumber = positiveIntegerStringToNumber.pipe(
   Schema.filter((port: number) => port <= 65535, {
      message: () => `Port must be between 1 and 65535.`,
   })
);

// ===== SECRETS (wrapped in Redacted) =============================================
const mongoConnectionUriPattern =
   /^mongodb(\+srv)?:\/\/(?:[^:@]+:[^:@]+@)?[^/]+(?:\/[^?]*)?(?:\?.*)?$/;

const mongoConnectionUri = nonEmptyReasonablyLongString.pipe(
   Schema.pattern(mongoConnectionUriPattern, {
      message: () =>
         `Connection string doesn't conform to the expected MongoDB URI pattern.`,
   })
);

/* Connection strings embed credentials (`user:pass@host`), so they're redacted just like the other secrets below — a stray `logger.info(myEnv.database.appUri)` anywhere downstream now prints `<redacted>` instead of a password. */
const redactedMongoConnectionUri = Schema.Redacted(mongoConnectionUri);

const pemPrivateKey = boundedString.pipe(
   Schema.filter(
      (str: string) =>
         str.startsWith('-----BEGIN PRIVATE KEY-----') &&
         str.endsWith('-----END PRIVATE KEY-----\n'),
      {
         message: () =>
            `JWT_PRIVATE_KEY does not look like a valid PKCS#8 PEM private key.`,
      }
   )
);
const redactedPemPrivateKey = Schema.Redacted(pemPrivateKey);

/* The public key is, by definition, public. Redacting it would just be theatre. */
const pemPublicKey = boundedString.pipe(
   Schema.filter(
      (str: string) =>
         str.startsWith('-----BEGIN PUBLIC KEY-----') &&
         str.endsWith('-----END PUBLIC KEY-----\n'),
      {
         message: () =>
            `JWT_PUBLIC_KEY does not look like a valid SPKI PEM public key.`,
      }
   )
);

const resendApiKey = nonEmptyReasonablyLongString.pipe(
   Schema.pattern(/^[a-zA-Z0-9\-._]{36}$/, {
      message: () => `String doesn't conform to the Resend API key pattern.`,
   })
);
const redactedResendApiKey = Schema.Redacted(resendApiKey);

/* A conservative, dependency-free email check. */
const emailAddress = nonEmptyReasonablyLongString.pipe(
   Schema.pattern(
      /^(?!\.)(?!.*\.\.)([A-Za-z0-9_'+-.]*)[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9-]*\.)+[A-Za-z]{2,}$/,
      { message: () => `Email is badly formatted.` }
   )
);

/* 32 bytes (256 bits) is a reasonable minimum for a pepper that strengthens every password hash in the system — matches the rigor already applied to totpEncryptionKey below. */
const argon2SecretBuffer = Schema.transform(
   nonEmptyReasonablyLongString,
   Schema.instanceOf(Buffer),
   {
      strict: true,
      decode: (str: string) => Buffer.from(str, 'utf8'),
      encode: (buf: Buffer) => buf.toString('utf8'),
   }
).pipe(
   Schema.filter((buf: Buffer) => buf.length >= 32, {
      message: () =>
         `ARGON2_SECRET must be at least 32 bytes long once UTF-8 encoded.`,
   })
);
const redactedArgon2Secret = Schema.Redacted(argon2SecretBuffer);

const httpUrl = Schema.transformOrFail(
   nonEmptyReasonablyLongString,
   Schema.String,
   {
      strict: true,
      decode: (str, _options, ast) => {
         if (!URL.canParse(str)) {
            return ParseResult.fail(
               new ParseResult.Type(ast, str, `The URL is badly formatted.`)
            );
         }
         const { protocol, origin } = new URL(str);
         return protocol === 'https:' || protocol === 'http:'
            ? ParseResult.succeed(origin)
            : ParseResult.fail(
                 new ParseResult.Type(
                    ast,
                    str,
                    `The URL must use http or https.`
                 )
              );
      },
      encode: str => ParseResult.succeed(str),
   }
);

const totpKeyId = nonEmptyReasonablyLongString.pipe(
   Schema.pattern(totpKeyIdRegex, {
      message: () => `TOTP key id must be 1-16 lowercase letters or digits.`,
   })
);

/* 32 bytes in base64 are always 43 characters plus one '=' pad. Anchoring on that, instead of trusting Buffer.from(…, 'base64') (which silently skips garbage), makes a typo fail loudly at startup. */
const totpKeyringEntryRegex = new RegExp(
   `^(${TOTP_KEY_ID_PATTERN}):([A-Za-z0-9+/]{43}=)$`
);

const totpKeyring = Schema.transformOrFail(
   nonEmptyReasonablyLongString,
   Schema.ReadonlyMapFromSelf({
      key: Schema.String,
      value: Schema.instanceOf(Buffer),
   }),
   {
      strict: true,
      decode: (str, _options, ast) => {
         /* '<redacted>' as the `actual`: this input IS the secret. */
         const fail = (message: string) =>
            ParseResult.fail(new ParseResult.Type(ast, '<redacted>', message));

         const keys = new Map<string, Buffer>();
         for (const entry of str
            .split(',')
            .map(part => part.trim())
            .filter(Boolean)) {
            const match = totpKeyringEntryRegex.exec(entry);
            if (match === null) {
               return fail(
                  `Each TOTP_ENCRYPTION_KEYRING entry must look like "<id>:<base64 of 32 bytes>".`
               );
            }
            const [, id, encoded] = match;
            if (keys.has(id)) {
               return fail(
                  `TOTP_ENCRYPTION_KEYRING contains the key id "${id}" twice.`
               );
            }
            const key = Buffer.from(encoded, 'base64');
            if (key.length !== 32) {
               return fail(`Key "${id}" must decode to exactly 32 bytes.`);
            }
            keys.set(id, key);
         }

         return keys.size > 0
            ? ParseResult.succeed(keys)
            : fail(`TOTP_ENCRYPTION_KEYRING must contain at least one key.`);
      },
      encode: keys =>
         ParseResult.succeed(
            [...keys]
               .map(([id, key]) => `${id}:${key.toString('base64')}`)
               .join(',')
         ),
   }
);
const redactedTotpKeyring = Schema.Redacted(totpKeyring);

const TotpEncryptionConfigSchema = Schema.Struct({
   keyring: redactedTotpKeyring,
   activeKeyId: totpKeyId,
}).pipe(
   Schema.filter(
      ({ keyring, activeKeyId }) => Redacted.value(keyring).has(activeKeyId),
      {
         message: () =>
            `TOTP_ACTIVE_KEY_ID must name a key present in TOTP_ENCRYPTION_KEYRING.`,
      }
   )
);

const commaSeparatedOrigins = Schema.transform(
   nonEmptyReasonablyLongString,
   Schema.Array(httpUrl),
   {
      strict: true,
      decode: (str: string) =>
         str
            .split(',')
            .map(v => v.trim())
            .filter(Boolean),
      encode: (arr: readonly string[]) => arr.join(','),
   }
).pipe(
   Schema.filter((arr: readonly string[]) => arr.length > 0, {
      message: () => `At least one CORS origin must be specified.`,
   })
);

// ===== COMPOSITE SCHEMA ==========================================================
const DatabaseConfigSchema = Schema.Struct({
   appUri: redactedMongoConnectionUri,
   authUri: redactedMongoConnectionUri,
   auditUri: redactedMongoConnectionUri,
   maxPoolSize: positiveIntegerStringToNumber,
   serverSelectionTimeoutMS: positiveIntegerStringToNumber,
   socketTimeoutMS: positiveIntegerStringToNumber,
   heartbeatFrequencyMS: positiveIntegerStringToNumber,
   maxRetries: positiveIntegerStringToNumber,
   baseDelay: positiveIntegerStringToNumber,
   gracePeriodMS: positiveIntegerStringToNumber,
}).pipe(
   /* This is the "two dials that must stay in proportion" check — the grace period is meaningless as a safety margin unless it's a multiple of how often we're even allowed to notice a problem (heartbeatFrequencyMS). Effect Schema's Struct-level filter is the direct equivalent of Valibot's forward(check(...), [...]) — same cross-field logic, no separate helper. */
   Schema.filter(
      ({ heartbeatFrequencyMS, gracePeriodMS }) =>
         gracePeriodMS >= heartbeatFrequencyMS * 3,
      {
         message: () =>
            `GRACE_PERIOD_MS should be at least three times HEARTBEAT_FREQUENCY_MS.`,
      }
   )
);

const ConfigSchema = Schema.Struct({
   environment: Schema.Literal('development', 'production', 'test'),
   database: DatabaseConfigSchema,
   server: Schema.Struct({
      host: nonEmptyReasonablyLongString,
      port: portNumber,
   }),
   cors: Schema.Struct({
      origins: commaSeparatedOrigins,
   }),
   jwt: Schema.Struct({
      privateKey: redactedPemPrivateKey,
      publicKey: pemPublicKey,
   }),
   resend: Schema.Struct({
      apiKey: redactedResendApiKey,
      from: emailAddress,
   }),
   argon2Secret: redactedArgon2Secret,
   appBaseUrl: httpUrl,
   totpEncryption: TotpEncryptionConfigSchema,
});

export type Env = Schema.Schema.Type<typeof ConfigSchema>;

// ===== VALIDATION ENTRY POINT ====================================================
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
   totpEncryption: {
      keyring: env.TOTP_ENCRYPTION_KEYRING,
      activeKeyId: env.TOTP_ACTIVE_KEY_ID,
   },
};

/* ArrayFormatter walks the issue tree and gives back only `{ path, message }` per issue — it never echoes the raw offending value back at you. Combined with Redacted above, there are now two independent layers between a bad secret and your log stream: the formatter doesn't expose values, and even if it somehow did, Redacted values print as `<redacted>` regardless of what wraps them. */
function formatConfigErrors(error: ParseResult.ParseError): string {
   return ParseResult.ArrayFormatter.formatErrorSync(error)
      .map(
         issue => `  • [${issue.path.join('.') || '(root)'}] ${issue.message}`
      )
      .join('\n');
}

function validateConfig(): Env {
   const result = Schema.decodeUnknownEither(ConfigSchema)(rawConfig, {
      onExcessProperty: 'error',
      errors: 'all',
   });

   if (Either.isLeft(result)) {
      process.stderr.write(
         `Configuration validation failed. The server cannot start until these are fixed:\n${formatConfigErrors(result.left)}\n`
      );
      return process.exit(1);
   }

   return result.right;
}

export const myEnv: Env = validateConfig();
