import 'dotenv/config';
import { env } from 'node:process';
import { Buffer } from 'node:buffer';
import { Schema, ParseResult, Either } from 'effect';
import logger from 'logger.ts';

// ===== BASIC LEAF SCHEMAS ========================================================
/* Same pattern already used in effectSchemaReusables.ts's `customTrim` — kept identical here on purpose so this file reads the same way as the rest of the codebase. */
const trimmedString = Schema.transform(
   Schema.String,
   Schema.String.pipe(Schema.trimmed()),
   {
      decode: (str: string) => str.trim(),
      encode: (str: string) => str,
   }
);

const nonEmptyReasonablyLongString = trimmedString.pipe(
   Schema.minLength(1, { message: () => `Variable is empty or missing.` }),
   Schema.maxLength(512, {
      message: () => `Variable exceeds the maximum allowed length (512).`,
   })
);

/* Deliberately NOT built on `trimmedString`. A PEM key's format is anchored on a literal trailing '\n' after '-----END ... KEY-----' — trimming it would silently strip the very character the shape-check below requires. */
const boundedString = Schema.String.pipe(
   Schema.minLength(1, { message: () => `Variable is empty or missing.` }),
   Schema.maxLength(4096, {
      message: () => `Variable exceeds the maximum allowed length.`,
   })
);

/* String -> positive integer, in one bidirectional codec instead of a chain of independent checks. `digits`-only pattern first (so `Number("  ")` or `Number("")` never sneaks a NaN through), then the transform, then a safe-integer filter on the *decoded* side — mirrors the original digits() -> transform(Number) -> number() -> check() pipeline but as a single declared shape instead of four. */
const positiveIntegerString = Schema.transform(
   nonEmptyReasonablyLongString.pipe(
      Schema.pattern(/^[0-9]+$/, {
         message: () => `Must contain only digits.`,
      })
   ),
   Schema.Number.pipe(
      Schema.int(),
      Schema.positive({ message: () => `Must be a positive integer.` })
   ),
   {
      strict: true,
      decode: (str: string) => Number(str),
      encode: (num: number) => String(num),
   }
).pipe(
   Schema.filter((num: number) => Number.isSafeInteger(num), {
      message: () => `Value exceeds the safely representable integer range.`,
   })
);

const portNumber = positiveIntegerString.pipe(
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
         try {
            new URL(str);
            return ParseResult.succeed(str);
         } catch {
            return ParseResult.fail(
               new ParseResult.Type(ast, str, `The URL is badly formatted.`)
            );
         }
      },
      encode: str => ParseResult.succeed(str),
   }
);

const base64Exact32Bytes = Schema.transformOrFail(
   trimmedString,
   Schema.instanceOf(Buffer),
   {
      strict: true,
      decode: (str, _options, ast) => {
         const buf = Buffer.from(str, 'base64');
         return buf.length === 32
            ? ParseResult.succeed(buf)
            : ParseResult.fail(
                 new ParseResult.Type(
                    ast,
                    str,
                    `TOTP_ENCRYPTION_KEY must be a base64 string that decodes to exactly 32 bytes.`
                 )
              );
      },
      encode: buf => ParseResult.succeed(buf.toString('base64')),
   }
);
const redactedTotpKey = Schema.Redacted(base64Exact32Bytes);

const commaSeparatedOrigins = Schema.transform(
   nonEmptyReasonablyLongString,
   Schema.Array(Schema.String),
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
   maxPoolSize: positiveIntegerString,
   serverSelectionTimeoutMS: positiveIntegerString,
   socketTimeoutMS: positiveIntegerString,
   heartbeatFrequencyMS: positiveIntegerString,
   maxRetries: positiveIntegerString,
   baseDelay: positiveIntegerString,
   gracePeriodMS: positiveIntegerString,
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
   totpEncryptionKey: redactedTotpKey,
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
   totpEncryptionKey: env.TOTP_ENCRYPTION_KEY,
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
      onExcessProperty: 'error', // the Effect equivalent of Valibot's strictObject
      errors: 'all', // report every problem in one pass, not just the first
   });

   if (Either.isLeft(result)) {
      logger.error(
         `Configuration validation failed. The server cannot start until these are fixed:\n${formatConfigErrors(result.left)}`
      );
      return process.exit(1);
   }

   return result.right;
}

export const myEnv: Env = validateConfig();
