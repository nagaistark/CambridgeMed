import 'dotenv/config';
import { env } from 'node:process';
import { Buffer } from 'node:buffer';
import { Schema, ParseResult, Either, Redacted } from 'effect';
import { TOTP_KEY_ID_PATTERN, totpKeyIdRegex } from '@ssot/totp_constants.ts';
import {
   clinicStaffEmail,
   customTrim,
   positiveIntegerStringToNumber,
} from '@utils/effectSchemaReusables.ts';
import { LIST_QUERY_MAX_TIME_MS } from '@ssot/pagination_constants.ts';

// ===== BASIC LEAF SCHEMAS ========================================================
const nonEmptyReasonablyLongString = customTrim.pipe(
   Schema.minLength(1, { message: () => `Variable is empty or missing.` }),
   Schema.maxLength(512, {
      message: () => `Variable exceeds the maximum allowed length (512).`,
   })
);

const boundedString = Schema.String.pipe(
   Schema.minLength(1, { message: () => `Variable is empty or missing.` }),
   Schema.maxLength(4096, {
      message: () => `Variable exceeds the maximum allowed length.`,
   })
);

const boundedIntegerString = (min: number, max: number) =>
   positiveIntegerStringToNumber.pipe(
      Schema.between(min, max, {
         message: () => `Must be between ${min} and ${max}.`,
      })
   );

const portNumber = positiveIntegerStringToNumber.pipe(
   Schema.filter((port: number) => port <= 65535, {
      message: () => `Port must be between 1 and 65535.`,
   })
);

// ===== SECRETS (wrapped in Redacted) =============================================
const mongoConnectionUriPattern =
   /^mongodb(?:\+srv)?:\/\/[^:@/\s]+:[^:@/\s]+@[^/?\s]+\/[^/?\s]+(?:\?.*)?$/;

const targetOf = (uri: Redacted.Redacted<string>): string | undefined =>
   /^mongodb(?:\+srv)?:\/\/[^@/]+@([^/]+\/[^/?]+)/.exec(
      Redacted.value(uri)
   )?.[1];

const mongoConnectionUri = nonEmptyReasonablyLongString.pipe(
   Schema.pattern(mongoConnectionUriPattern, {
      message: () =>
         `Connection string doesn't conform to the expected MongoDB URI pattern.`,
   })
);

/* Connection strings embed credentials (`user:pass@host`), so they're redacted just like the other secrets below — a stray `logger.info(myEnv.database.appUri)` anywhere downstream now prints `<redacted>` instead of a password. */
const redactedMongoConnectionUri = Schema.Redacted(mongoConnectionUri);

/* No `g` flag on purpose: `.test()` on a global regex is stateful. */
const TLS_REQUESTED = /[?&](?:tls|ssl)=true(?:&|$)/i;
const TLS_WEAKENED =
   /[?&](?:tls=false|ssl=false|tlsInsecure=true|tlsAllowInvalidCertificates=true|tlsAllowInvalidHostnames=true)(?:&|$)/i;

/* mongodb+srv:// implies TLS. Otherwise TLS must be requested explicitly, and nothing may weaken its verification. */
const hasVerifiedTransport = (uri: Redacted.Redacted<string>): boolean => {
   const value = Redacted.value(uri);
   if (TLS_WEAKENED.test(value)) return false;
   return value.startsWith('mongodb+srv://') || TLS_REQUESTED.test(value);
};

const resendApiKey = nonEmptyReasonablyLongString.pipe(
   Schema.pattern(/^re_[A-Za-z0-9_]+$/, {
      message: () => `String doesn't conform to the Resend API key pattern.`,
   })
);
const redactedResendApiKey = Schema.Redacted(resendApiKey);

/* 32 bytes (256 bits) is a reasonable minimum for a pepper that strengthens every password hash in the system — matches the rigor already applied to totpEncryptionKey below. */
const argon2SecretBuffer = Schema.transform(
   boundedString,
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
         /* '<redacted>' as the `actual`: a misconfigured URL may embed credentials. */
         const fail = (message: string) =>
            ParseResult.fail(new ParseResult.Type(ast, '<redacted>', message));

         if (!URL.canParse(str)) return fail(`The URL is badly formatted.`);

         const {
            protocol,
            origin,
            pathname,
            search,
            hash,
            username,
            password,
         } = new URL(str);

         if (protocol !== 'https:' && protocol !== 'http:') {
            return fail(`The URL must use http or https.`);
         }

         if (
            pathname !== '/' ||
            search !== '' ||
            hash !== '' ||
            username !== '' ||
            password !== ''
         ) {
            return fail(
               `The URL must be a bare origin (scheme://host[:port]) with no path, query, fragment or credentials.`
            );
         }

         return ParseResult.succeed(origin);
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
   maxPoolSize: boundedIntegerString(1, 100),
   serverSelectionTimeoutMS: boundedIntegerString(1_000, 60_000),
   socketTimeoutMS: boundedIntegerString(1_000, 300_000),
   heartbeatFrequencyMS: boundedIntegerString(500, 60_000), // driver minimum is 500
   waitQueueTimeoutMS: boundedIntegerString(100, 60_000),
   maxRetries: boundedIntegerString(1, 10),
   baseDelay: boundedIntegerString(100, 10_000),
   gracePeriodMS: boundedIntegerString(1_000, 600_000),
}).pipe(
   /* This is the "two dials that must stay in proportion" check — the grace period is meaningless as a safety margin unless it's a multiple of how often we're even allowed to notice a problem (heartbeatFrequencyMS). Effect Schema's Struct-level filter is the direct equivalent of Valibot's forward(check(...), [...]) — same cross-field logic, no separate helper. */
   Schema.filter(
      ({ heartbeatFrequencyMS, gracePeriodMS }) =>
         gracePeriodMS >= heartbeatFrequencyMS * 3,
      {
         message: () =>
            `GRACE_PERIOD_MS should be at least three times HEARTBEAT_FREQUENCY_MS.`,
      }
   ),
   Schema.filter(
      ({ appUri, authUri, auditUri }) =>
         new Set([targetOf(appUri), targetOf(authUri), targetOf(auditUri)])
            .size === 3,
      {
         message: () =>
            `DB_APP_URI, DB_AUTH_URI and DB_AUDIT_URI must target three different host/database pairs.`,
      }
   ),
   Schema.filter(
      ({ socketTimeoutMS }) => socketTimeoutMS > LIST_QUERY_MAX_TIME_MS,
      {
         message: () =>
            `SOCKET_TIMEOUT_MS must exceed LIST_QUERY_MAX_TIME_MS, or the socket dies before the server can report the timeout.`,
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
   resend: Schema.Struct({
      apiKey: redactedResendApiKey,
      from: clinicStaffEmail,
   }),
   argon2Secret: redactedArgon2Secret,
   appBaseUrl: httpUrl,
   totpEncryption: TotpEncryptionConfigSchema,
}).pipe(
   Schema.filter(
      ({ environment, appBaseUrl, cors }) =>
         environment === 'test' ||
         [appBaseUrl, ...cors.origins].every(origin =>
            origin.startsWith('https://')
         ),
      {
         message: () =>
            `APP_BASE_URL and every CORS origin must use https (Secure cookies are never sent over http).`,
      }
   ),
   Schema.filter(({ appBaseUrl, cors }) => cors.origins.includes(appBaseUrl), {
      message: () => `APP_BASE_URL must be one of CORS_ORIGINS.`,
   }),
   Schema.filter(({ environment, database }) => {
      const issues: Array<Schema.FilterIssue> = [];
      if (environment !== 'production') return issues;

      const uris = [
         ['appUri', database.appUri],
         ['authUri', database.authUri],
         ['auditUri', database.auditUri],
      ] as const;

      for (const [key, uri] of uris) {
         if (!hasVerifiedTransport(uri)) {
            issues.push({
               path: ['database', key],
               message: `In production this MongoDB URI must use mongodb+srv:// or tls=true, and must not disable certificate or hostname verification.`,
            });
         }
      }
      return issues;
   })
);

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
      waitQueueTimeoutMS: env.DB_WAIT_QUEUE_TIMEOUT_MS,
      maxRetries: env.DB_MAX_RETRIES,
      baseDelay: env.DB_BASE_DELAY_MS,
      gracePeriodMS: env.DB_GRACE_PERIOD_MS,
   },
   server: {
      host: env.HOST,
      port: env.PORT,
   },
   cors: {
      origins: env.CORS_ORIGINS,
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
