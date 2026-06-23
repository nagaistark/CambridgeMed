import '@ssot/date_time_constants.ts';
import {
   check,
   integer,
   minLength,
   minValue,
   maxLength,
   number,
   pipe,
   regex,
   string,
   transform,
   trim,
   strictObject,
   InferOutput,
   object,
   fallback,
   toNumber,
   optional,
   maxValue,
   instance,
   date,
   ip,
   email,
} from 'valibot';
import { DateTime } from 'luxon';
import { ObjectId } from 'mongodb';
import { MIN_LEGAL_AGE } from '@ssot/policy_constants.ts';
import { paginationLimit } from '@ssot/pagination_constants.ts';
import { HEX64_REGEX } from '@ssot/node_crypto_constants.ts';
import { argon2Regex } from '@ssot/argon2_config_constants.ts';
import { recoveryCodeRegex, totpSecretRegex } from '@ssot/totp_constants.ts';

const baseStringMaxLength = 128 as const;
const longStringMaxLength = 2056 as const;
export const shortDateRegex = /^\d{4}-\d{2}-\d{2}$/;
export const postalCodeCanadaRegex = /^[A-Za-z]\d[A-Za-z][ ]?\d[A-Za-z]\d$/i;
export const phoneNANPRegex = /^1?[2-9]\d{2}[2-9]\d{6}$/;
export const dinRegex = /^\d{8}$/;
export const snomedRegex = /^[1-9]\d{5,17}$/;

// ── Universal (primitive) validators  ────────────────────────────────────────────
export const baseString = pipe(
   string(`Must be a string (baseString).`),
   trim(),
   minLength(1, `String should be at least 1 character long (baseString).`),
   maxLength(baseStringMaxLength, `String is too long (baseString).`)
);

export const longString = pipe(
   string(`Must be a string (longString).`),
   trim(),
   minLength(1, `String should be at least 1 character long (longString).`),
   maxLength(longStringMaxLength, `String is too long (longString).`)
);

export const nameString = pipe(
   baseString,
   regex(
      /^[\p{L} .'\-'']+$/u,
      `Must not contain invalid or consecutive non-alphanumeric characters in name (nameString).`
   ),
   transform(name => {
      const words = name
         .split(/[\s-]+/)
         .map(w => `${w.slice(0, 1).toUpperCase()}${w.slice(1).toLowerCase()}`);
      const separators = name.match(/[\s-]+/g) ?? [];
      return words.reduce(
         (acc, cur, idx) => acc + cur + (separators[idx] ?? ''),
         ''
      );
   })
);

export const validateCanadianPostalCode = pipe(
   baseString,
   regex(
      postalCodeCanadaRegex,
      `Invalid Canadian postal code format (validateCanadianPostalCode).`
   )
);

export const validateNANPPhoneNumber = pipe(
   baseString,
   transform(phone => phone.replace(/[^\d]/g, '')),
   regex(
      phoneNANPRegex,
      `Must be an NANP phone number (validateNANPPhoneNumber).`
   )
);

export const validateEmail = pipe(
   baseString,
   email(`Incorrectly formatted email (validateEmail).`),
   transform(str => str.toLowerCase())
);

export const validateIPAddress = pipe(
   baseString,
   ip(`Invalid IP Address format (validateIPAddress).`)
);

export const validateDIN = pipe(
   baseString,
   regex(dinRegex, `DIN must be exactly 8 digits (validateDIN).`)
);

export const validateSnomed = pipe(
   baseString,
   regex(snomedRegex, `Invalid SNOMED code (validateSnomed).`)
);

export const Sha256HexString = pipe(
   string(`Must be a string to start with (Sha256HexString).`),
   regex(HEX64_REGEX, `Invalid SHA256 hash (Sha256HexString).`)
);

export const Argon2HashString = pipe(
   string(`Must be a string to start with (Argon2HashString).`),
   regex(argon2Regex, `Invalid Argon2 hash (Argon2HashString).`)
);

// ── [modelName]DocumentVSchema validators  ───────────────────────────────────────
export const positiveIntegerDocument = pipe(
   number(`Must be a number (valibot)`),
   integer(`Must be an integer (valibot)`),
   minValue(1, `Must be a positive integer number (valibot).`)
);

export const nonNegativeIntegerDocument = pipe(
   number(`Must be a number (valibot)`),
   integer(`Must be an integer (valibot)`),
   minValue(0, `Must be a non-negative integer number (valibot).`)
);

export const objectIdInstance = instance(
   ObjectId,
   `Must be an ObjectId instance (objectIdInstance).`
);

export const jsDateInThePast = pipe(
   date(`Must be a valid Date object (jsDateInThePast).`),
   check((date: Date) => {
      return date <= new Date();
   }, `Date cannot be in the future (jsDateInThePast).`)
);

export const jsDateInTheFuture = pipe(
   date(`Must be a valid Date object (jsDateInTheFuture).`),
   check((date: Date) => {
      return date >= new Date();
   }, `Date cannot be in the past (jsDateInTheFuture).`)
);

// ── [modelName]InputVSchema validators  ──────────────────────────────────────────
export const positiveIntegerInput = pipe(
   baseString,
   transform(val => parseInt(val, 10)),
   positiveIntegerDocument
);

export const nonNegativeIntegerInput = pipe(
   baseString,
   transform(val => parseInt(val, 10)),
   nonNegativeIntegerDocument
);

export const objectIdInput = pipe(
   baseString,
   regex(/^[a-f\d]{24}$/i, `Must be a valid ObjectId format (objectIdInput).`)
);

export const stringToObjectId = pipe(
   objectIdInput,
   transform((str: string): ObjectId => new ObjectId(str))
);

const validateCalendarDate = check((input: string) => {
   return DateTime.fromISO(input).isValid;
}, `Must be a valid calendar date (validateCalendarDate).`);

export const dateFromISOString = pipe(
   baseString,
   regex(
      /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}\.\d{1,3}Z)?$/,
      `Must be in either "YYYY-MM-DD" or "YYYY-MM-DDTHH:mm:ss.sssZ" format (valibot).`
   ),
   validateCalendarDate
);

// Used specifically for YYYY-MM-DD dates (10 characters only). E.g., birthdays or expiry dates. Outputs a YYYY-MM-DD string.
export const dateFromShortString = pipe(
   string(),
   regex(shortDateRegex, `Invalid date format (valibot).`),
   validateCalendarDate
);

// Checks Luxon's DateTime object constructed from simple 10-character string against LOCAL now. Outputs the same simple string.
export const validateExpiryDate = pipe(
   dateFromShortString,
   check(input => {
      return DateTime.fromISO(input).endOf('day') >= DateTime.now();
   }, `The health card has expired (valibot).`)
);

export const validateDOB = pipe(
   dateFromShortString,
   check(inputStr => {
      const dob = DateTime.fromISO(inputStr);
      const age = DateTime.now().diff(dob, 'years').years;
      return age >= MIN_LEGAL_AGE;
   }, `The patient must be at least ${MIN_LEGAL_AGE} years old (valibot).`),
   check(inputStr => {
      const year = parseInt(inputStr.split('-')[0], 10);
      return year > 1900;
   }, `The patient must be born after 1900 (valibot).`)
   // No transformations inside this schema. Outputs the same simple string as `dateFromShortString`.
);

export const stringDateInThePastOrOptionallyToday = pipe(
   // Accepts both short (YYYY-MM-DD — 10 characters) and long (YYYY-MM-DDTHH:mm:ss.sssZ — 24 characters) date strings.
   dateFromISOString,

   // Validate against the correct clock while we still have the raw string context.
   check(input => {
      const fromIso = DateTime.fromISO(input);

      if (input.length === 10) {
         /* Date in a distant past. In fact, so distant nobody remembers the exact time the event this date represents happened. Most of the time, these are either legacy dates or manually typed in ones. Short dates are valid for "today". */
         const todayLocal = DateTime.now().startOf('day');
         return fromIso.startOf('day') <= todayLocal;
      } else {
         /* Real-time Timestamp. This kind of timestamps are usually generated by the app itself. */
         return fromIso <= DateTime.now();
      }
   }, `Date cannot be in the future (valibot).`),

   // Now that it's validated, safely transform it into a JavaScript date (UTC-based).
   transform(input => {
      const fromIso = DateTime.fromISO(input);
      const output = input.length === 10 ? fromIso.startOf('day') : fromIso;
      return output.toJSDate();
   })
);

export const stringDateInTheFutureOrOptionallyToday = pipe(
   // Accepts both short (YYYY-MM-DD — 10 characters) and long (YYYY-MM-DDTHH:mm:ss.sssZ — 24 characters) date strings.
   dateFromISOString,
   check(input => {
      const fromIso = DateTime.fromISO(input);

      if (input.length === 10) {
         /* Date in the future. And we don't know the exact moment. Valid if "today". */
         const todayLocal = DateTime.now().endOf('day');
         return fromIso.endOf('day') >= todayLocal;
      } else {
         // Real-time Timestamp. Must be the current moment or later.
         return fromIso >= DateTime.now();
      }
   }, `Date cannot be in the past (valibot).`),

   transform(input => {
      const fromIso = DateTime.fromISO(input);
      // For termination boundaries, endOf('day') ensures the date covers the patient until the very last moment of that day.
      const output = input.length === 10 ? fromIso.endOf('day') : fromIso;
      return output.toJSDate();
   })
);

// ── TOTP-related checks ──────────────────────────────────────────────────────────
export const MongoIdParamSchema = strictObject({
   id: stringToObjectId,
});
export type IMongoIdParam = InferOutput<typeof MongoIdParamSchema>;

// ── TOTP-related checks ──────────────────────────────────────────────────────────
export const totpSecret = pipe(
   string(`Must be a string (totpSecret).`),
   regex(totpSecretRegex, `Invalid encrypted TOTP secret format (totpSecret).`)
);

export const recoveryCode = pipe(
   string(`Must be a string (recoveryCode).`),
   regex(recoveryCodeRegex, `Invalid recovery code format (recoveryCode).`)
);

// ── Reusable Pagination Schema (req.query) ───────────────────────────────────────
/* `object` (not `strictObject`) because URLs can carry arbitrary query params from browser extensions, analytics proxies, or CDN tools. */
export const CursorPaginationSchema = object({
   cursor: optional(
      pipe(string(`Cursor must be a string (CursorPaginationSchema).`), trim())
   ),
   limit: fallback(
      pipe(
         baseString,
         toNumber(),
         integer(),
         minValue(1, `Limit must be at least 1 (valibot).`),
         maxValue(paginationLimit, `Limit's too high (valibot).`)
      ),
      paginationLimit
   ),
});
