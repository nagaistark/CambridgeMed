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
   union,
   strictObject,
   InferOutput,
   object,
   fallback,
   toNumber,
   optional,
   maxValue,
   instance,
   date,
} from 'valibot';
import { DateTime } from 'luxon';
import { MIN_LEGAL_AGE } from '@ssot/policy_constants.ts';
import { paginationLimit } from '@ssot/pagination_constants.ts';
import { HEX64_REGEX } from '@ssot/node_crypto_constants.ts';
import { ObjectId } from 'mongodb';

const baseStringMaxLength = 128 as const;
const longStringMaxLength = 2056 as const;
export const shortDateRegex = /^\d{4}-\d{2}-\d{2}$/;
export const postalCodeCanadaRegex = /^[A-Za-z]\d[A-Za-z][ ]?\d[A-Za-z]\d$/i;
export const phoneNANPRegex = /^1?[2-9]\d{2}[2-9]\d{6}$/;
export const dinRegex = /^\d{8}$/;
export const snomedRegex = /^[1-9]\d{5,17}$/;

export const baseString = pipe(
   string(`Must be a string (valibot).`),
   trim(),
   minLength(1, `String should be at least 1 character long (valibot).`),
   maxLength(baseStringMaxLength, `String is too long (valibot).`)
);

export const longString = pipe(
   string(`Must be a string (valibot).`),
   trim(),
   minLength(1, `String should be at least 1 character long (valibot).`),
   maxLength(longStringMaxLength, `String is too long (valibot).`)
);

export const nameString = pipe(
   baseString,
   regex(
      /^[\p{L} .'\-'']+$/u,
      `Must not contain invalid or consecutive non-alphanumeric characters in name (valibot).`
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

export const positiveInteger = pipe(
   baseString,
   transform(val => parseInt(val, 10)),
   number(`Must be a number (valibot)`),
   integer(`Must be an integer (valibot)`),
   minValue(1, `Must be a positive integer number (valibot).`)
);

export const objectIdStringCheck = pipe(
   baseString,
   regex(/^[a-f\d]{24}$/i, `Must be a valid ObjectId format (valibot).`)
);

export const objectIdSchema = pipe(
   objectIdStringCheck,
   transform((str: string): ObjectId => new ObjectId(str))
);

export const objectIdInstance = instance(
   ObjectId,
   `Must be an ObjectId instance (valibot).`
);

export const idOrName = union(
   [objectIdStringCheck, nameString],
   `Must be either an ID or a name (valibot).`
);

export const MongoIdParamSchema = strictObject({
   id: objectIdStringCheck,
});

export type IMongoIdParam = InferOutput<typeof MongoIdParamSchema>;

const validateCalendarDate = check((input: string) => {
   return DateTime.fromISO(input).isValid;
}, `Must be a valid calendar date (valibot).`);

export const dateFromString = pipe(
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
   dateFromString,

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
   dateFromString,
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

export const jsDateInThePast = pipe(
   date(`Must be a valid Date object (valibot).`),
   check((date: Date) => {
      return date <= new Date();
   }, `Date cannot be in the future (valibot).`)
);

export const jsDateInTheFuture = pipe(
   date(`Must be a valid Date object (valibot).`),
   check((date: Date) => {
      return date >= new Date();
   }, `Date cannot be in the past (valibot).`)
);

export const validateCanadianPostalCode = pipe(
   baseString,
   regex(
      postalCodeCanadaRegex,
      `Invalid Canadian postal code format (valibot).`
   )
);

export const validateNANPPhoneNumber = pipe(
   baseString,
   transform(phone => phone.replace(/[^\d]/g, '')),
   regex(phoneNANPRegex, `Must be an NANP phone number (valibot).`)
);

export const validateDIN = pipe(
   baseString,
   regex(dinRegex, `DIN must be exactly 8 digits (valibot).`)
);

export const validateSnomed = pipe(
   baseString,
   regex(snomedRegex, `Invalid SNOMED code (valibot).`)
);

export const Sha256HexString = pipe(
   string(),
   regex(HEX64_REGEX, `Invalid SHA256 hash.`)
);

// ── Reusable Pagination Schema (req.query) ───────────────────────────────────────
/* `object` (not `strictObject`) because URLs can carry arbitrary query params from browser extensions, analytics proxies, or CDN tools. */
export const CursorPaginationSchema = object({
   cursor: optional(pipe(string(`Cursor must be a string (valibot).`), trim())),
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
