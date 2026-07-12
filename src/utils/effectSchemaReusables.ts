import '@ssot/date_time_constants.ts';
import { argon2Regex } from '@ssot/argon2_config_constants.ts';
import { HEX64_REGEX } from '@ssot/node_crypto_constants.ts';
import { ParseResult, Schema } from 'effect';
import { ObjectId } from 'mongodb';
import { DateTime } from 'luxon';
import { MIN_LEGAL_AGE } from '@ssot/policy_constants.ts';
import { recoveryCodeRegex, totpSecretRegex } from '@ssot/totp_constants.ts';

const baseStringMaxLength = 128 as const;
const longStringMaxLength = 2056 as const;
const shortDateRegex = /^\d{4}-\d{2}-\d{2}$/;
const fullDateRegex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{1,3}Z$/;
const emailRegex =
   /^(?!\.)(?!.*\.\.)([A-Z0-9_'+\-.]*)[A-Z0-9_+-]@([A-Z0-9][A-Z0-9-]*\.)+[A-Z]{2,}$/i;
const ipRegex =
   /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$|^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$|^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}$|^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}$|^:(?::[0-9a-fA-F]{1,4}){1,7}$|^::$/;

const postalCodeCanadaRegex = /^[A-Za-z]\d[A-Za-z][ ]?\d[A-Za-z]\d$/i;
const phoneNANPRegex = /^1?[2-9]\d{2}[2-9]\d{6}$/;
const chartNumberRegex = /^[A-Za-z0-9-]{10}$/;
const dinRegex = /^\d{8}$/;
const snomedRegex = /^[1-9]\d{5,17}$/;

// ===== BASICS ====================================================================
export const customTrim = Schema.transform(
   Schema.String.annotations({
      message: () => `Must be a string.`,
   }),
   Schema.String.pipe(Schema.trimmed()),
   {
      decode: (str: string) => str.trim(),
      encode: (str: string) => str,
   }
);

export const baseString = customTrim.pipe(
   Schema.minLength(1, {
      message: () => `String should be at least 1 character long (baseString).`,
   }),
   Schema.maxLength(baseStringMaxLength, {
      message: () => `String is too long (baseString).`,
   })
);

export const longString = customTrim.pipe(
   Schema.minLength(1, {
      message: () => `String should be at least 1 character long (longString).`,
   }),
   Schema.maxLength(longStringMaxLength, {
      message: () => `String is too long (longString).`,
   })
);

export const nameString = Schema.transform(
   baseString.pipe(
      Schema.pattern(/^[\p{L} .'\-'']+$/iu, {
         message: () =>
            `Must not contain invalid or consecutive non-alphanumeric characters in name (nameString).`,
      })
   ),
   Schema.String,
   {
      strict: true,
      decode: (name: string) => {
         const words = name
            .split(/[\s-]+/)
            .map(
               w => `${w.slice(0, 1).toUpperCase()}${w.slice(1).toLowerCase()}`
            );
         const separators = name.match(/[\s-]+/g) ?? [];
         return words.reduce(
            (acc, cur, idx) => acc + cur + (separators[idx] ?? ''),
            ''
         );
      },
      encode: (name: string) => name,
   }
);

export const passwordString = baseString.pipe(
   Schema.filter((str: string) => str.length >= 8, {
      message: () => `Password must be at least 8 characters.`,
   }),
   Schema.pattern(/[A-Z]/, {
      message: () => `Password must contain at least one uppercase letter.`,
   }),
   Schema.pattern(/[a-z]/, {
      message: () => `Password must contain at least one lowercase letter.`,
   }),
   Schema.pattern(/[0-9]/, {
      message: () => `Password must contain at least one number.`,
   })
);

export const positiveIntegerStringToNumber = Schema.transform(
   baseString.pipe(
      Schema.pattern(/^[0-9]+$/, {
         message: () =>
            `Must be a numeric string (positiveIntegerStringToNumber).`,
      })
   ),
   Schema.Number.pipe(
      Schema.filter(num => Number.isSafeInteger(num), {
         message: () => `Value is not a safe JavaScript integer.`,
      }),
      Schema.int({ message: () => `Must be an integer.` }),
      Schema.positive({ message: () => `Must be a positive number.` })
   ),
   {
      strict: true,
      decode: (str: string) => Number(str),
      encode: (num: number) => String(num),
   }
);

export const nonNegativeIntegerStringToNumber = Schema.transform(
   baseString.pipe(
      Schema.pattern(/^[0-9]+$/, {
         message: () => `Must be a numeric string (nonNegativeInteger).`,
      })
   ),
   Schema.Number.pipe(
      Schema.filter(num => Number.isSafeInteger(num), {
         message: () => `Value is not a safe JavaScript integer.`,
      }),
      Schema.nonNegative({ message: () => `Must be a non-negative number.` })
   ),
   {
      strict: true,
      decode: (str: string) => Number(str),
      encode: (num: number) => String(num),
   }
);

// export const positiveInteger = Schema.Number.pipe(
//    Schema.int({ message: () => `Must be an integer (positiveInteger).` }),
//    Schema.positive({
//       message: () => `Must be a positive number (positiveInteger)`,
//    })
// );

// export const nonNegativeInteger = Schema.Number.pipe(
//    Schema.int({ message: () => `Must be an integer (nonNegativeInteger).` }),
//    Schema.nonNegative({
//       message: () => `Must be a non-negative number (nonNegativeInteger).`,
//    })
// );

const normalizedString = Schema.transform(
   baseString,
   Schema.String.pipe(Schema.trimmed(), Schema.lowercased()),
   {
      decode: (email: string) => email.toLowerCase(),
      encode: (email: string) => email,
   }
);

// ===== OBJECTID ==================================================================
export const objectIdInstance = Schema.instanceOf(ObjectId, {
   message: () => `Must be a valid ObjectId instance (objectIdInstance).`,
});

const objectIdInput = baseString.pipe(
   Schema.pattern(/^[a-f\d]{24}$/i, {
      message: () =>
         `Must be a valid 24-character hex string format (objectIdInput).`,
   })
);

export const stringToObjectId = Schema.transformOrFail(
   objectIdInput,
   objectIdInstance,
   {
      strict: true,
      decode: (str, _options, ast) =>
         ParseResult.try({
            try: () => new ObjectId(str),
            catch: () =>
               new ParseResult.Type(
                  ast,
                  str,
                  `Failed to construct ObjectId: input is not a valid 24-character hex string.`
               ),
         }),
      encode: objId => ParseResult.succeed(objId.toHexString()),
   }
);

export const MongoIdParamsSchema = Schema.Struct({
   id: stringToObjectId,
});

// ===== DATES =====================================================================
export const isCalendarDate = Schema.filter<Schema.Schema<string>>(
   (str: string) => DateTime.fromISO(str).isValid,
   { message: () => `Must be a valid calendar date.` }
);

export const shortDateString = baseString.pipe(
   Schema.pattern(shortDateRegex, {
      message: () =>
         `Invalid date format (Must be YYYY-MM-DD) (shortDateString).`,
   }),
   isCalendarDate
);

export const fullDateStringToJSDate = Schema.transform(
   baseString.pipe(
      Schema.pattern(fullDateRegex, {
         message: () =>
            `Invalid date format (Must be YYYY-MM-DDTHH:mm:ss.sssZ) (fullDateStringToJSDate).`,
      }),
      isCalendarDate
   ),
   Schema.ValidDateFromSelf,
   {
      strict: true,
      decode: (str: string) => DateTime.fromISO(str).toJSDate(),
      encode: (date: Date) => date.toISOString(),
   }
);

export const fullDateInThePast = fullDateStringToJSDate.pipe(
   Schema.filter(
      (dateObj: Date) => dateObj.getTime() < DateTime.now().valueOf(),
      {
         message: () => `The date must be in the past (fullDateInThePast).`,
      }
   )
);

export const fullDateInTheFuture = fullDateStringToJSDate.pipe(
   Schema.filter(
      (dateObj: Date) => dateObj.getTime() > DateTime.now().valueOf(),
      {
         message: () => `The date must be in the future (fulldateInTheFuture).`,
      }
   )
);

export const shortDateInThePast = shortDateString.pipe(
   Schema.filter(
      (dateStr: string) => {
         const targetDate = DateTime.fromISO(dateStr).startOf('day');
         const today = DateTime.now().startOf('day');
         return targetDate.valueOf() < today.valueOf();
      },
      {
         message: () => `The date must be in the past (shortDateInThePast).`,
      }
   )
);

export const shortDateInThePastOrToday = shortDateString.pipe(
   Schema.filter(
      (dateStr: string) => {
         const targetDate = DateTime.fromISO(dateStr).startOf('day');
         const today = DateTime.now().startOf('day');
         /* Using <= directly against today's midnight perfectly includes today and cleanly excludes tomorrow. */
         return targetDate.valueOf() <= today.valueOf();
      },
      {
         message: () =>
            `The date must be in the past or today (shortDateInThePastOrToday).`,
      }
   )
);

export const shortDateInTheFuture = shortDateString.pipe(
   Schema.filter(
      (dateStr: string) => {
         const targetDate = DateTime.fromISO(dateStr).endOf('day');
         const today = DateTime.now().endOf('day');
         return targetDate.valueOf() > today.valueOf();
      },
      {
         message: () =>
            `The date must be in the future (shortDateInTheFuture).`,
      }
   )
);

export const shortDateInTheFutureOrToday = shortDateString.pipe(
   Schema.filter(
      (dateStr: string) => {
         const targetDate = DateTime.fromISO(dateStr).endOf('day');
         const today = DateTime.now().endOf('day');
         return targetDate.valueOf() >= today.valueOf();
      },
      {
         message: () =>
            `The date must be in the future or today (shortDateInTheFutureOrToday).`,
      }
   )
);

// export const validDateInThePast = Schema.ValidDateFromSelf.pipe(
//    Schema.filter((date: Date) => date.getTime() < Date.now(), {
//       message: () => `The date must be in the past (validDateInThePast).`,
//    })
// );
// export const validDateInTheFuture = Schema.ValidDateFromSelf.pipe(
//    Schema.filter((date: Date) => date.getTime() > Date.now(), {
//       message: () => `The date must be in the future (validDateInTheFuture).`,
//    })
// );

export const validateDOB = shortDateString.pipe(
   Schema.filter(
      (str: string) => {
         const year = parseInt(str.split('-')[0], 10);
         return year > 1900;
      },
      {
         message: () => `The patient must be born after 1900 (validateDOB).`,
      }
   ),
   Schema.filter(
      (str: string) => {
         const dob = DateTime.fromISO(str).startOf('day');
         const legalBirthdayCutoff = DateTime.now()
            .startOf('day')
            .minus({ years: MIN_LEGAL_AGE });
         return dob.valueOf() <= legalBirthdayCutoff.valueOf();
      },
      {
         message: () =>
            `The patient must be at least ${MIN_LEGAL_AGE} years old (validateDOB).`,
      }
   )
);

// ===== MISC ======================================================================
export const clinicStaffEmail = normalizedString.pipe(
   Schema.pattern(emailRegex, {
      message: () => `Incorrectly formatter email (clinicStaffEmail).`,
   })
);

export const postalCodeCanada = baseString.pipe(
   Schema.pattern(postalCodeCanadaRegex, {
      message: () => `Invalid Canadian postal code format (postalCodeCanada).`,
   })
);

export const phoneNumberNANP = Schema.transform(
   baseString,
   baseString.pipe(
      Schema.pattern(phoneNANPRegex, {
         message: () => `Must be an NANP phone number (phoneNumberNANP).`,
      })
   ),
   {
      decode: (phone: string) => phone.replace(/[^\d]/g, ''),
      encode: (phone: string) => phone,
   }
);

export const chartNumber = baseString.pipe(
   Schema.pattern(chartNumberRegex, {
      message: () =>
         `Chart Number must be 10 letters, numbers, or hyphens (chartNumber).`,
   })
);

export const DIN = baseString.pipe(
   Schema.pattern(dinRegex, {
      message: () => `DIN must be exactly 8 digits (DIN).`,
   })
);

export const snomed = baseString.pipe(
   Schema.pattern(snomedRegex, {
      message: () => `Invalid SNOMED code (snomed).`,
   })
);

export const sha256HexString = customTrim.pipe(
   Schema.pattern(HEX64_REGEX, {
      message: () => `Invalid SHA256 hash (sha256HexString).`,
   })
);

export const argon2HashString = customTrim.pipe(
   Schema.pattern(argon2Regex, {
      message: () => `Invalid Argon2 hash (argon2HashString).`,
   })
);

export const ipAddress = baseString.pipe(
   Schema.pattern(ipRegex, {
      message: () => `Invalid IP Address format (ipAddress).`,
   })
);

// ===== TOTP-RELATED CHECKS =======================================================
export const totpSecretCheck = baseString.pipe(
   Schema.pattern(totpSecretRegex, {
      message: () => `Invalid encrypted TOTP secret format (totpSecretCheck).`,
   })
);

export const recoveryCodeCheck = baseString.pipe(
   Schema.pattern(recoveryCodeRegex, {
      message: () => `Invalid recovery code format (recoveryCodeCheck).`,
   })
);
