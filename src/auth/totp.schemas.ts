import { baseString } from '@utils/effectSchemaReusables.ts';
import { Schema } from 'effect';

/* Used by both /totp/enroll/confirm and /totp/verify. */
export const TotpCodeSchema = Schema.Struct({
   code: baseString.pipe(
      Schema.pattern(/^\d{6}$/, {
         message: () => `Code must be exactly 6 digits.`,
      })
   ),
});
export type TotpCodeBody = Schema.Schema.Type<typeof TotpCodeSchema>;

/* Recovery codes are XXXXXXXXXX-XXXXXXXXXX (10 uppercase hex chars per segment). We normalize to uppercase in the controller before hashing. */
export const RecoveryCodeSchema = Schema.Struct({
   code: baseString.pipe(
      Schema.pattern(/^[A-F0-9]{10}-[A-F0-9]{10}$/i, {
         message: () => `Invalid recovery code format.`,
      })
   ),
});
export type RecoveryCodeBody = Schema.Schema.Type<typeof RecoveryCodeSchema>;

/* Disabling TOTP requires the user to prove it's really them. No complexity rules — we're verifying an existing hash, not creating a new one. */
export const DisableTotpSchema = Schema.Struct({
   password: baseString,
});
export type DisableTotpBody = Schema.Schema.Type<typeof DisableTotpSchema>;
