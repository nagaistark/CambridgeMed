import {
   baseString,
   recoveryCodeString,
   totpCodeString,
} from '@utils/effectSchemaReusables.ts';
import { Schema } from 'effect';

/* Used by both /totp/enroll/confirm and /totp/verify. */
export const TotpCodeSchema = Schema.Struct({ code: totpCodeString });
export type TotpCodeBody = Schema.Schema.Type<typeof TotpCodeSchema>;

/* Format and casing come from the SSOT regex via recoveryCodeString. */
export const RecoveryCodeSchema = Schema.Struct({ code: recoveryCodeString });
export type RecoveryCodeBody = Schema.Schema.Type<typeof RecoveryCodeSchema>;

/* Starting an enrollment is a security-relevant change, so it needs the password. No complexity rules: we verify an existing hash. */
export const TotpEnrollSchema = Schema.Struct({ currentPassword: baseString });
export type TotpEnrollBody = Schema.Schema.Type<typeof TotpEnrollSchema>;

/* Disabling 2FA needs the password AND exactly one second factor. */
export const DisableTotpSchema = Schema.Struct({
   currentPassword: baseString,
   totpCode: Schema.optional(totpCodeString),
   recoveryCode: Schema.optional(recoveryCodeString),
}).pipe(
   Schema.filter(
      ({ totpCode, recoveryCode }) =>
         (totpCode === undefined) !== (recoveryCode === undefined),
      { message: () => `Provide exactly one of totpCode or recoveryCode.` }
   )
);
export type DisableTotpBody = Schema.Schema.Type<typeof DisableTotpSchema>;
