import {
   passwordString,
   recoveryCodeString,
   totpCodeString,
} from '@utils/effectSchemaReusables.ts';
import { Schema } from 'effect';

/* The full complexity suite on newPassword, as before. The second factor is optional HERE because the schema can't know whether the account has TOTP; the controller enforces "required when enabled". */
export const ResetPasswordSchema = Schema.Struct({
   newPassword: passwordString,
   totpCode: Schema.optional(totpCodeString),
   recoveryCode: Schema.optional(recoveryCodeString),
}).pipe(
   Schema.filter(
      ({ totpCode, recoveryCode }) =>
         totpCode === undefined || recoveryCode === undefined,
      { message: () => `Provide at most one of totpCode or recoveryCode.` }
   )
);

export type ResetPasswordBody = Schema.Schema.Type<typeof ResetPasswordSchema>;
