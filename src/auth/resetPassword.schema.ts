import { passwordString } from '@utils/effectSchemaReusables.ts';
import { Schema } from 'effect';

/* The full complexity suite — identical to the password field in `UserInputSchema`. These are creation constraints, not verification constraints, so every rule applies. */
export const ResetPasswordSchema = Schema.Struct({
   newPassword: passwordString,
});

export type ResetPasswordBody = Schema.Schema.Type<typeof ResetPasswordSchema>;
