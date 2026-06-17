import { validateEmail } from '@utils/valibotSchemaReusables.ts';
import { InferOutput, strictObject } from 'valibot';

/* Mirrors the email field from LoginSchema exactly. We apply the same maxLength ceiling so an over-long payload is rejected before we touch the database, and the lowercase transform ensures we query with the canonical form. */
export const ForgotPasswordSchema = strictObject({
   email: validateEmail,
});

export type ForgotPasswordBody = InferOutput<typeof ForgotPasswordSchema>;
