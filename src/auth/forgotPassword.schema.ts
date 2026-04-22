import {
   email,
   InferOutput,
   maxLength,
   nonEmpty,
   pipe,
   strictObject,
   string,
   transform,
} from 'valibot';

/* Mirrors the email field from LoginSchema exactly. We apply the same maxLength ceiling so an over-long payload is rejected before we touch the database, and the lowercase transform ensures we query with the canonical form. */
export const ForgotPasswordSchema = strictObject({
   email: pipe(
      string(`Must be a string.`),
      nonEmpty(`Please enter your email address.`),
      email(`Incorrectly formatted email.`),
      maxLength(64, `Your email is too long.`),
      transform(str => str.toLowerCase())
   ),
});

export type ForgotPasswordBody = InferOutput<typeof ForgotPasswordSchema>;
