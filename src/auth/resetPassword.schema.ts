import {
   InferOutput,
   minLength,
   maxLength,
   pipe,
   regex,
   strictObject,
   string,
} from 'valibot';

/* The full complexity suite — identical to the password field in UserRegistrationSchema. These are creation constraints, not verification constraints, so every rule applies. */
export const ResetPasswordSchema = strictObject({
   newPassword: pipe(
      string(`Must be a string.`),
      minLength(8, `Password must be at least 8 characters.`),
      maxLength(128, `Password is too long.`),
      regex(/[A-Z]/, `Password must contain at least one uppercase letter.`),
      regex(/[a-z]/, `Password must contain at least one lowercase letter.`),
      regex(/[0-9]/, `Password must contain at least one number.`)
   ),
});

export type ResetPasswordBody = InferOutput<typeof ResetPasswordSchema>;
