import {
   strictObject,
   string,
   pipe,
   regex,
   nonEmpty,
   maxLength,
   type InferOutput,
} from 'valibot';

// Used by both /totp/enroll/confirm and /totp/verify.
export const TotpCodeSchema = strictObject({
   code: pipe(
      string(`Must be a string.`),
      nonEmpty(`Please enter the 6-digit code.`),
      regex(/^\d{6}$/, `Code must be exactly 6 digits.`)
   ),
});
export type TotpCodeBody = InferOutput<typeof TotpCodeSchema>;

/* Recovery codes are XXXXXXXXXX-XXXXXXXXXX (10 uppercase hex chars per segment). We normalize to uppercase in the controller before hashing. */
export const RecoveryCodeSchema = strictObject({
   code: pipe(
      string(`Must be a string.`),
      nonEmpty(`Please enter a recovery code.`),
      regex(/^[A-F0-9]{10}-[A-F0-9]{10}$/i, `Invalid recovery code format.`)
   ),
});
export type RecoveryCodeBody = InferOutput<typeof RecoveryCodeSchema>;

/* Disabling TOTP requires the user to prove it's really them. No complexity rules — we're verifying an existing hash, not creating a new one. */
export const DisableTotpSchema = strictObject({
   password: pipe(
      string(`Must be a string.`),
      nonEmpty(`Your current password is required to disable 2FA.`),
      maxLength(128, `Password is too long.`)
   ),
});
export type DisableTotpBody = InferOutput<typeof DisableTotpSchema>;
