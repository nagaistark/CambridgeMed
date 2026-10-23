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

// ── Re-authentication payloads (password + a second factor) ─────────────────────
/* One definition of "the second-factor part of a body", so disable, regenerate and the admin reset cannot drift apart. */
const secondFactorFields = {
   totpCode: Schema.optional(totpCodeString),
   recoveryCode: Schema.optional(recoveryCodeString),
} as const;

type FactorFields = {
   readonly totpCode?: string | undefined;
   readonly recoveryCode?: string | undefined;
};

const hasExactlyOneFactor = ({
   totpCode,
   recoveryCode,
}: FactorFields): boolean =>
   (totpCode === undefined) !== (recoveryCode === undefined);

const hasAtMostOneFactor = ({
   totpCode,
   recoveryCode,
}: FactorFields): boolean =>
   totpCode === undefined || recoveryCode === undefined;

/* Disabling 2FA and regenerating recovery codes need the password AND exactly one second factor. */
const ReauthWithOneFactorSchema = Schema.Struct({
   currentPassword: baseString,
   ...secondFactorFields,
}).pipe(
   Schema.filter(hasExactlyOneFactor, {
      message: () => `Provide exactly one of totpCode or recoveryCode.`,
   })
);

export const DisableTotpSchema = ReauthWithOneFactorSchema;
export type DisableTotpBody = Schema.Schema.Type<typeof DisableTotpSchema>;

export const RegenerateRecoveryCodesSchema = ReauthWithOneFactorSchema;
export type RegenerateRecoveryCodesBody = Schema.Schema.Type<
   typeof RegenerateRecoveryCodesSchema
>;

/* The admin's OWN re-authentication. Whether a second factor is required depends on whether THAT admin has 2FA enabled, which the schema cannot know; the controller enforces "required when enabled". Hence at most one here. */
export const AdminResetTotpSchema = Schema.Struct({
   currentPassword: baseString,
   ...secondFactorFields,
}).pipe(
   Schema.filter(hasAtMostOneFactor, {
      message: () => `Provide at most one of totpCode or recoveryCode.`,
   })
);
export type AdminResetTotpBody = Schema.Schema.Type<
   typeof AdminResetTotpSchema
>;
