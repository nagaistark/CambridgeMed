import {
   baseString,
   clinicStaffEmail,
   nameString,
   passwordString,
} from '@utils/effectSchemaReusables.ts';
import { Schema } from 'effect';

/* The schema handles SYNTACTIC checks (Is it a string? Is it non-empty? Do the fields satisfy pure relational logic like A != B?). The SEMANTIC check (does A actually match the stored hash in the database for the user making the request?) is performed by the controller down the middleware chain. */
export const ChangePasswordSchema = Schema.Struct({
   currentPassword: baseString,
   newPassword: passwordString,
}).pipe(
   Schema.filter(
      ({ currentPassword, newPassword }) => {
         return currentPassword !== newPassword;
      },
      {
         message: () =>
            `New password must be different from your current password.`,
      }
   )
);

export type ChangePasswordBody = Schema.Schema.Type<
   typeof ChangePasswordSchema
>;

// ── Change name ──────────────────────────────────────────────────────────────────
/* Both fields are optional individually, but we enforce that at least one is present. This allows a user to change only their first name, only their last name, or both in a single request. */
export const ChangeNameSchema = Schema.Struct({
   firstName: Schema.optional(nameString),
   lastName: Schema.optional(nameString),
}).pipe(
   Schema.filter(
      ({ firstName, lastName }) => {
         return firstName !== undefined || lastName !== undefined;
      },
      {
         message: () =>
            `At least one of firstName or lastName must be provided.`,
      }
   )
);

export type ChangeNameBody = Schema.Schema.Type<typeof ChangeNameSchema>;

// ── Initiate email change ─────────────────────────────────────────────────────
/* Identical pipeline to the registration email field: format validation, length cap, and a lowercase transform. The equality check against the user's current email (new !== old) is enforced in the controller, not here, because the schema has no access to the authenticated user's record. */
export const InitiateEmailChangeSchema = Schema.Struct({
   newEmail: clinicStaffEmail,
});

export type InitiateEmailChangeBody = Schema.Schema.Type<
   typeof InitiateEmailChangeSchema
>;

// ── canIssueInvites (PATCH /api/users/:id/can-issue-invites) ─────────────────────
/* Accepts an explicit boolean rather than toggling blindly. */
export const SetCanIssueInvitesSchema = Schema.Struct({
   canIssueInvites: Schema.Boolean.annotations({
      message: () => `Must be a boolean.`,
   }),
});

export type SetCanIssueInvitesBody = Schema.Schema.Type<
   typeof SetCanIssueInvitesSchema
>;

// ── isActive (PATCH /api/users/:id/is-active) ────────────────────────────────────
/* Same explicit-value pattern for the same reason. */
export const SetIsActiveSchema = Schema.Struct({
   isActive: Schema.Boolean.annotations({
      message: () => `Must be a boolean.`,
   }),
});

export type SetIsActiveBody = Schema.Schema.Type<typeof SetIsActiveSchema>;
