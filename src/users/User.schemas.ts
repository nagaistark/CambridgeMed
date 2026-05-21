import {
   boolean,
   check,
   email,
   InferOutput,
   maxLength,
   minLength,
   nonEmpty,
   optional,
   pipe,
   regex,
   strictObject,
   string,
   transform,
} from 'valibot';
import { nameString } from '@utils/valibotSchemaReusables.ts';

// ── Change password ──────────────────────────────────────────────────────────────
/* currentPassword has no complexity rules. We are verifying against an existing hash, not enforcing creation constraints. maxLength makes sure an over-long payload is rejected before we touch the database. newPassword runs the full complexity suite identical to registration. */
export const ChangePasswordSchema = pipe(
   strictObject({
      currentPassword: pipe(
         string(`Must be a string.`),
         nonEmpty(`Please enter your current password.`),
         maxLength(128, `Password is too long.`)
      ),
      newPassword: pipe(
         string(`Must be a string.`),
         minLength(8, `Password must be at least 8 characters.`),
         maxLength(128, `Password is too long.`),
         regex(/[A-Z]/, `Password must contain at least one uppercase letter.`),
         regex(/[a-z]/, `Password must contain at least one lowercase letter.`),
         regex(/[0-9]/, `Password must contain at least one number.`)
      ),
   }),
   check(data => {
      return data.currentPassword !== data.newPassword;
   }, `New password must be different from your current password.`)
);

export type ChangePasswordBody = InferOutput<typeof ChangePasswordSchema>;

// ── Change name ──────────────────────────────────────────────────────────────────
/* Both fields are optional individually, but the pipe-level `check` enforces that at least one is present. This allows a user to change only their first name, only their last name, or both in a single request. */
export const ChangeNameSchema = pipe(
   strictObject({
      firstName: optional(nameString),
      lastName: optional(nameString),
   }),
   check(data => {
      return data.firstName !== undefined || data.lastName !== undefined;
   }, `At least one of firstName or lastName must be provided.`)
);

export type ChangeNameBody = InferOutput<typeof ChangeNameSchema>;

// ── Initiate email change ─────────────────────────────────────────────────────
/* Identical pipeline to the registration email field: format validation, length cap, and a lowercase transform. The equality check against the user's current email (new !== old) is enforced in the controller, not here, because the schema has no access to the authenticated user's record. */
export const InitiateEmailChangeSchema = strictObject({
   newEmail: pipe(
      string(`Must be a string.`),
      nonEmpty(`Please enter your new email address.`),
      email(`Incorrectly formatted email.`),
      maxLength(64, `Your email is too long.`),
      transform(str => str.toLowerCase())
   ),
});

export type InitiateEmailChangeBody = InferOutput<
   typeof InitiateEmailChangeSchema
>;

// ── canIssueInvites (PATCH /api/users/:id/can-issue-invites) ─────────────────────
/* Accepts an explicit boolean rather than toggling blindly. A toggle is a read-modify-write where the "modify" step depends on what was just read — two simultaneous PATCH requests by the superadmin could toggle twice and land back at the original value. An explicit value has no such race: the last writer wins with a known, intended outcome. */
export const SetCanIssueInvitesSchema = strictObject({
   canIssueInvites: boolean(`Must be a boolean.`),
});

export type SetCanIssueInvitesBody = InferOutput<
   typeof SetCanIssueInvitesSchema
>;

// ── isActive (PATCH /api/users/:id/is-active) ────────────────────────────────────
/* Same explicit-value pattern for the same reason. */
export const SetIsActiveSchema = strictObject({
   isActive: boolean(`Must be a boolean.`),
});

export type SetIsActiveBody = InferOutput<typeof SetIsActiveSchema>;
