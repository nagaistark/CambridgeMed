import { AUTHENTICATED_USER } from '@ssot/authenticated_user_constants.ts';
import { TOTP_RECOVERY_CODE_COUNT } from '@ssot/totp_constants.ts';
import {
   Argon2HashString,
   nameString,
   nonNegativeIntegerNumber,
   objectIdInstance,
   positiveIntegerNumber,
   Sha256HexString,
   totpSecret,
} from '@utils/valibotSchemaReusables.ts';
import {
   array,
   boolean,
   date,
   email,
   InferOutput,
   length,
   maxLength,
   minLength,
   nonEmpty,
   nullable,
   omit,
   optional,
   pick,
   pipe,
   regex,
   strictObject,
   string,
   transform,
} from 'valibot';

// ── Valibot registration schema ──────────────────────────────────────────────────
/* This schema validates the body of POST /api/invites/:token/accept. It is unchanged from its original form — all the additions to the User model are server-side concerns invisible to the registering user. */
export const UserInputVSchema = strictObject({
   firstName: nameString,
   lastName: nameString,
   email: pipe(
      string(`Must be a string.`),
      nonEmpty(`Please enter your email.`),
      email(`Incorrectly formatted email.`),
      maxLength(64, `Your email is too long.`),
      transform(str => str.toLowerCase())
   ),
   password: pipe(
      string(`Must be a string.`),
      minLength(8, `Password must be at least 8 characters.`),
      maxLength(128, `Password is too long.`),
      regex(/[A-Z]/, `Password must contain at least one uppercase letter.`),
      regex(/[a-z]/, `Password must contain at least one lowercase letter.`),
      regex(/[0-9]/, `Password must contain at least one number.`)
   ),
});

// ── History entry types ──────────────────────────────────────────────────────────
/* Each entry represents a name or email that was once the live value on this account. `archivedAt` records the moment the entry was archived. */
const NameHistoryEntrySubVSchema = strictObject({
   ...pick(UserInputVSchema, ['firstName', 'lastName']).entries,
   archivedAt: date(`archivedAt must be a valid JS Date object.`),
});

const EmailHistoryEntrySubVSchema = strictObject({
   ...pick(UserInputVSchema, ['email']).entries,
   archivedAt: date(`archivedAt must be a valid JS Date object.`),
});

export const UserDocumentVSchema = strictObject({
   ...omit(UserInputVSchema, ['password']).entries,
   ...pick(AUTHENTICATED_USER, ['role', 'permissions']).entries,
   _id: objectIdInstance,
   passwordHash: Argon2HashString,
   previousNames: array(NameHistoryEntrySubVSchema),
   previousEmails: array(EmailHistoryEntrySubVSchema),
   nameChangesUsed: nonNegativeIntegerNumber,
   emailChangesUsed: nonNegativeIntegerNumber,
   totpSecret: nullable(totpSecret),
   isTotpEnabled: boolean(),
   totpRecoveryCodes: pipe(
      array(Sha256HexString),
      length(
         TOTP_RECOVERY_CODE_COUNT,
         `Must contain exactly ${TOTP_RECOVERY_CODE_COUNT} codes.`
      )
   ),
   totpLastUsedStep: positiveIntegerNumber,
   invitedBy: optional(objectIdInstance),
   isActive: boolean(),
   createdAt: date(`createdAt must be a valid JS Date object.`),
   updatedAt: date(`updatedAt must be a valid JS Date object.`),
});

// type IUserInput = InferOutput<typeof UserInputVSchema>;
type IUserDocument = InferOutput<typeof UserDocumentVSchema>;

// ── Types Used in MongoDB Projections ────────────────────────────────────────────
/* The SAFE, full (except `passwordHash` and sensitive TOTP-related data) projection for self-view (GET /api/auth/me) and superadmin views. */
export type SafeUser = Omit<
   IUserDocument,
   'passwordHash' | 'totpSecret' | 'totpRecoveryCodes' | 'totpLastUsedStep'
>;

/* The minimal PUBLIC-facing shape returned to non-superadmin authenticated users looking up their colleagues. */
export type PublicUser = Pick<
   IUserDocument,
   '_id' | 'firstName' | 'lastName' | 'email' | 'role' | 'permissions'
>;

// ── HTTP response types ──────────────────────────────────────────────────────────
export type AuthUserResponse = {
   success: true;
   message: string;
   user: PublicUser;
};

export type AuthUserResponseLogout = Omit<AuthUserResponse, 'user'>;
