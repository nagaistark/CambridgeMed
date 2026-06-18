import { AUTHENTICATED_USER } from '@ssot/authenticated_user_constants.ts';
import { TOTP_RECOVERY_CODE_COUNT } from '@ssot/totp_constants.ts';
import { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import {
   Argon2HashString,
   nameString,
   nonNegativeIntegerNumber,
   objectIdInstance,
   positiveIntegerNumber,
   Sha256HexString,
   totpSecret,
   validateEmail,
} from '@utils/valibotSchemaReusables.ts';
import { Collection } from 'mongodb';
import { DatabaseManager } from 'mongoDBConnect.ts';
import {
   array,
   boolean,
   date,
   InferOutput,
   length,
   maxLength,
   minLength,
   nullable,
   omit,
   optional,
   pick,
   pipe,
   regex,
   strictObject,
   string,
} from 'valibot';

// ── Valibot registration schema ──────────────────────────────────────────────────
/* This schema validates the body of POST /api/invites/:token/accept. It is unchanged from its original form — all the additions to the User model are server-side concerns invisible to the registering user. */
export const UserInputVSchema = strictObject({
   firstName: nameString,
   lastName: nameString,
   email: validateEmail,
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

export type IUserDocument = InferOutput<typeof UserDocumentVSchema>;

export function getUserCollection(): Collection<IUserDocument> {
   return DatabaseManager.getInstance()
      .auth.db()
      .collection<IUserDocument>('users');
}

export const userIndexes = [
   { key: { email: 1 }, unique: true },
] satisfies readonly TypedIndexDescription<IUserDocument>[];

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
