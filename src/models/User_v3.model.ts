import { AUTHENTICATED_USER } from '@ssot/authenticated_user_constants.ts';
import { serverGeneratedFields } from '@ssot/serverGeneratedFields.ts';
import { TOTP_RECOVERY_CODE_COUNT } from '@ssot/totp_constants.ts';
import {
   EMAIL_CHANGE_CAP,
   NAME_CHANGE_CAP,
} from '@ssot/user_change_constants.ts';
import {
   argon2HashString,
   clinicStaffEmail,
   nameString,
   nonNegativeIntegerStringToNumber,
   passwordString,
   sha256HexString,
   stringToObjectId,
   totpSecretCheck,
} from '@utils/effectSchemaReusables.ts';
import { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import { Schema } from 'effect';
import { Collection } from 'mongodb';
import { DatabaseManager } from '../mongoDBConnect.ts';

/* Input schema: what arrives over HTTP. */
export const UserInputSchema = Schema.Struct({
   firstName: nameString,
   lastName: nameString,
   email: clinicStaffEmail,
   password: passwordString,
});

/* Document schema: composed from the SAME field atoms, extended with server-generated fields. No duplication of firstName/lastName/email rules. */
export const UserDocumentSchema = Schema.Struct({
   passwordHash: argon2HashString,
   previousNames: Schema.Array(
      Schema.Struct({
         archivedAt: Schema.ValidDateFromSelf,
      }).pipe(Schema.extend(UserInputSchema.pick('firstName', 'lastName')))
   ).pipe(Schema.maxItems(NAME_CHANGE_CAP)),
   previousEmails: Schema.Array(
      Schema.Struct({
         archivedAt: Schema.ValidDateFromSelf,
      }).pipe(Schema.extend(UserInputSchema.pick('email')))
   ).pipe(Schema.maxItems(EMAIL_CHANGE_CAP)),
   nameChangesUsed: nonNegativeIntegerStringToNumber,
   emailChangesUsed: nonNegativeIntegerStringToNumber,

   isTotpEnabled: Schema.Boolean,
   totpSecret: Schema.NullOr(totpSecretCheck).annotations({
      message: () =>
         `totpSecret must be null or a validly formatted encrypted secret.`,
   }),
   totpRecoveryCodes: Schema.Union(
      Schema.Array(sha256HexString).pipe(Schema.itemsCount(0)),
      Schema.Array(sha256HexString).pipe(
         Schema.itemsCount(TOTP_RECOVERY_CODE_COUNT)
      )
   ).annotations({
      message: () =>
         `Must contain either zero codes or exactly ${TOTP_RECOVERY_CODE_COUNT} recovery codes.`,
   }),
   totpLastUsedStep: nonNegativeIntegerStringToNumber,

   invitedBy: Schema.optional(stringToObjectId),
   isActive: Schema.Boolean,
}).pipe(
   Schema.extend(serverGeneratedFields),
   Schema.extend(UserInputSchema.omit('password')),
   Schema.extend(AUTHENTICATED_USER.pick('role', 'permissions')),
   Schema.filter(profile => {
      const issues: Array<Schema.FilterIssue> = [];

      if (profile.isTotpEnabled !== (profile.totpSecret !== null)) {
         issues.push({
            path: ['totpSecret'],
            message: `totpSecret must be set if and only if TOTP is enabled.`,
         });
      }

      if (
         profile.isTotpEnabled !==
         (profile.totpRecoveryCodes.length === TOTP_RECOVERY_CODE_COUNT)
      ) {
         issues.push({
            path: ['totpRecoveryCodes'],
            message: `Recovery codes must be fully present if and only if TOTP is enabled.`,
         });
      }

      if (profile.createdAt > profile.updatedAt) {
         issues.push({
            path: ['updatedAt'],
            message: `updatedAt cannot be chronologically before createdAt.`,
         });
      }

      if (profile.role === 'superadmin' && profile.invitedBy !== undefined) {
         issues.push({
            path: ['invitedBy'],
            message: `Superadmins cannot have an invitedBy reference.`,
         });
      }

      if (profile.role !== 'superadmin' && profile.invitedBy === undefined) {
         issues.push({
            path: ['invitedBy'],
            message: `Non-superadmin users must have an invitedBy reference.`,
         });
      }
      return issues;
   })
);

export const UserDocumentValidator = Schema.typeSchema(UserDocumentSchema);

export type IUserInput = Schema.Schema.Type<typeof UserInputSchema>;
export type IUserDocument = Schema.Schema.Type<typeof UserDocumentSchema>;

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
