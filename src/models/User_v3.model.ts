import { AUTHENTICATED_USER_V2 } from '@ssot/authenticated_user_constants.ts';
import { TOTP_RECOVERY_CODE_COUNT } from '@ssot/totp_constants.ts';
import {
   EMAIL_CHANGE_CAP,
   NAME_CHANGE_CAP,
} from '@ssot/user_change_constants.ts';
import {
   argon2HashString,
   baseString,
   clinicStaffEmail,
   nameString,
   nonNegativeIntegerStringToNumber,
   objectIdInstance,
   sha256HexString,
   totpSecretCheck,
} from '@utils/effectSchemaReusables.ts';
import { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import { Schema } from 'effect';
import { Collection } from 'mongodb';
import { DatabaseManager } from 'mongoDBConnect.ts';

/* Input schema: what arrives over HTTP. */
export const UserInputSchema = Schema.Struct({
   firstName: nameString,
   lastName: nameString,
   email: clinicStaffEmail,
   password: baseString.pipe(
      Schema.filter((str: string) => str.length >= 8, {
         message: () => `Password must be at least 8 characters.`,
      }),
      Schema.pattern(/[A-Z]/, {
         message: () => `Password must contain at least one uppercase letter.`,
      }),
      Schema.pattern(/[a-z]/, {
         message: () => `Password must contain at least one lowercase letter.`,
      }),
      Schema.pattern(/[0-9]/, {
         message: () => `Password must contain at least one number.`,
      })
   ),
});

/* Document schema: composed from the SAME field atoms, extended with server-generated fields. No duplication of firstName/lastName/email rules. */
export const UserDocumentSchema = Schema.Struct({
   ...UserInputSchema.omit('password').fields,
   ...AUTHENTICATED_USER_V2.pick('role', 'permissions').fields,
   _id: objectIdInstance,
   passwordHash: argon2HashString,
   previousNames: Schema.Array(
      Schema.Struct({
         ...UserInputSchema.pick('firstName', 'lastName').fields,
         archivedAt: Schema.Date,
      })
   ).pipe(Schema.maxItems(NAME_CHANGE_CAP)),
   previousEmails: Schema.Array(
      Schema.Struct({
         ...UserInputSchema.pick('email').fields,
         archivedAt: Schema.Date,
      })
   ).pipe(Schema.maxItems(EMAIL_CHANGE_CAP)),
   nameChangesUsed: nonNegativeIntegerStringToNumber,
   emailChangesUsed: nonNegativeIntegerStringToNumber,
   totpSecret: Schema.NullOr(totpSecretCheck),
   isTotpEnabled: Schema.Boolean,
   totpRecoveryCodes: Schema.Union(
      Schema.Array(sha256HexString).pipe(Schema.itemsCount(0)),
      Schema.Array(sha256HexString).pipe(
         Schema.itemsCount(TOTP_RECOVERY_CODE_COUNT)
      )
   ),
   totpLastUsedStep: nonNegativeIntegerStringToNumber,
   invitedBy: Schema.optional(objectIdInstance),
   isActive: Schema.Boolean,
   createdAt: Schema.Date,
   updatedAt: Schema.Date,
}).pipe(
   Schema.filter(profile => {
      const issues: Array<Schema.FilterIssue> = [];
      if (
         profile.isTotpEnabled !==
         (profile.totpRecoveryCodes.length === TOTP_RECOVERY_CODE_COUNT)
      ) {
         issues.push({
            path: ['totpRecoveryCodes'],
            message: `recoveryCodes length must match 2FA status.`,
         });
      }
      if (profile.createdAt > profile.updatedAt) {
         issues.push({
            path: ['updatedAt'],
            message: `updatedAt cannot be chronologically before createdAt.`,
         });
      }
      if (
         (profile.role === 'superadmin' && !!profile.invitedBy) ||
         (profile.role !== 'superadmin' && !profile.invitedBy)
      ) {
         issues.push({
            path: ['role'],
            message: `Role invariant violated: the superadmin role may only exist without an invitedBy reference, and all invited users must have an allowed role.`,
         });
      }
      return issues;
   })
);

type IUserDocument = Schema.Schema.Type<typeof UserDocumentSchema>;

export function getUserCollection(): Collection<IUserDocument> {
   return DatabaseManager.getInstance()
      .auth.db()
      .collection<IUserDocument>('users');
}

export const userIndexes = [
   { key: { email: 1 }, unique: true },
] satisfies readonly TypedIndexDescription<IUserDocument>[];
