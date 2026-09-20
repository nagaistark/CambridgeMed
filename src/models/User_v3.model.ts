import { AUTHENTICATED_USER } from '@ssot/authenticated_user_constants.ts';
import { ServerGeneratedFields } from '@ssot/serverGeneratedFields.ts';
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

/* Document struct is composed from the SAME field atoms, extended with server-generated fields. No duplication of firstName/lastName/email rules. */
export const UserDocumentStruct = Schema.Struct({
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

   invitedBy: Schema.NullOr(stringToObjectId),
   isActive: Schema.Boolean,

   ...UserInputSchema.omit('password').fields,
   ...AUTHENTICATED_USER.pick('role', 'permissions').fields,
   ...ServerGeneratedFields.fields,
});

/* Standalone cross-field validation */
export type IUserDocument = Schema.Schema.Type<typeof UserDocumentStruct>;

const validateChronology = <
   A extends Pick<IUserDocument, 'createdAt' | 'updatedAt'>,
   I,
   R,
>(
   schema: Schema.Schema<A, I, R>
) => {
   return schema.pipe(
      Schema.filter(profile => {
         const issues: Array<Schema.FilterIssue> = [];

         if (profile.createdAt > profile.updatedAt) {
            issues.push({
               path: ['updatedAt'],
               message: `updatedAt cannot be chronologically before createdAt.`,
            });
         }

         return issues;
      })
   );
};

const validateInviteRole = <
   A extends Pick<IUserDocument, 'role' | 'invitedBy'>,
   I,
   R,
>(
   schema: Schema.Schema<A, I, R>
) => {
   return schema.pipe(
      Schema.filter(profile => {
         const issues: Array<Schema.FilterIssue> = [];

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
};

const validateTotp = <
   A extends Pick<
      IUserDocument,
      'isTotpEnabled' | 'totpSecret' | 'totpRecoveryCodes'
   >,
   I,
   R,
>(
   schema: Schema.Schema<A, I, R>
) => {
   return schema.pipe(
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

         return issues;
      })
   );
};

/* Document Schema */
const UserDocumentSchema = UserDocumentStruct.pipe(
   validateChronology,
   validateInviteRole,
   validateTotp
);

// ===== PROJECTION SCHEMA(S) AND INFERRED TYPES ===================================
/* The SAFE, full (except `passwordHash` and sensitive TOTP-related data) projection. Used for self-view (GET /api/auth/me) and superadmin views (getUserController, listUsersController). */
const SafeUserSchema = UserDocumentStruct.omit(
   'passwordHash',
   'totpSecret',
   'totpRecoveryCodes',
   'totpLastUsedStep'
).pipe(validateChronology, validateInviteRole);
export type ISafeUser = Schema.Schema.Type<typeof SafeUserSchema>;

/* The minimal PUBLIC-facing shape returned to non-superadmin authenticated users looking up their colleagues (getUserController, listUsersController). */
const PublicUserSchema = UserDocumentStruct.pick(
   '_id',
   'firstName',
   'lastName',
   'email',
   'role',
   'permissions'
);
export type IPublicUser = Schema.Schema.Type<typeof PublicUserSchema>;

/* _id + passwordHash. Used in changePasswordController. */
const UserIdPasswordHashSchema = UserDocumentStruct.pick('_id', 'passwordHash');
export type IUserIdPasswordHash = Schema.Schema.Type<
   typeof UserIdPasswordHashSchema
>;

/* Minimal user name info. Used in createInviteController and changeNameController.  */
const UserIdNameSchema = UserDocumentStruct.pick(
   '_id',
   'firstName',
   'lastName'
);
export type IUserIdName = Schema.Schema.Type<typeof UserIdNameSchema>;

/* User name + email info. Used in changeNameController */
const UserNameEmailSchema = UserDocumentStruct.pick(
   '_id',
   'firstName',
   'lastName',
   'nameChangesUsed',
   'email',
   'emailChangesUsed'
);
export type IUserNameEmail = Schema.Schema.Type<typeof UserNameEmailSchema>;

// ===== Validators against which we validate the documents ========================
export const UserDocumentValidator = Schema.typeSchema(UserDocumentSchema);
export const UserDocumentArrayValidator = Schema.Array(UserDocumentValidator);

export const SafeUserValidator = Schema.typeSchema(SafeUserSchema);
export const SafeUserArrayValidator = Schema.Array(SafeUserValidator);

export const PublicUserValidator = Schema.typeSchema(PublicUserSchema);
export const PublicUserArrayValidator = Schema.Array(PublicUserValidator);

export const UserIdPasswordHashValidator = Schema.typeSchema(
   UserIdPasswordHashSchema
);
export const UserIdPasswordHashArrayValidator = Schema.Array(
   UserIdPasswordHashValidator
);

export const UserIdNameValidator = Schema.typeSchema(UserIdNameSchema);
export const UserIdNameArrayValidator = Schema.Array(UserIdNameValidator);

export const UserNameEmailValidator = Schema.typeSchema(UserNameEmailSchema);
export const UserNameEmailArrayValidator = Schema.Array(UserNameEmailValidator);

/* MongoDB Collection Connection */
export function getUserCollection(): Collection<IUserDocument> {
   return DatabaseManager.getInstance()
      .auth.db()
      .collection<IUserDocument>('users');
}

/* MongoDB "users" Collection Indexes */
export const userIndexes = [
   { key: { email: 1 }, unique: true },
] satisfies readonly TypedIndexDescription<IUserDocument>[];

/* Helper types */
export type IUserInput = Schema.Schema.Type<typeof UserInputSchema>;

// ── HTTP response types ──────────────────────────────────────────────────────────
export type AuthUserResponse = {
   success: true;
   message: string;
   user: IPublicUser;
};

export type AuthUserResponseLogout = Omit<AuthUserResponse, 'user'>;
