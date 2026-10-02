import {
   ServerGeneratedFields,
   validateChronology,
} from '@ssot/serverGeneratedFields.ts';
import { allowedRoles } from '@ssot/user_roles_constants.ts';
import { canBeDelegated } from '@ssot/permissions_constants.ts';
import {
   clinicStaffEmail,
   fullDateInTheFuture,
   sha256HexString,
   stringToObjectId,
} from '@utils/effectSchemaReusables.ts';
import { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import { Schema } from 'effect';
import { Collection } from 'mongodb';
import { DatabaseManager } from '../mongoDBConnect.ts';
import { UserDocumentStruct, UserIdNameSchema } from '@models/User_v3.model.ts';

/* Input schema: what arrives over HTTP. */
const InviteInputStruct = Schema.Struct({
   email: clinicStaffEmail,
   role: Schema.Literal(...allowedRoles),
   canIssueInvites: Schema.Boolean,
});

/* Struct = Input Schema + Server-generated fields */
const InviteDocumentBase = Schema.Struct({
   tokenHash: sha256HexString,
   issuedBy: stringToObjectId,
   ...InviteInputStruct.fields,
   ...ServerGeneratedFields.fields,
});

const InviteDocumentCreateStruct = Schema.Struct({
   ...InviteDocumentBase.fields,
   usedAt: Schema.Null,
   acceptedBy: Schema.Null,
   expiresAt: fullDateInTheFuture,
});

const InviteDocumentReadStruct = Schema.Struct({
   ...InviteDocumentBase.fields,
   usedAt: Schema.NullOr(Schema.ValidDateFromSelf),
   acceptedBy: Schema.NullOr(stringToObjectId),
   expiresAt: Schema.ValidDateFromSelf,
});

// ===== Standalone modular cross-field filters ====================================
const validateAcceptanceLinkage = <
   A extends Pick<IInviteDocumentRead, 'usedAt' | 'acceptedBy'>,
   I,
   R,
>(
   schema: Schema.Schema<A, I, R>
) => {
   return schema.pipe(
      Schema.filter(doc => {
         const issues: Array<Schema.FilterIssue> = [];

         if ((doc.usedAt === null) !== (doc.acceptedBy === null)) {
            issues.push({
               path: ['acceptedBy'],
               message: `acceptedBy must be set if and only if the invite has been used.`,
            });
         }

         return issues;
      })
   );
};

const validateInvitePrivilege = <
   A extends Pick<
      Schema.Schema.Type<typeof InviteInputStruct>,
      'role' | 'canIssueInvites'
   >,
   I,
   R,
>(
   schema: Schema.Schema<A, I, R>
) => {
   return schema.pipe(
      Schema.filter(invite => {
         const issues: Array<Schema.FilterIssue> = [];

         if (
            invite.canIssueInvites &&
            !canBeDelegated(invite.role, 'ISSUE_INVITES')
         ) {
            issues.push({
               path: ['canIssueInvites'],
               message: `The ${invite.role} role cannot be granted invite privileges.`,
            });
         }

         return issues;
      })
   );
};

const validateInviteTimeline = <
   A extends Pick<IInviteDocumentRead, 'createdAt' | 'expiresAt' | 'usedAt'>,
   I,
   R,
>(
   schema: Schema.Schema<A, I, R>
) => {
   return schema.pipe(
      Schema.filter(doc => {
         const issues: Array<Schema.FilterIssue> = [];

         if (doc.expiresAt.getTime() <= doc.createdAt.getTime()) {
            issues.push({
               path: ['expiresAt'],
               message: `expiresAt must be chronologically after createdAt.`,
            });
         }

         if (
            doc.usedAt !== null &&
            doc.usedAt.getTime() < doc.createdAt.getTime()
         ) {
            issues.push({
               path: ['usedAt'],
               message: `usedAt cannot be chronologically before createdAt.`,
            });
         }

         return issues;
      })
   );
};

// ===== Invite Input Schema And Type ==============================================
export const InviteInputSchema = InviteInputStruct.pipe(
   validateInvitePrivilege
);

export type IInviteInput = Schema.Schema.Type<typeof InviteInputSchema>;

// ===== Full Invite Document Schemas And Types ====================================
export const InviteDocumentCreateSchema = InviteDocumentCreateStruct.pipe(
   validateChronology,
   validateInvitePrivilege,
   validateAcceptanceLinkage
);

export type IInviteDocumentCreate = Schema.Schema.Type<
   typeof InviteDocumentCreateStruct
>;

export const InviteDocumentReadSchema = InviteDocumentReadStruct.pipe(
   validateChronology,
   validateInviteTimeline,
   validateInvitePrivilege,
   validateAcceptanceLinkage
);

export type IInviteDocumentRead = Schema.Schema.Type<
   typeof InviteDocumentReadStruct
>;

// ===== PARTIAL SCHEMA(S) FOR PROJECTIONS AND INFERRED TYPES ===================================
const SAFE_INVITE_KEYS = [
   '_id',
   'email',
   'role',
   'canIssueInvites',
   'expiresAt',
   'usedAt',
   'issuedBy',
] as const satisfies readonly (keyof IInviteDocumentRead)[];

/* Safe Invite Schemas. Excluding the sensitive tokenHash info in particular. */
const SafeInviteCreateSchema = InviteDocumentCreateStruct.pick(
   ...SAFE_INVITE_KEYS
).pipe(validateInvitePrivilege);
export type ISafeInviteCreate = Schema.Schema.Type<
   typeof SafeInviteCreateSchema
>;

const SafeInviteReadSchema = InviteDocumentReadStruct.pick(
   ...SAFE_INVITE_KEYS
).pipe(validateInvitePrivilege);
export type ISafeInviteRead = Schema.Schema.Type<typeof SafeInviteReadSchema>;

/* For listInvitesController only. Deliberately NOT part of SAFE_INVITE_KEYS, because the public preview endpoint returns that shape. */
const InviteListReadSchema = InviteDocumentReadStruct.pick(
   ...SAFE_INVITE_KEYS,
   'acceptedBy'
).pipe(validateInvitePrivilege, validateAcceptanceLinkage);
export type IInviteListRead = Schema.Schema.Type<typeof InviteListReadSchema>;

/* Other helpers used in listInvitesController. */
const baseInviteItem = Schema.Struct({
   ...InviteDocumentReadStruct.pick('_id', 'email', 'role', 'canIssueInvites')
      .fields,
   issuer: Schema.optional(UserIdNameSchema),
});
export type BaseInviteItem = Schema.Schema.Type<typeof baseInviteItem>;

const PendingInviteItem = Schema.Struct({
   ...baseInviteItem.fields,
   ...InviteDocumentReadStruct.pick('expiresAt').fields,
   status: Schema.Literal('pending'),
});
export type IPendingInviteItem = Schema.Schema.Type<typeof PendingInviteItem>;

const AcceptedInviteItem = Schema.Struct({
   ...baseInviteItem.fields,
   ...UserDocumentStruct.pick('firstName', 'lastName').fields,
   status: Schema.Literal('accepted'),
   usedAt: Schema.ValidDateFromSelf, // "Accepted" Invite means usedAt is guaranteed non-null.
});
export type IAcceptedInviteItem = Schema.Schema.Type<typeof AcceptedInviteItem>;

/* Minimal issuedBy, usedAt + _id fields used by revokeInviteController */
const InviteRevocationSchema = InviteDocumentReadStruct.pick(
   '_id',
   'usedAt',
   'issuedBy'
);
export type IInviteRevocation = Schema.Schema.Type<
   typeof InviteRevocationSchema
>;

/* Minimal shape for the pre-hash email pre-flight in acceptInviteController. */
const InviteEmailCheckSchema = InviteDocumentReadStruct.pick('_id', 'email');
export type IInviteEmailCheck = Schema.Schema.Type<
   typeof InviteEmailCheckSchema
>;

/* Minimal shape for previews in previewInviteController. */
const InvitePreviewSchema = InviteDocumentReadStruct.pick(
   'role',
   'expiresAt',
   'usedAt'
);
export type IInvitePreview = Schema.Schema.Type<typeof InvitePreviewSchema>;

// ===== Validators against which we validate the documents ========================
export const InviteDocumentCreateValidator = Schema.typeSchema(
   InviteDocumentCreateSchema
);

export const InviteDocumentReadValidator = Schema.typeSchema(
   InviteDocumentReadSchema
);
export const InviteDocumentReadArrayValidator = Schema.Array(
   InviteDocumentReadValidator
);

export const SafeInviteReadValidator = Schema.typeSchema(SafeInviteReadSchema);
export const SafeInviteReadArrayValidator = Schema.Array(
   SafeInviteReadValidator
);

export const InviteListReadArrayValidator = Schema.Array(
   Schema.typeSchema(InviteListReadSchema)
);

export const InviteRevocationValidator = Schema.typeSchema(
   InviteRevocationSchema
);
export const InviteRevocationArrayValidator = Schema.Array(
   InviteRevocationValidator
);

export const InviteEmailCheckValidator = Schema.typeSchema(
   InviteEmailCheckSchema
);

export const InvitePreviewValidator = Schema.typeSchema(InvitePreviewSchema);

// ===== MongoDB Collection Connection =============================================
export function getInviteCollection(): Collection<IInviteDocumentRead> {
   return DatabaseManager.getInstance()
      .auth.db()
      .collection<IInviteDocumentRead>('invites');
}

// ===== MongoDB "invites" Collection Indexes ======================================
export const inviteIndexes = [
   {
      key: { email: 1 },
      unique: true,
      partialFilterExpression: { usedAt: null },
   },
   { key: { tokenHash: 1 }, unique: true },
   {
      key: { expiresAt: 1 },
      expireAfterSeconds: 0,
      partialFilterExpression: { usedAt: null }, // ← only sweep NEVER-accepted invites
   },
] satisfies readonly TypedIndexDescription<IInviteDocumentRead>[];

// ── HTTP response types ──────────────────────────────────────────────────────────
export type ICreateInviteResponse = {
   success: true;
   message: string;
   inv: ISafeInviteCreate;
};

export type IPreviewInviteResponse = {
   success: true;
   inv: Omit<IInvitePreview, 'usedAt'>;
};
