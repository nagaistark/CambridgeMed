import {
   ServerGeneratedFields,
   validateChronology,
} from '@ssot/serverGeneratedFields.ts';
import { allowedRoles } from '@ssot/user_roles_constants.ts';
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
export const InviteInputSchema = Schema.Struct({
   email: clinicStaffEmail,
   role: Schema.Literal(...allowedRoles),
   canIssueInvites: Schema.Boolean,
});
export type IInviteInput = Schema.Schema.Type<typeof InviteInputSchema>;

/* Struct = Input Schema + Server-generated fields */
const InviteDocumentBase = Schema.Struct({
   tokenHash: sha256HexString,
   issuedBy: stringToObjectId,
   ...InviteInputSchema.fields,
   ...ServerGeneratedFields.fields,
});

const InviteDocumentCreateStruct = Schema.Struct({
   ...InviteDocumentBase.fields,
   usedAt: Schema.Null,
   expiresAt: fullDateInTheFuture,
});

const InviteDocumentReadStruct = Schema.Struct({
   ...InviteDocumentBase.fields,
   usedAt: Schema.NullOr(Schema.ValidDateFromSelf),
   expiresAt: Schema.ValidDateFromSelf,
});

export type IInviteDocumentRead = Schema.Schema.Type<
   typeof InviteDocumentReadStruct
>;

export type IInviteDocumentCreate = Schema.Schema.Type<
   typeof InviteDocumentCreateStruct
>;

// ===== Standalone modular cross-field filters ====================================
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

// ===== Full Invite Document Schemas ==============================================
export const InviteDocumentCreateSchema =
   InviteDocumentCreateStruct.pipe(validateChronology);

export const InviteDocumentReadSchema = InviteDocumentReadStruct.pipe(
   validateChronology,
   validateInviteTimeline
);

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
);
export type ISafeInviteCreate = Schema.Schema.Type<
   typeof SafeInviteCreateSchema
>;

const SafeInviteReadSchema = InviteDocumentReadStruct.pick(...SAFE_INVITE_KEYS);
export type ISafeInviteRead = Schema.Schema.Type<typeof SafeInviteReadSchema>;

/* Helpers used in listInvitesController. */
const baseInviteItem = Schema.Struct({
   ...InviteDocumentReadStruct.pick('_id', 'email', 'role', 'canIssueInvites')
      .fields,
   issuer: Schema.optional(UserIdNameSchema),
});
export type BaseInviteItem = Schema.Schema.Type<typeof baseInviteItem>;

export const PendingInviteItem = Schema.Struct({
   ...baseInviteItem.fields,
   ...InviteDocumentReadStruct.pick('expiresAt').fields,
   status: Schema.Literal('pending'),
});
export type IPendingInviteItem = Schema.Schema.Type<typeof PendingInviteItem>;

export const AcceptedInviteItem = Schema.Struct({
   ...baseInviteItem.fields,
   ...UserDocumentStruct.pick('firstName', 'lastName').fields,
   status: Schema.Literal('accepted'),
   usedAt: Schema.ValidDateFromSelf, // "Accepted" Invite means usedAt is guaranteed non-null.
});
export type IAcceptedInviteItem = Schema.Schema.Type<typeof AcceptedInviteItem>;

/* Minimal issuedBy, usedAt + _id fields used by revokeInviteController */
export const InviteRevocationSchema = InviteDocumentReadStruct.pick(
   '_id',
   'usedAt',
   'issuedBy'
);
export type IInviteRevocation = Schema.Schema.Type<
   typeof InviteRevocationSchema
>;

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

export const InviteRevocationValidator = Schema.typeSchema(
   InviteRevocationSchema
);
export const InviteRevocationArrayValidator = Schema.Array(
   InviteRevocationValidator
);

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
   inv: ISafeInviteRead;
};
