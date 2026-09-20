import { ServerGeneratedFields } from '@ssot/serverGeneratedFields.ts';
import { allowedRoles } from '@ssot/user_roles_constants.ts';
import {
   clinicStaffEmail,
   fullDateInTheFuture,
   fullDateInThePast,
   sha256HexString,
   stringToObjectId,
} from '@utils/effectSchemaReusables.ts';
import { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import { Schema } from 'effect';
import { Collection } from 'mongodb';
import { DatabaseManager } from '../mongoDBConnect.ts';
import { UserDocumentStruct } from '@models/User_v3.model.ts';

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

// ===== Standalone modular cross-field filters ====================================
export type IInviteDocument = Schema.Schema.Type<
   typeof InviteDocumentReadStruct
>;

const validateChronology = <
   A extends Pick<IInviteDocument, 'createdAt' | 'updatedAt'>,
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

const validateInviteTimeline = <
   A extends Pick<IInviteDocument, 'createdAt' | 'expiresAt' | 'usedAt'>,
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

// ===== PROJECTION SCHEMA(S) AND INFERRED TYPES ===================================
/* Safe Invite Schemas. Excluding the sensitive tokenHash info in particular. Used in createInviteController and previewInviteController. */
const SAFE_INVITE_KEYS = [
   '_id',
   'email',
   'role',
   'canIssueInvites',
   'expiresAt',
   'usedAt',
   'issuedBy',
] as const satisfies readonly (keyof IInviteDocument)[];

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
   issuerInfo: Schema.optional(stringToObjectId),
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
   usedAt: fullDateInThePast, // "Accepted" Invite means usedAt is guaranteed non-null.
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

export const SafeInviteCreateValidator = Schema.typeSchema(
   SafeInviteCreateSchema
);
// no SafeInviteCreateArrayValidator because we do not create invites in bulk

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
export function getInviteCollection(): Collection<IInviteDocument> {
   return DatabaseManager.getInstance()
      .auth.db()
      .collection<IInviteDocument>('invites');
}

// ===== MongoDB "invites" Collection Indexes ======================================
export const inviteIndexes = [
   {
      key: { email: 1 },
      unique: true,
      partialFilterExpression: { usedAt: null },
   },
   { key: { tokenHash: 1 }, unique: true },
   { key: { expiresAt: 1 }, expireAfterSeconds: 0 },
] satisfies readonly TypedIndexDescription<IInviteDocument>[];

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
