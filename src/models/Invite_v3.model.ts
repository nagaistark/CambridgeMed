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

/* Struct = Input Schema + Server-generated fields */
const InviteDocumentStruct = Schema.Struct({
   tokenHash: sha256HexString,
   usedAt: Schema.NullOr(fullDateInThePast),
   expiresAt: fullDateInTheFuture,
   issuedBy: stringToObjectId,
   ...InviteInputSchema.fields,
   ...ServerGeneratedFields.fields,
});

/* Standalone modular cross-field filters */
export type IInviteDocument = Schema.Schema.Type<typeof InviteDocumentStruct>;

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

/* Full Invite Document Schema */
export const InviteDocumentSchema =
   InviteDocumentStruct.pipe(validateChronology);

/* Projection Schema(s) and inferred types */
export const SafeInviteSchema = InviteDocumentStruct.pick(
   'email',
   'role',
   'canIssueInvites',
   'expiresAt',
   'usedAt'
);
export type ISafeInvite = Schema.Schema.Type<typeof SafeInviteSchema>;

const InviteIssuer = UserDocumentStruct.pick('_id', 'firstName', 'lastName');
export type IInviteIssuer = Schema.Schema.Type<typeof InviteIssuer>;

/* Projections for listing Invite items */
const baseInviteItem = Schema.Struct({
   ...InviteDocumentStruct.pick('_id', 'email', 'role', 'canIssueInvites')
      .fields,
   issuerInfo: Schema.optional(stringToObjectId),
});
export type BaseInviteItem = Schema.Schema.Type<typeof baseInviteItem>;

export const PendingInviteItem = Schema.Struct({
   ...baseInviteItem.fields,
   ...InviteDocumentStruct.pick('expiresAt').fields,
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

/* Validators against which we validate the documents */
export const InviteDocumentValidator = Schema.typeSchema(InviteDocumentSchema);
export const InviteDocumentArrayValidator = Schema.Array(
   InviteDocumentValidator
);
export const SafeInviteValidator = Schema.typeSchema(SafeInviteSchema);

/* MongoDB Collection Connection */
export function getInviteCollection(): Collection<IInviteDocument> {
   return DatabaseManager.getInstance()
      .auth.db()
      .collection<IInviteDocument>('invites');
}

/* MongoDB "invites" Collection Indexes */
export const inviteIndexes = [
   {
      key: { email: 1 },
      unique: true,
      partialFilterExpression: { usedAt: null },
   },
   { key: { tokenHash: 1 }, unique: true },
   { key: { expiresAt: 1 }, expireAfterSeconds: 0 },
] satisfies readonly TypedIndexDescription<IInviteDocument>[];

/* Helper types */
export type IInviteInput = Schema.Schema.Type<typeof InviteInputSchema>;

// ── HTTP response types ──────────────────────────────────────────────────────────
export type ICreateInviteResponse = {
   success: true;
   message: string;
   inv: ISafeInvite;
};

export type IPreviewInviteResponse = {
   success: true;
   inv: ISafeInvite;
};
