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
import { DatabaseManager } from 'mongoDBConnect.ts';

export const InviteInputSchema = Schema.Struct({
   email: clinicStaffEmail,
   role: Schema.Literal(...allowedRoles),
   canIssueInvites: Schema.Boolean,
});

export const InviteDocumentSchema = Schema.Struct({
   _id: stringToObjectId,
   tokenHash: sha256HexString,
   usedAt: Schema.NullOr(fullDateInThePast),
   expiresAt: fullDateInTheFuture,
   issuedBy: stringToObjectId,
   createdAt: Schema.ValidDateFromSelf,
   updatedAt: Schema.ValidDateFromSelf,
}).pipe(Schema.extend(InviteInputSchema));

export const InviteDocumentValidator = Schema.typeSchema(InviteDocumentSchema);

export type IInviteDoc = Schema.Schema.Type<typeof InviteDocumentSchema>;

export type ISafeInvite = Pick<
   IInviteDoc,
   'email' | 'role' | 'canIssueInvites' | 'expiresAt' | 'usedAt'
>;

export type IPreviewInviteResponse = {
   success: true;
   inv: ISafeInvite;
};

export function getInviteCollection(): Collection<IInviteDoc> {
   return DatabaseManager.getInstance()
      .auth.db()
      .collection<IInviteDoc>('invites');
}

export const inviteIndexes = [
   { key: { email: 1 } },
   { key: { tokenHash: 1 }, unique: true },
   { key: { expiresAt: 1 }, expireAfterSeconds: 0 },
] satisfies readonly TypedIndexDescription<IInviteDoc>[];
