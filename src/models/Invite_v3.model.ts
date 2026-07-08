import { allowedRoles } from '@ssot/user_roles_constants.ts';
import {
   clinicStaffEmail,
   objectIdInstance,
   sha256HexString,
   validDateInTheFuture,
   validDateInThePast,
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
   ...InviteInputSchema.fields,
   _id: objectIdInstance,
   tokenHash: sha256HexString,
   usedAt: Schema.NullOr(validDateInThePast),
   expiresAt: validDateInTheFuture,
   issuedBy: objectIdInstance,
   createdAt: Schema.ValidDateFromSelf,
   updatedAt: Schema.ValidDateFromSelf,
});

export type IInviteDocument = Schema.Schema.Type<typeof InviteDocumentSchema>;

export type ISafeInvite = Pick<
   IInviteDocument,
   'email' | 'role' | 'canIssueInvites' | 'expiresAt' | 'usedAt'
>;

export type IPreviewInviteResponse = {
   success: true;
   inv: ISafeInvite;
};

export function getInviteCollection(): Collection<IInviteDocument> {
   return DatabaseManager.getInstance()
      .auth.db()
      .collection<IInviteDocument>('invites');
}

export const inviteIndexes = [
   { key: { email: 1 } },
   { key: { tokenHash: 1 }, unique: true },
   { key: { expiresAt: 1 }, expireAfterSeconds: 0 },
] satisfies readonly TypedIndexDescription<IInviteDocument>[];
