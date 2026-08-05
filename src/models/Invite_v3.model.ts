import { serverGeneratedFields } from '@ssot/serverGeneratedFields.ts';
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
   tokenHash: sha256HexString,
   usedAt: Schema.NullOr(fullDateInThePast),
   expiresAt: fullDateInTheFuture,
   issuedBy: stringToObjectId,
}).pipe(Schema.extend(InviteInputSchema), Schema.extend(serverGeneratedFields));

export const InviteDocumentValidator = Schema.typeSchema(InviteDocumentSchema);

export type IInviteInput = Schema.Schema.Type<typeof InviteInputSchema>;
export type IInviteDocument = Schema.Schema.Type<typeof InviteDocumentSchema>;

export type ISafeInvite = Pick<
   IInviteDocument,
   'email' | 'role' | 'canIssueInvites' | 'expiresAt' | 'usedAt'
>;

export type ICreateInviteResponse = {
   success: true;
   message: string;
   inv: ISafeInvite;
};

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
