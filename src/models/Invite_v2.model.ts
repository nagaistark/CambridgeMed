import { allowedRoles } from '@ssot/user_roles_constants.ts';
import { makePicklist } from '@utils/arrayToValPicklist.ts';
import { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import {
   jsDateInTheFuture,
   jsDateInThePast,
   objectIdInstance,
   Sha256HexString,
} from '@utils/valibotSchemaReusables.ts';
import { Collection } from 'mongodb';
import { DatabaseManager } from 'mongoDBConnect.ts';
import {
   boolean,
   date,
   email,
   InferOutput,
   maxLength,
   nonEmpty,
   nullable,
   pipe,
   strictObject,
   string,
   transform,
} from 'valibot';

export const InviteInputVSchema = strictObject({
   email: pipe(
      string(`Must be a string.`),
      nonEmpty(`Please enter your email.`),
      email(`Incorrectly formatted email.`),
      maxLength(64, `Your email is too long.`),
      transform(str => {
         return str.toLowerCase();
      })
   ),
   role: makePicklist(allowedRoles), // Allowed Roles only, never a superadmin
   canIssueInvites: boolean(),
});

export const InviteDocumentVSchema = strictObject({
   ...InviteInputVSchema.entries,
   _id: objectIdInstance,
   tokenHash: Sha256HexString,
   usedAt: nullable(jsDateInThePast),
   expiresAt: jsDateInTheFuture,
   issuedBy: objectIdInstance,
   createdAt: date(`createdAt must be a valid JS Date object.`),
   updatedAt: date(`updatedAt must be a valid JS Date object.`),
});

export type IInviteInput = InferOutput<typeof InviteInputVSchema>;
export type IInviteDocument = InferOutput<typeof InviteDocumentVSchema>;

export type SafeInvite = Pick<
   IInviteDocument,
   'email' | 'role' | 'canIssueInvites' | 'expiresAt' | 'usedAt'
>;

export type PreviewInviteResponse = {
   success: true;
   inv: SafeInvite;
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
