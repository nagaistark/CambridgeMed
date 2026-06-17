import { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import {
   jsDateInTheFuture,
   objectIdInstance,
   Sha256HexString,
} from '@utils/valibotSchemaReusables.ts';
import { Collection } from 'mongodb';
import { DatabaseManager } from 'mongoDBConnect.ts';
import { date, InferOutput, strictObject } from 'valibot';

export const PasswordResetDocumentVSchema = strictObject({
   tokenHash: Sha256HexString,
   userId: objectIdInstance,
   expiresAt: jsDateInTheFuture,
   _id: objectIdInstance,
   createdAt: date(`createdAt must be a valid JS Date object.`),
   updatedAt: date(`updatedAt must be a valid JS Date object.`),
});

type IPasswordResetDocument = InferOutput<typeof PasswordResetDocumentVSchema>;

export function getPasswordResetCollection(): Collection<IPasswordResetDocument> {
   return DatabaseManager.getInstance()
      .auth.db()
      .collection<IPasswordResetDocument>('passwordresets');
}

export const passwordResetIndexes = [
   /* Primary lookup key. Every redemption request hashes the raw token and queries this field. */
   { key: { tokenHash: 1 }, unique: true },

   /* Enforces one active reset per user at the database layer. The application layer (forgotPasswordController) deliberately replaces any existing reset with a fresh one, so this index acts as a safety net rather than a primary gate. */
   { key: { userId: 1 }, unique: true },

   /* TTL janitor. */
   { key: { expiresAt: 1 }, expireAfterSeconds: 0 },
] satisfies readonly TypedIndexDescription<IPasswordResetDocument>[];
