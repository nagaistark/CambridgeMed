import {
   fullDateInTheFuture,
   objectIdInstance,
   sha256HexString,
} from '@utils/effectSchemaReusables.ts';
import { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import { Schema } from 'effect';
import { Collection } from 'mongodb';
import { DatabaseManager } from 'mongoDBConnect.ts';

export const PasswordResetDocumentSchema = Schema.Struct({
   tokenHash: sha256HexString,
   userId: objectIdInstance,
   expiresAt: fullDateInTheFuture,
   _id: objectIdInstance,
   createdAt: Schema.ValidDateFromSelf,
   updatedAt: Schema.ValidDateFromSelf,
});

type IPasswordResetDoc = Schema.Schema.Type<typeof PasswordResetDocumentSchema>;

export function getPasswordResetCollection(): Collection<IPasswordResetDoc> {
   return DatabaseManager.getInstance()
      .auth.db()
      .collection<IPasswordResetDoc>('passwordresets');
}

export const passwordResetIndexes = [
   /* Primary lookup key. Every redemption request hashes the raw token and queries this field. */
   { key: { tokenHash: 1 }, unique: true },

   /* Enforces one active reset per user at the database layer. The application layer (forgotPasswordController) deliberately replaces any existing reset with a fresh one, so this index acts as a safety net rather than a primary gate. */
   { key: { userId: 1 }, unique: true },

   /* TTL janitor. */
   { key: { expiresAt: 1 }, expireAfterSeconds: 0 },
] satisfies readonly TypedIndexDescription<IPasswordResetDoc>[];
