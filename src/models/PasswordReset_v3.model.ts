import { serverGeneratedFields } from '@ssot/serverGeneratedFields.ts';
import {
   fullDateInTheFuture,
   sha256HexString,
   stringToObjectId,
} from '@utils/effectSchemaReusables.ts';
import { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import { Schema } from 'effect';
import { Collection } from 'mongodb';
import { DatabaseManager } from '../mongoDBConnect.ts';

export const PasswordResetDocumentSchema = Schema.Struct({
   tokenHash: sha256HexString,
   userId: stringToObjectId,
   expiresAt: fullDateInTheFuture,
}).pipe(Schema.extend(serverGeneratedFields));

export const PasswordResetDocumentValidator = Schema.typeSchema(
   PasswordResetDocumentSchema
);

export type IPasswordResetDocument = Schema.Schema.Type<
   typeof PasswordResetDocumentSchema
>;

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
