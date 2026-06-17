import { InitiateEmailChangeVSchema } from '@users/User.schemas.ts';
import { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import {
   jsDateInTheFuture,
   jsDateInThePast,
   objectIdInstance,
   Sha256HexString,
   validateEmail,
} from '@utils/valibotSchemaReusables.ts';
import { Collection } from 'mongodb';
import { DatabaseManager } from 'mongoDBConnect.ts';
import { date, InferOutput, nullable, strictObject } from 'valibot';

export const EmailChangeDocumentVSchema = strictObject({
   ...InitiateEmailChangeVSchema.entries,
   confirmTokenHash: Sha256HexString,
   cancelTokenHash: Sha256HexString,
   userId: objectIdInstance,
   oldEmail: validateEmail,

   /* TTL index target. Both tokens expire together at this moment regardless of their individual usage state. */
   expiresAt: jsDateInTheFuture,
   confirmedAt: nullable(jsDateInThePast),

   _id: objectIdInstance,
   createdAt: date(`createdAt must be a valid JS Date object.`),
   updatedAt: date(`updatedAt must be a valid JS Date object.`),
});

type IEmailChangeDocument = InferOutput<typeof EmailChangeDocumentVSchema>;

export function getEmailChangeCollection(): Collection<IEmailChangeDocument> {
   return DatabaseManager.getInstance()
      .auth.db()
      .collection<IEmailChangeDocument>('emailChanges');
}

export const emailChangeIndexes = [
   /* Unique indexes on both hashes. Primary lookup keys for their respective controllers. */
   { key: { confirmTokenHash: 1 }, unique: true },
   { key: { cancelTokenHash: 1 }, unique: true },

   /* Needed to enforce the "one pending change per user" rule at the application and database layers. */
   { key: { userId: 1 }, unique: true },

   /* TTL janitor. */
   { key: { expiresAt: 1 }, expireAfterSeconds: 0 },
] satisfies readonly TypedIndexDescription<IEmailChangeDocument>[];
