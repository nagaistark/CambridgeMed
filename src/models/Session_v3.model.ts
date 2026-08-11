import { serverGeneratedFields } from '@ssot/serverGeneratedFields.ts';
import {
   fullDateInTheFuture,
   ipAddress,
   longString,
   sha256HexString,
   stringToObjectId,
} from '@utils/effectSchemaReusables.ts';
import { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import { Schema } from 'effect';
import { Collection } from 'mongodb';
import { DatabaseManager } from '../mongoDBConnect.ts';

export const SessionDocumentSchema = Schema.Struct({
   userId: stringToObjectId,

   /* SHA-256 hex digest of the raw opaque token currently valid for this session. Primary lookup key on every refresh request. */
   currentTokenHash: sha256HexString,

   /* SHA-256 hex digest of the immediately preceding token. Null only for the very first token issued at login (no rotation has occurred yet). Kept for two purposes: 1. Race condition tolerance: a simultaneous refresh from another tab will present this hash within a short grace window → treat as benign. 2. Reuse detection: this hash arriving AFTER the grace window means a rotated token was re-presented → nuclear as malicious. */
   previousTokenHash: Schema.NullOr(sha256HexString),

   /* The moment the currentTokenHash was last written. Used to calculate the grace window. */
   rotatedAt: Schema.ValidDateFromSelf,

   /* The TTL index on this field causes MongoDB to automatically purge the session document at the weekly reset, regardless of whether the user explicitly logged out. */
   expiresAt: fullDateInTheFuture,

   /* Device-metadata (captured once at login, never mutated) */
   ipAddress: ipAddress,
   userAgent: longString,
}).pipe(Schema.extend(serverGeneratedFields));

export const SessionDocumentValidator = Schema.typeSchema(
   SessionDocumentSchema
);

export type ISessionDocument = Schema.Schema.Type<typeof SessionDocumentSchema>;

export function getSessionCollection(): Collection<ISessionDocument> {
   return DatabaseManager.getInstance()
      .auth.db()
      .collection<ISessionDocument>('sessions');
}

export const sessionIndexes = [
   { key: { currentTokenHash: 1 }, unique: true },
   { key: { previousTokenHash: 1 }, sparse: true },

   // Needed for "nuclear" option. If reuse is confirmed, call deleteMany({ userId }) to destroy all active sessions for the affected user in one operation.
   { key: { userId: 1 } },

   // TTL index: MongoDB automatically removes expired documents once expiresAt has passed.
   { key: { expiresAt: 1 }, expireAfterSeconds: 0 },
] satisfies readonly TypedIndexDescription<ISessionDocument>[];
