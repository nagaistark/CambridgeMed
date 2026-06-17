import { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import {
   jsDateInTheFuture,
   longString,
   objectIdInstance,
   Sha256HexString,
   validateIPAddress,
} from '@utils/valibotSchemaReusables.ts';
import { Collection } from 'mongodb';
import { DatabaseManager } from 'mongoDBConnect.ts';
import { date, InferOutput, nullable, strictObject } from 'valibot';

export const SessionDocumentVSchema = strictObject({
   userId: objectIdInstance,

   /* SHA-256 hex digest of the raw opaque token currently valid for this session. Primary lookup key on every refresh request. */
   currentTokenHash: Sha256HexString,

   /* SHA-256 hex digest of the immediately preceding token. Null only for the very first token issued at login (no rotation has occurred yet). Kept for two purposes: 1. Race condition tolerance: a simultaneous refresh from another tab will present this hash within a short grace window → treat as benign. 2. Reuse detection: this hash arriving AFTER the grace window means a rotated token was re-presented → nuclear as malicious. */
   previousTokenHash: nullable(Sha256HexString),

   /* The moment the currentTokenHash was last written. Used to calculate the grace window. */
   rotatedAt: date(`rotatedAt must be a valid JS Date object.`),

   /* The TTL index on this field causes MongoDB to automatically purge the session document at the weekly reset, regardless of whether the user explicitly logged out. */
   expiresAt: jsDateInTheFuture,

   /* Device-metadata (captured once at login, never mutated) */
   ipAddress: validateIPAddress,
   userAgent: longString,

   _id: objectIdInstance,
   createdAt: date(`createdAt must be a valid JS Date object.`),
   updatedAt: date(`updatedAt must be a valid JS Date object.`),
});

type ISessionDocument = InferOutput<typeof SessionDocumentVSchema>;

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
