import {
   ServerGeneratedFields,
   validateChronology,
} from '@ssot/serverGeneratedFields.ts';
import {
   fullDateInTheFuture,
   ipAddress,
   longString,
   sha256HexString,
   stringToObjectId,
} from '@utils/effectSchemaReusables.ts';
import type { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import { Schema } from 'effect';
import { Collection } from 'mongodb';
import { DatabaseManager } from '../mongoDBConnect.ts';

export const SessionDocumentBase = Schema.Struct({
   userId: stringToObjectId,

   /* SHA-256 digest of the raw opaque token currently valid for this session. Primary lookup key on every refresh. */
   currentTokenHash: sha256HexString,

   /* Digest of the immediately preceding token; null only before the first rotation. Race tolerance (inside the grace window) and reuse detection (outside it). */
   previousTokenHash: Schema.NullOr(sha256HexString),

   /* When currentTokenHash was last written; anchors the grace window. */
   rotatedAt: Schema.ValidDateFromSelf,

   /* Device metadata captured at login. null = the client sent nothing usable. */
   ipAddress: Schema.NullOr(ipAddress),
   userAgent: Schema.NullOr(longString),

   ...ServerGeneratedFields.fields,
});

/* A session being created must expire in the future; one read back may legitimately be past it (the TTL janitor lags by up to a minute). */
const SessionDocumentCreateStruct = Schema.Struct({
   ...SessionDocumentBase.fields,
   expiresAt: fullDateInTheFuture,
});

const SessionDocumentReadStruct = Schema.Struct({
   ...SessionDocumentBase.fields,
   expiresAt: Schema.ValidDateFromSelf,
});

export const SessionDocumentCreateSchema =
   SessionDocumentCreateStruct.pipe(validateChronology);
export const SessionDocumentReadSchema =
   SessionDocumentReadStruct.pipe(validateChronology);

/* Kept under its old name to avoid touching ten imports. It is the Read type. Create and Read share the same type side. */
export type ISessionDocument = Schema.Schema.Type<
   typeof SessionDocumentReadStruct
>;

/* Minimal shape for refreshController (both lookups). */
const SessionRefreshSchema = SessionDocumentReadStruct.pick(
   '_id',
   'userId',
   'rotatedAt'
);
export type ISessionRefresh = Schema.Schema.Type<typeof SessionRefreshSchema>;

export const SessionDocumentCreateValidator = Schema.typeSchema(
   SessionDocumentCreateSchema
);
export const SessionDocumentReadValidator = Schema.typeSchema(
   SessionDocumentReadSchema
);
export const SessionRefreshValidator = Schema.typeSchema(SessionRefreshSchema);

export function getSessionCollection(): Collection<ISessionDocument> {
   return DatabaseManager.getInstance()
      .auth.db()
      .collection<ISessionDocument>('sessions');
}

export const sessionIndexes = [
   { key: { currentTokenHash: 1 }, unique: true },
   { key: { previousTokenHash: 1 }, sparse: true },

   // Needed for the "nuclear" option: deleteMany({ userId }).
   { key: { userId: 1 } },

   // TTL index: MongoDB removes expired documents once expiresAt has passed.
   { key: { expiresAt: 1 }, expireAfterSeconds: 0 },
] satisfies readonly TypedIndexDescription<ISessionDocument>[];
