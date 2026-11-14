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
import type { ExpandType } from '@utils/helperTypes.ts';
import type { IUserIdNameEmail } from '@models/User_v3.model.ts';

export const SessionDocumentBase = Schema.Struct({
   userId: stringToObjectId,

   /* SHA-256 digest of the opaque token held in the browser's cookie. The raw token is never stored. Primary lookup key on every authenticated request. */
   tokenHash: sha256HexString,

   /* The last moment a deliberate request slid the idle timer. Written at most once per SESSION_ACTIVITY_THROTTLE_MS. A SECURITY signal (idle logoff), not a UX "last seen". */
   lastActiveAt: Schema.ValidDateFromSelf,

   /* Device metadata captured at login. null = the client sent nothing usable. */
   ipAddress: Schema.NullOr(ipAddress),
   userAgent: Schema.NullOr(longString),

   ...ServerGeneratedFields.fields,
});

/* Two clocks. `absoluteExpiresAt` is the weekly reset: fixed at login, never moves. `expiresAt` is the idle deadline: it slides forward on activity but is capped at `absoluteExpiresAt`, so `expiresAt > now` alone still means "this session is alive" (and the TTL janitor keeps working on it). A session being created must expire in the future; one read back may legitimately be past it (the TTL janitor lags by up to a minute). */
const SessionDocumentCreateStruct = Schema.Struct({
   ...SessionDocumentBase.fields,
   absoluteExpiresAt: fullDateInTheFuture,
   expiresAt: fullDateInTheFuture,
});

const SessionDocumentReadStruct = Schema.Struct({
   ...SessionDocumentBase.fields,
   absoluteExpiresAt: Schema.ValidDateFromSelf,
   expiresAt: Schema.ValidDateFromSelf,
});

/* Create and Read share the same type side. */
export type ISessionDocument = Schema.Schema.Type<
   typeof SessionDocumentReadStruct
>;

// ===== Standalone modular cross-field filters ====================================
const validateExpiryOrder = <
   A extends Pick<ISessionDocument, 'expiresAt' | 'absoluteExpiresAt'>,
   I,
   R,
>(
   schema: Schema.Schema<A, I, R>
) => {
   return schema.pipe(
      Schema.filter(doc => {
         const issues: Array<Schema.FilterIssue> = [];

         if (doc.expiresAt.getTime() > doc.absoluteExpiresAt.getTime()) {
            issues.push({
               path: ['expiresAt'],
               message: `expiresAt cannot be chronologically after absoluteExpiresAt.`,
            });
         }

         return issues;
      })
   );
};

const validateSessionTimeline = <
   A extends Pick<
      ISessionDocument,
      'createdAt' | 'lastActiveAt' | 'expiresAt' | 'absoluteExpiresAt'
   >,
   I,
   R,
>(
   schema: Schema.Schema<A, I, R>
) => {
   return schema.pipe(
      Schema.filter(doc => {
         const issues: Array<Schema.FilterIssue> = [];

         if (doc.expiresAt.getTime() <= doc.createdAt.getTime()) {
            issues.push({
               path: ['expiresAt'],
               message: `expiresAt must be chronologically after createdAt.`,
            });
         }

         if (doc.absoluteExpiresAt.getTime() <= doc.createdAt.getTime()) {
            issues.push({
               path: ['absoluteExpiresAt'],
               message: `absoluteExpiresAt must be chronologically after createdAt.`,
            });
         }

         if (doc.lastActiveAt.getTime() < doc.createdAt.getTime()) {
            issues.push({
               path: ['lastActiveAt'],
               message: `lastActiveAt cannot be chronologically before createdAt.`,
            });
         }

         return issues;
      })
   );
};

export const SessionDocumentCreateSchema = SessionDocumentCreateStruct.pipe(
   validateChronology,
   validateExpiryOrder,
   validateSessionTimeline
);
export const SessionDocumentReadSchema = SessionDocumentReadStruct.pipe(
   validateChronology,
   validateExpiryOrder,
   validateSessionTimeline
);

// ===== PARTIAL SCHEMA(S) FOR PROJECTIONS AND INFERRED TYPES ======================
/* What a user may see about a session. No token hash, ever. */
const SESSION_SELF_VIEW_KEYS = [
   '_id',
   'ipAddress',
   'userAgent',
   'createdAt',
   'expiresAt',
   'lastActiveAt',
] as const satisfies readonly (keyof ISessionDocument)[];

const SessionSelfViewSchema = SessionDocumentReadStruct.pick(
   ...SESSION_SELF_VIEW_KEYS
);
export type ISessionSelfView = Schema.Schema.Type<typeof SessionSelfViewSchema>;

const SessionAdminViewSchema = SessionDocumentReadStruct.pick(
   ...SESSION_SELF_VIEW_KEYS,
   'userId'
);
export type ISessionAdminView = Schema.Schema.Type<
   typeof SessionAdminViewSchema
>;

/* Minimal shape of a session we only need to identify and attribute (kill result, cap eviction). */
const SessionOwnerSchema = SessionDocumentReadStruct.pick('_id', 'userId');
export type ISessionOwner = Schema.Schema.Type<typeof SessionOwnerSchema>;

/* Minimal shape for the `authenticate` middleware and the activity slide: who owns the session, and both clocks. */
const SessionAuthSchema = SessionDocumentReadStruct.pick(
   '_id',
   'userId',
   'lastActiveAt',
   'expiresAt',
   'absoluteExpiresAt'
).pipe(validateExpiryOrder);
export type ISessionAuth = Schema.Schema.Type<typeof SessionAuthSchema>;

// ── Validators ─────────────────────────────────────────────────────
export const SessionDocumentCreateValidator = Schema.typeSchema(
   SessionDocumentCreateSchema
);
export const SessionDocumentReadValidator = Schema.typeSchema(
   SessionDocumentReadSchema
);
export const SessionAuthValidator = Schema.typeSchema(SessionAuthSchema);

export const SessionSelfViewArrayValidator = Schema.Array(
   Schema.typeSchema(SessionSelfViewSchema)
);
export const SessionAdminViewArrayValidator = Schema.Array(
   Schema.typeSchema(SessionAdminViewSchema)
);
export const SessionOwnerValidator = Schema.typeSchema(SessionOwnerSchema);
export const SessionOwnerArrayValidator = Schema.Array(SessionOwnerValidator);

// ── HTTP response item types ─────────────────────────────────────────────────────
export type ISessionSelfListItem = ExpandType<
   ISessionSelfView & { readonly isCurrent: boolean }
>;
export type ISessionAdminListItem = ExpandType<
   ISessionAdminView & {
      readonly isCurrent: boolean;
      readonly user: IUserIdNameEmail | null;
   }
>;

export function getSessionCollection(): Collection<ISessionDocument> {
   return DatabaseManager.getInstance()
      .auth.db()
      .collection<ISessionDocument>('sessions');
}

export const sessionIndexes = [
   { key: { tokenHash: 1 }, unique: true },

   // Needed for the "nuclear" option: deleteMany({ userId }), and the per-user cap eviction.
   { key: { userId: 1, _id: -1 } },

   // TTL index on the SLIDING deadline: MongoDB removes a session once it has been idle too long.
   { key: { expiresAt: 1 }, expireAfterSeconds: 0 },
] satisfies readonly TypedIndexDescription<ISessionDocument>[];
