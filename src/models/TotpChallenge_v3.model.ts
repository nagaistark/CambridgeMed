import {
   ServerGeneratedFields,
   validateChronology,
} from '@ssot/serverGeneratedFields.ts';
import {
   fullDateInTheFuture,
   sha256HexString,
   stringToObjectId,
} from '@utils/effectSchemaReusables.ts';
import type { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import { Schema } from 'effect';
import { Collection } from 'mongodb';
import { DatabaseManager } from '../mongoDBConnect.ts';

/* A TOTP challenge is the "you're halfway there" ticket: the password has been proven, the second factor has not. One document per user (the slot holds that user's CURRENT challenge; a new password login replaces it). Create and Read differ only in `expiresAt`: a challenge being created must expire in the future, but one read back may legitimately be past its expiry (the TTL janitor lags by up to a minute). Same split as PasswordReset, Invite and Session. */
const TotpChallengeDocumentBase = Schema.Struct({
   /* SHA-256 digest of the opaque token in the browser's cookie. The raw token is never stored. */
   tokenHash: sha256HexString,
   userId: stringToObjectId,
   ...ServerGeneratedFields.fields,
});

const TotpChallengeCreateStruct = Schema.Struct({
   ...TotpChallengeDocumentBase.fields,
   expiresAt: fullDateInTheFuture,
});

const TotpChallengeReadStruct = Schema.Struct({
   ...TotpChallengeDocumentBase.fields,
   expiresAt: Schema.ValidDateFromSelf,
});

export type ITotpChallengeDocument = Schema.Schema.Type<
   typeof TotpChallengeReadStruct
>;

// ===== Standalone modular cross-field filter =====================================
const validateChallengeTimeline = <
   A extends Pick<ITotpChallengeDocument, 'createdAt' | 'expiresAt'>,
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

         return issues;
      })
   );
};

const TotpChallengeCreateSchema = TotpChallengeCreateStruct.pipe(
   validateChronology,
   validateChallengeTimeline
);

/* Minimal shape for `authenticateTotp` and `completeTotpLogin`: which challenge this is, and whose. */
const TotpChallengeAuthSchema = TotpChallengeReadStruct.pick('_id', 'userId');
export type ITotpChallengeAuth = Schema.Schema.Type<
   typeof TotpChallengeAuthSchema
>;

// ===== Validators against which we validate the documents ========================
export const TotpChallengeCreateValidator = Schema.typeSchema(
   TotpChallengeCreateSchema
);
export const TotpChallengeAuthValidator = Schema.typeSchema(
   TotpChallengeAuthSchema
);

// ===== MongoDB Collection Connection =============================================
export function getTotpChallengeCollection(): Collection<ITotpChallengeDocument> {
   return DatabaseManager.getInstance()
      .auth.db()
      .collection<ITotpChallengeDocument>('totpchallenges');
}

// ===== MongoDB "totpchallenges" Collection Indexes ===============================
export const totpChallengeIndexes = [
   /* Primary lookup key. Every verify/recover request hashes the cookie value and queries this field. */
   { key: { tokenHash: 1 }, unique: true },

   /* One challenge per user. issueTotpChallenge relies on this index as its atomic arbiter for the upsert race. Do not drop it. */
   { key: { userId: 1 }, unique: true },

   /* TTL janitor. */
   { key: { expiresAt: 1 }, expireAfterSeconds: 0 },
] satisfies readonly TypedIndexDescription<ITotpChallengeDocument>[];
