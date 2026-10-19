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
import { UserDocumentStruct } from './User_v3.model.ts';

/* Struct = shared fields + server-generated fields. Create and Read differ only in `expiresAt`: a document being created must expire in the future, but a document read back from the database may legitimately be past its expiry (the TTL janitor lags by up to a minute). Same split as Invite and EmailChange. */
const PasswordResetDocumentBase = Schema.Struct({
   tokenHash: sha256HexString,
   userId: stringToObjectId,

   /* The address this link was mailed to. Redemption requires the user's CURRENT email to still equal this value, so a token can never outlive an email change (confirm OR revert): a link mailed to an attacker's address is dead the moment the account stops using that address. Same atom as User.email, so the validation rules cannot drift. */
   ...UserDocumentStruct.pick('email').fields,
   ...ServerGeneratedFields.fields,
});

const PasswordResetDocumentCreateStruct = Schema.Struct({
   ...PasswordResetDocumentBase.fields,
   expiresAt: fullDateInTheFuture,
});

const PasswordResetDocumentReadStruct = Schema.Struct({
   ...PasswordResetDocumentBase.fields,
   expiresAt: Schema.ValidDateFromSelf,
});

export type IPasswordResetDocumentCreate = Schema.Schema.Type<
   typeof PasswordResetDocumentCreateStruct
>;

export type IPasswordResetDocumentRead = Schema.Schema.Type<
   typeof PasswordResetDocumentReadStruct
>;

// ===== Standalone modular cross-field filter =====================================
const validateResetTimeline = <
   A extends Pick<IPasswordResetDocumentRead, 'createdAt' | 'expiresAt'>,
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

// ===== Full document schemas =====================================================
const PasswordResetDocumentCreateSchema =
   PasswordResetDocumentCreateStruct.pipe(
      validateChronology,
      validateResetTimeline
   );

const PasswordResetDocumentReadSchema = PasswordResetDocumentReadStruct.pipe(
   validateChronology,
   validateResetTimeline
);

/* Minimal shape for the pre-flight in resetPasswordController. */
const PasswordResetRedeemCheckSchema = PasswordResetDocumentReadStruct.pick(
   '_id',
   'userId'
);
export type IPasswordResetRedeemCheck = Schema.Schema.Type<
   typeof PasswordResetRedeemCheckSchema
>;

// ===== Validators against which we validate the documents ========================
export const PasswordResetDocumentCreateValidator = Schema.typeSchema(
   PasswordResetDocumentCreateSchema
);

export const PasswordResetDocumentReadValidator = Schema.typeSchema(
   PasswordResetDocumentReadSchema
);

export const PasswordResetRedeemCheckValidator = Schema.typeSchema(
   PasswordResetRedeemCheckSchema
);

// ===== MongoDB Collection Connection =============================================
export function getPasswordResetCollection(): Collection<IPasswordResetDocumentRead> {
   return DatabaseManager.getInstance()
      .auth.db()
      .collection<IPasswordResetDocumentRead>('passwordresets');
}

// ===== MongoDB "passwordresets" Collection Indexes ===============================
export const passwordResetIndexes = [
   /* Primary lookup key. Every redemption request hashes the raw token and queries this field. */
   { key: { tokenHash: 1 }, unique: true },

   /* One active reset per user. forgotPasswordController relies on this index as its atomic arbiter: the cooldown upsert's filter deliberately fails to match a document younger than the cooldown, the upsert then tries to INSERT, and this unique index rejects the insert (duplicate key on `userId`). Do not drop it. */
   { key: { userId: 1 }, unique: true },

   /* TTL janitor. */
   { key: { expiresAt: 1 }, expireAfterSeconds: 0 },
] satisfies readonly TypedIndexDescription<IPasswordResetDocumentRead>[];
