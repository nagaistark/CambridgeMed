import { Schema } from 'effect';
import { InitiateEmailChangeSchema } from '@users/User_v3.schemas.ts';
import {
   clinicStaffEmail,
   fullDateInTheFuture,
   fullDateInThePast,
   objectIdInstance,
   sha256HexString,
} from '@utils/effectSchemaReusables.ts';
import { Collection } from 'mongodb';
import { DatabaseManager } from '../mongoDBConnect.ts';
import { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import { ServerGeneratedFields } from '@ssot/serverGeneratedFields.ts';

export const EmailChangeDocumentStruct = Schema.Struct({
   confirmTokenHash: sha256HexString,
   cancelTokenHash: sha256HexString,
   userId: objectIdInstance,
   oldEmail: clinicStaffEmail,

   /* TTL index target. Both tokens expire together at this moment regardless of their individual usage state. */
   expiresAt: fullDateInTheFuture,
   confirmedAt: Schema.NullOr(fullDateInThePast),

   ...InitiateEmailChangeSchema.fields,
   ...ServerGeneratedFields.fields,
});

/* Standalone modular cross-field filters */
export type IEmailChangeDocument = Schema.Schema.Type<
   typeof EmailChangeDocumentStruct
>;

const validateChronology = <
   A extends Pick<IEmailChangeDocument, 'createdAt' | 'updatedAt'>,
   I,
   R,
>(
   schema: Schema.Schema<A, I, R>
) => {
   return schema.pipe(
      Schema.filter(profile => {
         const issues: Array<Schema.FilterIssue> = [];

         if (profile.createdAt > profile.updatedAt) {
            issues.push({
               path: ['updatedAt'],
               message: `updatedAt cannot be chronologically before createdAt.`,
            });
         }

         return issues;
      })
   );
};

/* Full EmailChange Document Schema */
export const EmailChangeDocumentSchema =
   EmailChangeDocumentStruct.pipe(validateChronology);

// ===== Validators against which we validate the documents ========================
export const EmailChangeDocumentValidator = Schema.typeSchema(
   EmailChangeDocumentSchema
);

/* MongoDB Collection Connection */
export function getEmailChangeCollection(): Collection<IEmailChangeDocument> {
   return DatabaseManager.getInstance()
      .auth.db()
      .collection<IEmailChangeDocument>('emailchanges');
}

/* MongoDB "emailchanges" Collection Indexes */
export const emailChangeIndexes = [
   /* Unique indexes on both hashes. Primary lookup keys for their respective controllers. */
   { key: { confirmTokenHash: 1 }, unique: true },
   { key: { cancelTokenHash: 1 }, unique: true },

   /* Needed to enforce the "one pending change per user" rule at the application and database layers. */
   { key: { userId: 1 }, unique: true },

   /* TTL janitor. */
   { key: { expiresAt: 1 }, expireAfterSeconds: 0 },
] satisfies readonly TypedIndexDescription<IEmailChangeDocument>[];
