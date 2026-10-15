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
import type { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import {
   ServerGeneratedFields,
   validateChronology,
} from '@ssot/serverGeneratedFields.ts';

export const EmailChangeDocumentBase = Schema.Struct({
   confirmTokenHash: sha256HexString,
   cancelTokenHash: sha256HexString,
   userId: objectIdInstance,
   oldEmail: clinicStaffEmail,
   ...InitiateEmailChangeSchema.pick('newEmail').fields,
   ...ServerGeneratedFields.fields,
});

export const EmailChangeDocumentCreateStruct = Schema.Struct({
   ...EmailChangeDocumentBase.fields,
   confirmExpiresAt: fullDateInTheFuture,
   cancelExpiresAt: fullDateInTheFuture,
   confirmedAt: Schema.Null,
});

export const EmailChangeDocumentReadStruct = Schema.Struct({
   ...EmailChangeDocumentBase.fields,
   confirmExpiresAt: Schema.ValidDateFromSelf,
   cancelExpiresAt: Schema.ValidDateFromSelf,
   confirmedAt: Schema.NullOr(fullDateInThePast),
});

export type IEmailChangeDocumentCreate = Schema.Schema.Type<
   typeof EmailChangeDocumentCreateStruct
>;

export type IEmailChangeDocumentRead = Schema.Schema.Type<
   typeof EmailChangeDocumentReadStruct
>;

// ===== Standalone modular cross-field invariant ==================================
const validateExpiryOrder = <
   A extends Pick<
      IEmailChangeDocumentRead,
      'confirmExpiresAt' | 'cancelExpiresAt'
   >,
   I,
   R,
>(
   schema: Schema.Schema<A, I, R>
) => {
   return schema.pipe(
      Schema.filter(doc => {
         const issues: Array<Schema.FilterIssue> = [];
         if (doc.cancelExpiresAt.getTime() < doc.confirmExpiresAt.getTime()) {
            issues.push({
               path: ['cancelExpiresAt'],
               message: `cancelExpiresAt cannot be before confirmExpiresAt.`,
            });
         }
         return issues;
      })
   );
};

const validateConfirmationTimeliness = <
   A extends Pick<IEmailChangeDocumentRead, 'confirmExpiresAt' | 'confirmedAt'>,
   I,
   R,
>(
   schema: Schema.Schema<A, I, R>
) => {
   return schema.pipe(
      Schema.filter(doc => {
         const issues: Array<Schema.FilterIssue> = [];
         if (
            doc.confirmedAt !== null &&
            doc.confirmedAt.getTime() > doc.confirmExpiresAt.getTime()
         ) {
            issues.push({
               path: ['confirmedAt'],
               message: `confirmedAt cannot be chronologically after confirmExpiresAt.`,
            });
         }
         return issues;
      })
   );
};

// ===== Full EmailChange Document Schemas =========================================
export const EmailChangeDocumentCreateSchema =
   EmailChangeDocumentCreateStruct.pipe(
      validateChronology,
      validateExpiryOrder
   );

export const EmailChangeDocumentReadSchema = EmailChangeDocumentReadStruct.pipe(
   validateChronology,
   validateExpiryOrder,
   validateConfirmationTimeliness
);

// ===== Validators against which we validate the documents ========================
export const EmailChangeDocumentCreateValidator = Schema.typeSchema(
   EmailChangeDocumentCreateSchema
);

export const EmailChangeDocumentReadValidator = Schema.typeSchema(
   EmailChangeDocumentReadSchema
);

// ===== MongoDB Collection Connection =============================================
export function getEmailChangeCollection(): Collection<IEmailChangeDocumentRead> {
   return DatabaseManager.getInstance()
      .auth.db()
      .collection<IEmailChangeDocumentRead>('emailchanges');
}
// ===== MongoDB "emailchanges" Collection Indexes =================================
export const emailChangeIndexes = [
   /* Unique indexes on both hashes. Primary lookup keys for their respective controllers. */
   { key: { confirmTokenHash: 1 }, unique: true },
   { key: { cancelTokenHash: 1 }, unique: true },

   /* Needed to enforce the "one pending change per user" rule at the application and database layers. */
   { key: { userId: 1 }, unique: true },
   {
      key: { newEmail: 1 },
      unique: true,
      partialFilterExpression: { confirmedAt: null },
   },

   /* TTL janitor. */
   { key: { cancelExpiresAt: 1 }, expireAfterSeconds: 0 },
] satisfies readonly TypedIndexDescription<IEmailChangeDocumentRead>[];
