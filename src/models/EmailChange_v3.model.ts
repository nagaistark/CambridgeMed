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
import {
   ServerGeneratedFields,
   validateChronology,
} from '@ssot/serverGeneratedFields.ts';

export const EmailChangeDocumentBase = Schema.Struct({
   confirmTokenHash: sha256HexString,
   cancelTokenHash: sha256HexString,
   userId: objectIdInstance,
   oldEmail: clinicStaffEmail,
   ...InitiateEmailChangeSchema.fields,
   ...ServerGeneratedFields.fields,
});

export const EmailChangeDocumentCreateStruct = Schema.Struct({
   ...EmailChangeDocumentBase.fields,
   expiresAt: fullDateInTheFuture,
   confirmedAt: Schema.Null,
});

export const EmailChangeDocumentReadStruct = Schema.Struct({
   ...EmailChangeDocumentBase.fields,
   expiresAt: Schema.ValidDateFromSelf,
   confirmedAt: Schema.NullOr(fullDateInThePast),
});

export type IEmailChangeDocumentCreate = Schema.Schema.Type<
   typeof EmailChangeDocumentCreateStruct
>;

export type IEmailChangeDocumentRead = Schema.Schema.Type<
   typeof EmailChangeDocumentReadStruct
>;

// ===== Full EmailChange Document Schemas =========================================
export const EmailChangeDocumentCreateSchema =
   EmailChangeDocumentCreateStruct.pipe(validateChronology);

export const EmailChangeDocumentReadSchema =
   EmailChangeDocumentReadStruct.pipe(validateChronology);

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

   /* TTL janitor. */
   { key: { expiresAt: 1 }, expireAfterSeconds: 0 },
] satisfies readonly TypedIndexDescription<IEmailChangeDocumentRead>[];
