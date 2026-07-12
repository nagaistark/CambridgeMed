import { auditableResourceTypes, auditActions } from '@ssot/audit_constants.ts';
import { allRoles } from '@ssot/user_roles_constants.ts';
import {
   ipAddress,
   longString,
   stringToObjectId,
} from '@utils/effectSchemaReusables.ts';
import { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import { Schema } from 'effect';
import { Collection } from 'mongodb';
import { DatabaseManager } from 'mongoDBConnect.ts';

export const AuditLogInputSchema = Schema.Struct({
   actorID: stringToObjectId,
   actorRole: Schema.Literal(...allRoles),
   action: Schema.Literal(...auditActions),
   resourceType: Schema.Literal(...auditableResourceTypes),
   resourceIDs: Schema.NonEmptyArray(stringToObjectId).annotations({
      message: () => ({
         message: `The resourceIDs array must contain at least one ID.`,
         override: true,
      }),
   }),
   patientIDs: Schema.NonEmptyArray(stringToObjectId).annotations({
      message: () => ({
         message: `Must include at least one patient ID.`,
         override: true,
      }),
   }),
   searchCriteria: Schema.optional(longString),
   ipAddress: ipAddress,
   requestId: Schema.UUID.annotations({
      message: () =>
         `The provided identifier must be a valid, standard format UUID.`,
   }),
});

export const AuditLogDocumentSchema = Schema.Struct({
   _id: stringToObjectId,
   occurredAt: Schema.ValidDateFromSelf,
}).pipe(Schema.extend(AuditLogInputSchema));

export const AuditLogDocumentValidator = Schema.typeSchema(
   AuditLogDocumentSchema
);

export type IAuditLogDoc = Schema.Schema.Type<typeof AuditLogDocumentSchema>;

export function getAuditLogCollection(): Collection<IAuditLogDoc> {
   return DatabaseManager.getInstance()
      .audit.db()
      .collection<IAuditLogDoc>('auditlogs');
}

export const auditLogIndexes = [
   { key: { patientIDs: 1, occurredAt: -1 } },
   { key: { actorID: 1, occurredAt: -1 } },
] satisfies readonly TypedIndexDescription<IAuditLogDoc>[];
