import { auditableResourceTypes, auditActions } from '@ssot/audit_constants.ts';
import { allRoles } from '@ssot/user_roles_constants.ts';
import {
   ipAddress,
   longString,
   objectIdInstance,
} from '@utils/effectSchemaReusables.ts';
import { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import { Schema } from 'effect';
import { Collection } from 'mongodb';
import { DatabaseManager } from '../mongoDBConnect.ts';

export const AuditLogDocumentSchema = Schema.Struct({
   _id: objectIdInstance,
   occurredAt: Schema.ValidDateFromSelf,
   actorID: objectIdInstance,
   actorRole: Schema.Literal(...allRoles),
   action: Schema.Literal(...auditActions),
   resourceType: Schema.Literal(...auditableResourceTypes),
   resourceIDs: Schema.NonEmptyArray(objectIdInstance).annotations({
      message: () => ({
         message: `The resourceIDs array must contain at least one ID.`,
         override: true,
      }),
   }),
   patientIDs: Schema.NonEmptyArray(objectIdInstance).annotations({
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
