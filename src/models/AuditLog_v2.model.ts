import { auditableResourceTypes, auditActions } from '@ssot/audit_constants.ts';
import { allRoles } from '@ssot/user_roles_constants.ts';
import { makePicklist } from '@utils/arrayToValPicklist.ts';
import { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import {
   baseString,
   longString,
   objectIdFromString,
   objectIdInstance,
} from '@utils/valibotSchemaReusables.ts';
import { Collection } from 'mongodb';
import { DatabaseManager } from 'mongoDBConnect.ts';
import {
   array,
   date,
   InferOutput,
   ip,
   minLength,
   optional,
   pipe,
   strictObject,
   uuid,
} from 'valibot';

export const AuditLogInputVSchema = strictObject({
   actorID: objectIdFromString,
   actorRole: makePicklist(allRoles),
   action: makePicklist(auditActions),
   resourceType: makePicklist(auditableResourceTypes),
   resourceIDs: pipe(
      array(objectIdFromString),
      minLength(1, `Must include at least one resource ID.`)
   ),
   patientIDs: pipe(
      array(objectIdFromString),
      minLength(1, `Must include at least one patient ID.`)
   ),

   searchCriteria: optional(longString), // To capture req.query if applicable

   ipAddress: pipe(baseString, ip(`IP Address is badly formatted (valibot).`)),
   requestId: pipe(
      baseString,
      uuid(`Request ID is not a valid UUID (valibot).`)
   ),
});

export const AuditLogDocumentVSchema = strictObject({
   ...AuditLogInputVSchema.entries,
   _id: objectIdInstance,
   occurredAt: date(`occurredAt must be a valid JS Date object.`),
});

type IAuditLogDocument = InferOutput<typeof AuditLogDocumentVSchema>;

export function getAuditLogCollection(): Collection<IAuditLogDocument> {
   return DatabaseManager.getInstance()
      .audit.db()
      .collection<IAuditLogDocument>('auditLogs');
}

export const auditLogIndexes = [
   { key: { patientIDs: 1, occurredAt: -1 } },
   { key: { actorID: 1, occurredAt: -1 } },
] satisfies readonly TypedIndexDescription<IAuditLogDocument>[];
