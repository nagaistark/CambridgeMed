import { auditableResourceTypes, auditActions } from '@ssot/audit_constants.ts';
import { allRoles } from '@ssot/user_roles_constants.ts';
import { makePicklist } from '@utils/arrayToValPicklist.ts';
import { ExtractKeysMatching } from '@utils/helperTypes.ts';
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
   GenericSchema,
   InferInput,
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

type IAuditLogInput = InferInput<typeof AuditLogInputVSchema>;
type IAuditLogInputIDKeys = ExtractKeysMatching<
   IAuditLogInput,
   `${string}IDs` | `${string}ID`
>;

const nativeIdFields = {
   actorID: objectIdInstance,
   resourceIDs: pipe(
      array(objectIdInstance),
      minLength(1, `Must include at least one resource ID.`)
   ),
   patientIDs: pipe(
      array(objectIdInstance),
      minLength(1, `Must include at least one patient ID.`)
   ),
} satisfies Record<IAuditLogInputIDKeys, GenericSchema>;

export const AuditLogDocumentVSchema = strictObject({
   ...AuditLogInputVSchema.entries,
   ...nativeIdFields, // overriding the plain string-formatted IDs from the InputVSchema with actual ObjectId's.
   _id: objectIdInstance,
   occurredAt: date(`occurredAt must be a valid JS Date object.`),
});

type IAuditLogDocument = InferOutput<typeof AuditLogDocumentVSchema>;

export function getAuditLogCollection(): Collection<IAuditLogDocument> {
   return DatabaseManager.getInstance()
      .audit.db()
      .collection<IAuditLogDocument>('auditlogs');
}

export const auditLogIndexes = [
   { key: { patientIDs: 1, occurredAt: -1 } },
   { key: { actorID: 1, occurredAt: -1 } },
] satisfies readonly TypedIndexDescription<IAuditLogDocument>[];
