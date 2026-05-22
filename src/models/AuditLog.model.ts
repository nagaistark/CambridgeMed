import mongoose from 'mongoose';
import { allRoles } from '@ssot/user_roles_constants.ts';
import { auditableResourceTypes, auditActions } from '@ssot/audit_constants.ts';
import {
   objectIdFormatCheck,
   baseString,
} from '@utils/valibotSchemaReusables.ts';
import { makePicklist } from '@utils/arrayToValPicklist.ts';
import { StrictSchemaDefinition_v2 } from '@utils/mongoose_types.ts';
import { DatabaseManager } from 'dbConnect.ts';
import { createModelGetter } from '@utils/createLazyGetter.ts';
import { InferOutput, ip, pipe, strictObject, uuid } from 'valibot';

type StringIDToObjectId<T extends Record<string, unknown>> = {
   [K in keyof T]: K extends `${string}ID` ? mongoose.Types.ObjectId : T[K];
};

// ── Service input contract ───────────────────────────────────────────────────────
export const AuditLogInputSchema = strictObject({
   actorID: objectIdFormatCheck,
   actorRole: makePicklist(allRoles),
   action: makePicklist(auditActions),
   resourceType: makePicklist(auditableResourceTypes),
   resourceID: objectIdFormatCheck,
   patientID: objectIdFormatCheck,

   ipAddress: pipe(baseString, ip(`IP Address is badly formatted (valibot).`)),
   requestId: pipe(
      baseString,
      uuid(`Request ID is not a valid UUID (valibot).`)
   ),
});

export type IAuditLogInput = InferOutput<typeof AuditLogInputSchema>;
export type IAuditLogDefinition = StringIDToObjectId<IAuditLogInput> & {
   occurredAt: Date;
};
export type IAuditLogDocument = IAuditLogDefinition & {
   _id: mongoose.Types.ObjectId;
};

// ── Mongoose schema definition ───────────────────────────────────────────────────
const AuditLogMongooseDefinition = {
   actorID: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
   },
   actorRole: {
      type: String,
      enum: allRoles,
      required: true,
   },
   action: {
      type: String,
      enum: auditActions,
      required: true,
   },
   resourceType: {
      type: String,
      enum: auditableResourceTypes,
      required: true,
   },
   resourceID: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
   },
   patientID: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
   },
   ipAddress: {
      type: String,
      required: true,
   },
   requestId: {
      type: String,
      required: true,
   },
   occurredAt: {
      type: Date,
      required: true,
   },
} satisfies StrictSchemaDefinition_v2<IAuditLogDefinition>;

export const AuditLogMongooseSchema = new mongoose.Schema<IAuditLogDocument>(
   AuditLogMongooseDefinition,
   { strict: 'throw', timestamps: false }
);

AuditLogMongooseSchema.index({ patientId: 1, occurredAt: -1 });
AuditLogMongooseSchema.index({ actorId: 1, occurredAt: -1 });

export const getAuditLogModel = createModelGetter<IAuditLogDocument>(
   () => DatabaseManager.getInstance().audit.connection,
   'AuditLog',
   AuditLogMongooseSchema
);
