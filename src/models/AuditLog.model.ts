import mongoose from 'mongoose';
import { allRoles } from '@ssot/user_roles_constants.ts';
import { auditableResourceTypes, auditActions } from '@ssot/audit_constants.ts';
import {
   objectIdFormatCheck,
   baseString,
   longString,
} from '@utils/valibotSchemaReusables.ts';
import { makePicklist } from '@utils/arrayToValPicklist.ts';
import { StrictSchemaDefinition_v5 } from '@utils/mongoose_types.ts';
import { DatabaseManager } from 'dbConnect.ts';
import { createModelGetter } from '@utils/createLazyGetter.ts';
import {
   array,
   InferOutput,
   ip,
   minLength,
   optional,
   pipe,
   strictObject,
   uuid,
} from 'valibot';

type StringIDToObjectId<T extends Record<string, unknown>> = {
   [K in keyof T]: K extends `${string}IDs`
      ? mongoose.Types.ObjectId[] // plural suffix → array of ObjectIds
      : K extends `${string}ID`
        ? mongoose.Types.ObjectId // singular suffix → single ObjectId
        : T[K];
};

// ── Service input contract ───────────────────────────────────────────────────────
export const AuditLogInputSchema = strictObject({
   actorID: objectIdFormatCheck,
   actorRole: makePicklist(allRoles),
   action: makePicklist(auditActions),
   resourceType: makePicklist(auditableResourceTypes),
   resourceIDs: pipe(
      array(objectIdFormatCheck),
      minLength(1, `Must include at least one resource ID.`)
   ),
   patientIDs: pipe(
      array(objectIdFormatCheck),
      minLength(1, `Must include at least one patient ID.`)
   ),

   searchCriteria: optional(longString), // To capture req.query if applicable

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
   resourceIDs: {
      type: [mongoose.Schema.Types.ObjectId],
      required: true,
   },
   patientIDs: {
      type: [mongoose.Schema.Types.ObjectId],
      required: true,
   },
   searchCriteria: {
      type: String,
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
} satisfies StrictSchemaDefinition_v5<IAuditLogDefinition>;

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
