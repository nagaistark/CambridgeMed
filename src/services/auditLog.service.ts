import mongoose from 'mongoose';

import {
   getAuditLogModel,
   type IAuditLogInput,
} from '@models/AuditLog.model.ts';

async function record(input: IAuditLogInput): Promise<void> {
   const AuditLog = getAuditLogModel();

   await AuditLog.create({
      actorID: new mongoose.Types.ObjectId(input.actorID),
      actorRole: input.actorRole,
      action: input.action,
      resourceType: input.resourceType,
      resourceID: new mongoose.Types.ObjectId(input.resourceID),
      patientID: new mongoose.Types.ObjectId(input.patientID),
      ipAddress: input.ipAddress,
      requestId: input.requestId,
      occurredAt: new Date(),
   });
}

export const auditLog = { record };
