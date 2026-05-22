import mongoose from 'mongoose';
import logger from 'logger.ts';

import {
   getAuditLogModel,
   type IAuditLogInput,
} from '@models/AuditLog.model.ts';

function record(input: IAuditLogInput): void {
   /* Void return is intentionally synchronous from the caller's perspective. The promise is managed entirely inside this function. */
   getAuditLogModel()
      .create({
         actorID: new mongoose.Types.ObjectId(input.actorID),
         actorRole: input.actorRole,
         action: input.action,
         resourceType: input.resourceType,
         resourceID: new mongoose.Types.ObjectId(input.resourceID),
         patientID: new mongoose.Types.ObjectId(input.patientID),
         ipAddress: input.ipAddress,
         requestId: input.requestId,
         occurredAt: new Date(),
      })
      .catch((err: unknown) => {
         /* requestId is already in the input, so we can log it precisely without needing any external reference. */
         logger.error(
            `[AuditLog] Write failed — requestId=${input.requestId} | ` +
               `${err instanceof Error ? err.message : String(err)}`
         );
      });
}

export const auditLog = { record };
