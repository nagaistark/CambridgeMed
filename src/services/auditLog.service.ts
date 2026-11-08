import { trackBackgroundTask } from '@utils/backgroundTasks.ts';
import logger from '../logger.ts';

import {
   getAuditLogCollection,
   type IAuditLogDoc,
} from '@models/AuditLog_v3.model.ts';
import { ObjectId } from 'mongodb';

function record(input: Omit<IAuditLogDoc, '_id' | 'occurredAt'>): void {
   /* Void return is intentionally synchronous from the caller's perspective. The promise is managed entirely inside this function. */
   const payload: IAuditLogDoc = {
      _id: new ObjectId(),
      occurredAt: new Date(),
      actorID: input.actorID,
      actorRole: input.actorRole,
      action: input.action,
      resourceType: input.resourceType,
      resourceIDs: input.resourceIDs,
      patientIDs: input.patientIDs,
      searchCriteria: input.searchCriteria,
      ipAddress: input.ipAddress,
      requestId: input.requestId,
   };

   async function persist(payload: IAuditLogDoc): Promise<void> {
      try {
         await getAuditLogCollection().insertOne(payload);
      } catch (err: unknown) {
         logger.error(
            `[AuditLog] Write failed — requestId=${payload.requestId} | ${err instanceof Error ? err.message : String(err)}`
         );
      }
   }

   trackBackgroundTask(persist(payload));
}

export const auditLog = { record };
