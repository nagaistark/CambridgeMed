import { Either, Schema } from 'effect';
import { ObjectId } from 'mongodb';
import logger from '../logger.ts';
import { sanitizeError } from '../mongoDBConnect.ts';
import {
   getSecurityEventCollection,
   SecurityEventValidator,
   type ISecurityEventDocument,
} from '@models/SecurityEvent_v3.model.ts';
import {
   SECURITY_EVENT_SEVERITY,
   type SecondFactorKind,
   type SecondFactorPurpose,
   type SecurityEventType,
} from '@ssot/security_event_constants.ts';

export type RequestContext = {
   readonly requestId: string;
   readonly ipAddress: string | null;
};

/* Structural parameter types on purpose: any Request<...> / typed Response variant fits, no casts at call sites. */
export function requestContext(
   req: { readonly ip: string | undefined },
   res: { readonly locals: { readonly requestId: string } }
): RequestContext {
   return { requestId: res.locals.requestId, ipAddress: req.ip ?? null };
}

export type SecurityEventInput = RequestContext & {
   readonly event: SecurityEventType;
   readonly actorId: ObjectId | null;
   readonly targetUserId: ObjectId;
   readonly purpose?: SecondFactorPurpose;
   readonly factorKind?: SecondFactorKind;
};

/* Never rejects: an audit-store outage must not turn a successful action into a failed one. The process-log line written by `record` is the guaranteed trace; this is the durable one. */
async function persist(doc: ISecurityEventDocument): Promise<void> {
   try {
      const decoded = Schema.decodeUnknownEither(SecurityEventValidator)(doc);
      if (Either.isLeft(decoded)) {
         throw new Error(`Security event failed validation.`, {
            cause: decoded.left,
         });
      }
      await getSecurityEventCollection().insertOne(decoded.right);
   } catch (err) {
      logger.error(
         `[SecurityEvent] Persist failed — event=${doc.event} requestId=${doc.requestId} | ${sanitizeError(err).message}`
      );
   }
}

/* Synchronous from the caller's view, like auditLog.record. Safe to call after a commit or after the response is sent. */
function record(input: SecurityEventInput): void {
   const severity = SECURITY_EVENT_SEVERITY[input.event];

   const doc: ISecurityEventDocument = {
      _id: new ObjectId(),
      occurredAt: new Date(),
      event: input.event,
      severity,
      actorId: input.actorId,
      targetUserId: input.targetUserId,
      requestId: input.requestId,
      ipAddress: input.ipAddress,
      purpose: input.purpose ?? null,
      factorKind: input.factorKind ?? null,
   };

   const log = severity === 'warn' ? logger.warn : logger.info;
   log(`[SecurityEvent] ${doc.event}`, {
      requestId: doc.requestId,
      actorId: doc.actorId?.toHexString() ?? null,
      targetUserId: doc.targetUserId.toHexString(),
      purpose: doc.purpose,
      factorKind: doc.factorKind,
   });

   void persist(doc);
}

export const securityLog = { record };
