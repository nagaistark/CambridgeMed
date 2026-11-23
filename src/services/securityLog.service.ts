import { Either, Schema } from 'effect';
import { ObjectId } from 'mongodb';
import logger from '../logger.ts';
import { sanitizeError } from '@utils/sanitizeError.ts';
import {
   getSecurityEventCollection,
   SecurityEventValidator,
   type ISecurityEventDocument,
} from '@models/SecurityEvent_v3.model.ts';
import {
   SECURITY_EVENT_SEVERITY,
   type LoginFailureReason,
   type SecondFactorKind,
   type SecondFactorPurpose,
   type SecurityEventType,
} from '@ssot/security_event_constants.ts';
import { ipOrNull } from '@utils/effectSchemaReusables.ts';
import { trackBackgroundTask } from '@utils/backgroundTasks.ts';

export type RequestContext = {
   readonly requestId: string;
   readonly ipAddress: string | null;
};

/* Structural parameter types on purpose: any Request<...> / typed Response variant fits, no casts at call sites. */
export function requestContext(
   req: { readonly ip: string | undefined },
   res: { readonly locals: { readonly requestId: string } }
): RequestContext {
   return { requestId: res.locals.requestId, ipAddress: ipOrNull(req.ip) };
}

export type SecurityEventInput = RequestContext & {
   readonly event: Exclude<SecurityEventType, 'LOGIN_FAILED'>; // LOGIN_FAILED has its own entry point: it is the only event that may lack a target.
   readonly actorId: ObjectId | null;
   readonly targetUserId: ObjectId;
   readonly secondFactorPurpose?: SecondFactorPurpose;
   readonly secondFactorKind?: SecondFactorKind;
};

type EmitInput = RequestContext & {
   readonly event: SecurityEventType;
   readonly actorId: ObjectId | null;
   readonly targetUserId: ObjectId | null;
   readonly loginFailureReason: LoginFailureReason | null;
   readonly secondFactorPurpose?: SecondFactorPurpose;
   readonly secondFactorKind?: SecondFactorKind;
};

function emit(input: EmitInput): void {
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
      loginFailureReason: input.loginFailureReason,
      secondFactorPurpose: input.secondFactorPurpose ?? null,
      secondFactorKind: input.secondFactorKind ?? null,
   };

   const log = severity === 'warn' ? logger.warn : logger.info;
   log(`[SecurityEvent] ${doc.event}`, {
      requestId: doc.requestId,
      actorId: doc.actorId?.toHexString() ?? null,
      targetUserId: doc.targetUserId?.toHexString() ?? null,
      loginFailureReason: doc.loginFailureReason,
      secondFactorPurpose: doc.secondFactorPurpose,
      secondFactorKind: doc.secondFactorKind,
   });

   trackBackgroundTask(persist(doc));
}

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

function record(input: SecurityEventInput): void {
   emit({ ...input, loginFailureReason: null });
}

/* `targetUserId` is null exactly when no account matched. The submitted email is deliberately NOT accepted here: it can contain a pasted password. */
function recordLoginFailure(
   input: RequestContext & {
      readonly targetUserId: ObjectId | null;
      readonly reason: LoginFailureReason;
   }
): void {
   emit({
      event: 'LOGIN_FAILED',
      actorId: null,
      targetUserId: input.targetUserId,
      loginFailureReason: input.reason,
      requestId: input.requestId,
      ipAddress: input.ipAddress,
   });
}

export const securityLog = { record, recordLoginFailure };
