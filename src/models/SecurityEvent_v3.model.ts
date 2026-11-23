import { Schema } from 'effect';
import { Collection } from 'mongodb';
import {
   loginFailureReasons,
   secondFactorKinds,
   secondFactorPurposes,
   securityEventSeverities,
   securityEventTypes,
} from '@ssot/security_event_constants.ts';
import {
   baseString,
   ipAddress,
   stringToObjectId,
} from '@utils/effectSchemaReusables.ts';
import { DatabaseManager } from '../mongoDBConnect.ts';

/* An event is a fact about the past: it has `occurredAt` but no `updatedAt`, because nothing ever edits it. `actorId` is null when the actor had no session (mid-login, password-reset link). Never put codes, secrets or hashes in here. */
const SecurityEventStruct = Schema.Struct({
   _id: stringToObjectId,
   occurredAt: Schema.ValidDateFromSelf,
   event: Schema.Literal(...securityEventTypes),
   severity: Schema.Literal(...securityEventSeverities),
   actorId: Schema.NullOr(stringToObjectId),
   targetUserId: Schema.NullOr(stringToObjectId),
   requestId: baseString,
   ipAddress: Schema.NullOr(ipAddress),

   loginFailureReason: Schema.NullOr(Schema.Literal(...loginFailureReasons)),

   /* Populated only by second-factor events (SECOND_FACTOR_FAILED, SECOND_FACTOR_LOCKED, RECOVERY_CODE_USED); null for every other event. */
   secondFactorPurpose: Schema.NullOr(Schema.Literal(...secondFactorPurposes)),
   secondFactorKind: Schema.NullOr(Schema.Literal(...secondFactorKinds)),
});

export type ISecurityEventDocument = Schema.Schema.Type<
   typeof SecurityEventStruct
>;

const validateLoginFields = <
   A extends Pick<
      ISecurityEventDocument,
      'event' | 'targetUserId' | 'loginFailureReason'
   >,
   I,
   R,
>(
   schema: Schema.Schema<A, I, R>
) => {
   return schema.pipe(
      Schema.filter(doc => {
         const issues: Array<Schema.FilterIssue> = [];

         if (
            (doc.event === 'LOGIN_FAILED') !==
            (doc.loginFailureReason !== null)
         ) {
            issues.push({
               path: ['loginFailureReason'],
               message: `loginFailureReason must be set if and only if the event is LOGIN_FAILED.`,
            });
         }

         if (
            (doc.targetUserId === null) !==
            (doc.loginFailureReason === 'unknown_account')
         ) {
            issues.push({
               path: ['targetUserId'],
               message: `targetUserId must be null if and only if the failure reason is unknown_account.`,
            });
         }

         return issues;
      })
   );
};

export const SecurityEventValidator = Schema.typeSchema(
   SecurityEventStruct.pipe(validateLoginFields)
);

/* Lives in the AUDIT database. The DB user the app connects with there should hold "insert" only (no find/update/delete): an attacker who owns the app must not be able to erase their own footprints. */
export function getSecurityEventCollection(): Collection<ISecurityEventDocument> {
   return DatabaseManager.getInstance()
      .audit.db()
      .collection<ISecurityEventDocument>('securityevents');
}
