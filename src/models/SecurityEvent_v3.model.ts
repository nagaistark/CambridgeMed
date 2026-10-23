import { Schema } from 'effect';
import { Collection } from 'mongodb';
import {
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
import type { TypedIndexDescription } from '@utils/typedIndexDescription.ts';
import { DatabaseManager } from '../mongoDBConnect.ts';

/* An event is a fact about the past: it has `occurredAt` but no `updatedAt`, because nothing ever edits it. `actorId` is null when the actor had no session (mid-login, password-reset link). Never put codes, secrets or hashes in here. */
const SecurityEventStruct = Schema.Struct({
   _id: stringToObjectId,
   occurredAt: Schema.ValidDateFromSelf,
   event: Schema.Literal(...securityEventTypes),
   severity: Schema.Literal(...securityEventSeverities),
   actorId: Schema.NullOr(stringToObjectId),
   targetUserId: stringToObjectId,
   requestId: baseString,
   ipAddress: Schema.NullOr(ipAddress),
   purpose: Schema.NullOr(Schema.Literal(...secondFactorPurposes)),
   factorKind: Schema.NullOr(Schema.Literal(...secondFactorKinds)),
});

export type ISecurityEventDocument = Schema.Schema.Type<
   typeof SecurityEventStruct
>;

export const SecurityEventValidator = Schema.typeSchema(SecurityEventStruct);

/* Lives in the AUDIT database. The DB user the app connects with there should hold insert + find only (no update/delete): an attacker who owns the app must not be able to erase their own footprints. */
export function getSecurityEventCollection(): Collection<ISecurityEventDocument> {
   return DatabaseManager.getInstance()
      .audit.db()
      .collection<ISecurityEventDocument>('securityevents');
}

/* Deliberately NO TTL index: retention is a compliance decision, not a default. */
export const securityEventIndexes = [
   { key: { targetUserId: 1, occurredAt: -1 } },
   { key: { event: 1, occurredAt: -1 } },
] satisfies readonly TypedIndexDescription<ISecurityEventDocument>[];
