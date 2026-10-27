import type { Response } from 'express';
import type { ClientSession, ObjectId } from 'mongodb';
import { Either, Schema } from 'effect';
import { verify } from 'otplib';
import {
   getUserCollection,
   UserRecoveryCodesValidator,
   type IUserDocument,
   type IUserRecoveryCodes,
   type IUserSecondFactor,
} from '@models/User_v3.model.ts';
import { decryptTotpSecret, hashRecoveryCode } from '@utils/totpCrypto.ts';
import {
   TOTP_ATTEMPT_WINDOW_MS,
   TOTP_EPOCH_TOLERANCE_SECONDS,
   TOTP_MAX_ATTEMPTS,
} from '@ssot/totp_constants.ts';
import { USER_RECOVERY_CODES_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import type { SecondFactorPurpose } from '@ssot/security_event_constants.ts';
import type {
   StrictFindOneAndUpdateOptions,
   StrictMongoFilter,
   StrictUpdate,
} from '@utils/pathFinder_v3.ts';
import {
   securityLog,
   type RequestContext,
} from '@services/securityLog.service.ts';
import { createErrorResponse } from '../errorHandlers.ts';

// ── Types ────────────────────────────────────────────────────────────────────────
export type SecondFactorInput =
   | { readonly kind: 'totp'; readonly code: string }
   | { readonly kind: 'recovery'; readonly code: string };

/* Who is asking, why, and from where. Feeds the security log only. `actorId` is null when the caller has no session yet (mid-login, reset link). */
export type SecondFactorContext = RequestContext & {
   readonly purpose: SecondFactorPurpose;
   readonly actorId: ObjectId | null;
};

/* Proof that a code was CORRECT, not yet that it was SPENT. Phase 1 produces it, phase 2 spends it. */
export type FactorClaim =
   | {
        readonly kind: 'totp';
        readonly userId: ObjectId;
        readonly timeStep: number;
     }
   | {
        readonly kind: 'recovery';
        readonly userId: ObjectId;
        readonly codeHash: string;
     };

export type SecondFactorVerification =
   | { readonly status: 'verified'; readonly claim: FactorClaim }
   | { readonly status: 'invalid' }
   | { readonly status: 'locked' }
   | { readonly status: 'no_recovery_codes' };

export type SecondFactorFailure = Exclude<
   SecondFactorVerification,
   { status: 'verified' }
>;

export type FactorConsumption =
   /* remainingRecoveryCodes is null when a TOTP code (not a recovery code) was spent. */
   | {
        readonly status: 'consumed';
        readonly remainingRecoveryCodes: number | null;
     }
   /* Replayed or raced: somebody spent this exact code first. */
   | { readonly status: 'rejected' };

export type SecondFactorOutcome =
   | {
        readonly status: 'verified';
        readonly remainingRecoveryCodes: number | null;
     }
   | SecondFactorFailure;

export type TotpCodeCheck =
   | { readonly valid: false }
   | { readonly valid: true; readonly timeStep: number };

/* Request bodies carry two optional fields; this turns them into the discriminated input the service wants. null = neither was supplied. */
export function toSecondFactorInput(body: {
   readonly totpCode?: string | undefined;
   readonly recoveryCode?: string | undefined;
}): SecondFactorInput | null {
   if (body.totpCode !== undefined)
      return { kind: 'totp', code: body.totpCode };
   if (body.recoveryCode !== undefined) {
      return { kind: 'recovery', code: body.recoveryCode };
   }
   return null;
}

// ── Pure code verification (no DB writes) ────────────────────────────────────────
/* Shared by the live check below and by enrollment confirmation (which verifies against the PENDING secret). Fails closed: a "valid" result with no timeStep means replay protection cannot be recorded, so we refuse to proceed. */
export async function verifyTotpCode(input: {
   readonly encryptedSecret: string;
   readonly code: string;
   readonly lastUsedStep: number;
}): Promise<TotpCodeCheck> {
   const result = await verify({
      token: input.code,
      secret: decryptTotpSecret(input.encryptedSecret),
      epochTolerance: TOTP_EPOCH_TOLERANCE_SECONDS,
      afterTimeStep: input.lastUsedStep,
   });

   if (!result.valid) return { valid: false };

   if (!('timeStep' in result)) {
      throw new Error(
         `TOTP verification succeeded but returned no timeStep. Refusing to proceed without replay-protection state.`
      );
   }

   return { valid: true, timeStep: result.timeStep };
}

// ── The attempt gate ─────────────────────────────────────────────────────────────
/* A turnstile that counts people BEFORE they try the lock. Two atomic steps, each decided by its own filter:
   1. No window yet, or the last one lapsed: open a fresh window; this attempt is #1.
   2. A live window exists: take a ticket only while tickets remain.
   Parallel guesses each take a ticket, so concurrency cannot exceed the budget.

   It must stay OUTSIDE any business transaction: if a transaction rolls back, a ticket taken inside it would roll back too, handing the attacker free guesses. */
async function acquireAttempt(userId: ObjectId, now: Date): Promise<boolean> {
   const users = getUserCollection();
   const windowCutoff = new Date(now.getTime() - TOTP_ATTEMPT_WINDOW_MS);

   const opened = await users.updateOne(
      {
         _id: userId,
         $or: [
            { totpAttemptsWindowStartedAt: null },
            { totpAttemptsWindowStartedAt: { $lte: windowCutoff } },
         ],
      } satisfies StrictMongoFilter<IUserDocument>,
      {
         $set: { totpAttempts: 1, totpAttemptsWindowStartedAt: now },
      } satisfies StrictUpdate<IUserDocument>
   );
   if (opened.matchedCount === 1) return true;

   const taken = await users.updateOne(
      {
         _id: userId,
         totpAttemptsWindowStartedAt: { $gt: windowCutoff },
         totpAttempts: { $lt: TOTP_MAX_ATTEMPTS },
      } satisfies StrictMongoFilter<IUserDocument>,
      { $inc: { totpAttempts: 1 } } satisfies StrictUpdate<IUserDocument>
   );
   return taken.matchedCount === 1;
}

/* Call AFTER the business action has committed, never inside its transaction. */
export async function clearSecondFactorAttempts(
   userId: ObjectId
): Promise<void> {
   const cleared = await getUserCollection().updateOne(
      { _id: userId } satisfies StrictMongoFilter<IUserDocument>,
      {
         $set: { totpAttempts: 0, totpAttemptsWindowStartedAt: null },
      } satisfies StrictUpdate<IUserDocument>
   );
   if (cleared.matchedCount === 0) {
      throw new Error(
         `User ${userId.toHexString()} vanished while clearing TOTP attempts.`
      );
   }
}

// ── Security events ──────────────────────────────────────────────────────────────
function recordRejection(
   event: 'SECOND_FACTOR_FAILED' | 'SECOND_FACTOR_LOCKED',
   userId: ObjectId,
   input: SecondFactorInput,
   context: SecondFactorContext
): void {
   securityLog.record({
      event,
      actorId: context.actorId,
      targetUserId: userId,
      requestId: context.requestId,
      ipAddress: context.ipAddress,
      // purpose: context.purpose,
      // factorKind: input.kind,
      secondFactorPurpose: context.purpose,
      secondFactorKind: input.kind,
   });
}

/* Call once the spend has COMMITTED. A recovery code is the break-glass credential: using one is never silent. */
export function recordFactorUsage(
   claim: FactorClaim,
   context: SecondFactorContext
): void {
   if (claim.kind !== 'recovery') return;
   securityLog.record({
      event: 'RECOVERY_CODE_USED',
      actorId: context.actorId,
      targetUserId: claim.userId,
      requestId: context.requestId,
      ipAddress: context.ipAddress,
      secondFactorPurpose: context.purpose,
      secondFactorKind: 'recovery',
   });
}

// ── PHASE 1: verify (spends an attempt ticket, spends NOTHING else) ──────────────
/* Think of a pharmacy: phase 1 is the pharmacist checking your prescription is genuine; phase 2 is stamping it "used". If you stamp before the rest of the transaction is certain to succeed, a failure further along leaves you holding a stamped, useless prescription. So: check first, stamp inside the same transaction as the work it authorises.

Callers must already have established that TOTP is enabled for this user. */
export async function verifySecondFactor(
   user: IUserSecondFactor,
   input: SecondFactorInput,
   context: SecondFactorContext
): Promise<SecondFactorVerification> {
   /* Not a guess, so it costs no ticket. */
   if (input.kind === 'recovery' && user.totpRecoveryCodes.length === 0) {
      return { status: 'no_recovery_codes' };
   }

   if (!(await acquireAttempt(user._id, new Date()))) {
      recordRejection('SECOND_FACTOR_LOCKED', user._id, input, context);
      return { status: 'locked' };
   }

   const verification =
      input.kind === 'totp'
         ? await verifyTotpFactor(user, input.code)
         : verifyRecoveryFactor(user, input.code);

   if (verification.status === 'invalid') {
      recordRejection('SECOND_FACTOR_FAILED', user._id, input, context);
   }
   return verification;
}

async function verifyTotpFactor(
   user: IUserSecondFactor,
   code: string
): Promise<SecondFactorVerification> {
   if (user.totpSecret === null) {
      throw new Error(
         `Account ${user._id.toHexString()} has TOTP enabled but no stored secret.`
      );
   }

   const check = await verifyTotpCode({
      encryptedSecret: user.totpSecret,
      code,
      lastUsedStep: user.totpLastUsedStep,
   });
   if (!check.valid) return { status: 'invalid' };

   return {
      status: 'verified',
      claim: { kind: 'totp', userId: user._id, timeStep: check.timeStep },
   };
}

/* Membership is checked against the already-loaded hashes; the AUTHORITATIVE check is the atomic $pull in phase 2. */
function verifyRecoveryFactor(
   user: IUserSecondFactor,
   code: string
): SecondFactorVerification {
   const codeHash = hashRecoveryCode(code);
   return user.totpRecoveryCodes.includes(codeHash)
      ? {
           status: 'verified',
           claim: { kind: 'recovery', userId: user._id, codeHash },
        }
      : { status: 'invalid' };
}

// ── PHASE 2: consume (the stamp) ─────────────────────────────────────────────────
/* Pass `session` to spend the code inside the caller's transaction: if anything later in that transaction throws, the code is un-spent along with everything else. */
export async function consumeSecondFactor(
   claim: FactorClaim,
   options: { readonly session?: ClientSession } = {}
): Promise<FactorConsumption> {
   const users = getUserCollection();

   if (claim.kind === 'totp') {
      /* Replay protection as a compare-and-swap: of two simultaneous requests presenting the same code, exactly one advances the step. */
      const claimed = await users.updateOne(
         {
            _id: claim.userId,
            totpLastUsedStep: { $lt: claim.timeStep },
         } satisfies StrictMongoFilter<IUserDocument>,
         {
            $set: { totpLastUsedStep: claim.timeStep },
         } satisfies StrictUpdate<IUserDocument>,
         { session: options.session }
      );
      return claimed.matchedCount === 1
         ? { status: 'consumed', remainingRecoveryCodes: null }
         : { status: 'rejected' };
   }

   /* `returnDocument: 'after'` matters: the default ('before') would report the count from before the $pull. */
   const consumedRaw = await users.findOneAndUpdate(
      {
         _id: claim.userId,
         totpRecoveryCodes: claim.codeHash,
      } satisfies StrictMongoFilter<IUserDocument>,
      {
         $pull: { totpRecoveryCodes: claim.codeHash },
      } satisfies StrictUpdate<IUserDocument>,
      {
         projection: USER_RECOVERY_CODES_PROJECTION,
         returnDocument: 'after',
         session: options.session,
      } satisfies StrictFindOneAndUpdateOptions<IUserRecoveryCodes>
   );
   if (consumedRaw === null) return { status: 'rejected' };

   const decoded = Schema.decodeUnknownEither(UserRecoveryCodesValidator)(
      consumedRaw
   );
   if (Either.isLeft(decoded)) {
      throw new Error(`Stored recovery codes failed validation.`, {
         cause: decoded.left,
      });
   }

   return {
      status: 'consumed',
      remainingRecoveryCodes: decoded.right.totpRecoveryCodes.length,
   };
}

// ── Convenience: verify + consume, no surrounding transaction ────────────────────
/* For flows with nothing else to make atomic (login). Flows that DO have a transaction (disable, regenerate, reset, admin reset) use the two phases directly. */
export async function checkSecondFactor(
   user: IUserSecondFactor,
   input: SecondFactorInput,
   context: SecondFactorContext
): Promise<SecondFactorOutcome> {
   const verification = await verifySecondFactor(user, input, context);
   if (verification.status !== 'verified') return verification;

   const consumption = await consumeSecondFactor(verification.claim);
   if (consumption.status === 'rejected') {
      recordRejection('SECOND_FACTOR_FAILED', user._id, input, context);
      return { status: 'invalid' };
   }

   await clearSecondFactorAttempts(user._id);
   recordFactorUsage(verification.claim, context);

   return {
      status: 'verified',
      remainingRecoveryCodes: consumption.remainingRecoveryCodes,
   };
}

// ── One place that maps a failed check to an HTTP response ──────────────────────
/* The status of a WRONG CODE depends on whether the caller has a session:
   • 401 — pre-session routes (login, reset link). There is no session to protect.
   • 403 — routes behind `authenticate`. The session is fine; the extra credential is wrong. A 401 here would make a naive client interceptor try to refresh a perfectly good session.
   The machine-readable `code` is INVALID_CREDENTIALS in both cases. */
export type SecondFactorInvalidStatus = 401 | 403;

export function sendSecondFactorFailure(
   res: Response,
   failure: SecondFactorFailure,
   invalidStatus: SecondFactorInvalidStatus
): void {
   const requestId = res.locals.requestId;

   if (failure.status === 'locked') {
      return void res
         .status(429)
         .json(
            createErrorResponse(
               'RATE_LIMITED',
               `Too many attempts. Please try again later.`,
               requestId
            )
         );
   }

   if (failure.status === 'no_recovery_codes') {
      return void res
         .status(409)
         .json(
            createErrorResponse(
               'CONFLICT',
               `No recovery codes remain. Please contact an administrator.`,
               requestId
            )
         );
   }

   return void res
      .status(invalidStatus)
      .json(
         createErrorResponse('INVALID_CREDENTIALS', `Invalid code.`, requestId)
      );
}
