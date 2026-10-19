import type { Response } from 'express';
import type { ObjectId } from 'mongodb';
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
import type {
   StrictFindOneAndUpdateOptions,
   StrictMongoFilter,
   StrictUpdate,
} from '@utils/pathFinder_v3.ts';
import { createErrorResponse } from '../errorHandlers.ts';

export type SecondFactorInput =
   | { readonly kind: 'totp'; readonly code: string }
   | { readonly kind: 'recovery'; readonly code: string };

export type SecondFactorOutcome =
   /* remainingRecoveryCodes is null when a TOTP code (not a recovery code) was used. */
   | {
        readonly status: 'verified';
        readonly remainingRecoveryCodes: number | null;
     }
   | { readonly status: 'invalid' }
   | { readonly status: 'locked' }
   | { readonly status: 'no_recovery_codes' };

export type SecondFactorFailure = Exclude<
   SecondFactorOutcome,
   { status: 'verified' }
>;

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
/* Shared by the live check below and by enrollment confirmation, which verifies against the PENDING secret. Fails closed: a "valid" result with no timeStep means replay protection cannot be recorded, so we refuse to proceed. */
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
/* Takes a ticket BEFORE the guess is evaluated. Two atomic steps, each decided by its own filter:
   1. No window yet, or the last one lapsed: open a fresh window; this attempt is #1.
   2. A live window exists: take a ticket only while tickets remain.
   Parallel guesses each take a ticket, so concurrency cannot exceed the budget. `null` in the filter also matches a missing field, so unmigrated documents behave. */
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

async function clearAttempts(userId: ObjectId): Promise<void> {
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

// ── The two factor kinds ─────────────────────────────────────────────────────────
async function checkTotpCode(
   user: IUserSecondFactor,
   code: string
): Promise<SecondFactorOutcome> {
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

   /* Replay protection as a compare-and-swap: of two simultaneous requests presenting the same code, exactly one advances the step. Like a ticket scanned at two gates in the same second, only the first scan counts. */
   const claimed = await getUserCollection().updateOne(
      {
         _id: user._id,
         totpLastUsedStep: { $lt: check.timeStep },
      } satisfies StrictMongoFilter<IUserDocument>,
      {
         $set: { totpLastUsedStep: check.timeStep },
      } satisfies StrictUpdate<IUserDocument>
   );

   return claimed.matchedCount === 1
      ? { status: 'verified', remainingRecoveryCodes: null }
      : { status: 'invalid' };
}

async function checkRecoveryCode(
   user: IUserSecondFactor,
   code: string
): Promise<SecondFactorOutcome> {
   const submittedHash = hashRecoveryCode(code);

   /* `returnDocument: 'after'` matters: the default ('before') would report the count from before the $pull. */
   const consumedRaw = await getUserCollection().findOneAndUpdate(
      {
         _id: user._id,
         totpRecoveryCodes: submittedHash,
      } satisfies StrictMongoFilter<IUserDocument>,
      {
         $pull: { totpRecoveryCodes: submittedHash },
      } satisfies StrictUpdate<IUserDocument>,
      {
         projection: USER_RECOVERY_CODES_PROJECTION,
         returnDocument: 'after',
      } satisfies StrictFindOneAndUpdateOptions<IUserRecoveryCodes>
   );
   if (consumedRaw === null) return { status: 'invalid' };

   const decoded = Schema.decodeUnknownEither(UserRecoveryCodesValidator)(
      consumedRaw
   );
   if (Either.isLeft(decoded)) {
      throw new Error(`Stored recovery codes failed validation.`, {
         cause: decoded.left,
      });
   }

   return {
      status: 'verified',
      remainingRecoveryCodes: decoded.right.totpRecoveryCodes.length,
   };
}

// ── The public entry point ───────────────────────────────────────────────────────
/* Callers must already have established that TOTP is enabled for this user. */
export async function checkSecondFactor(
   user: IUserSecondFactor,
   input: SecondFactorInput
): Promise<SecondFactorOutcome> {
   /* Not a guess, so it costs no ticket. */
   if (input.kind === 'recovery' && user.totpRecoveryCodes.length === 0) {
      return { status: 'no_recovery_codes' };
   }

   if (!(await acquireAttempt(user._id, new Date()))) {
      return { status: 'locked' };
   }

   const outcome =
      input.kind === 'totp'
         ? await checkTotpCode(user, input.code)
         : await checkRecoveryCode(user, input.code);

   if (outcome.status === 'verified') await clearAttempts(user._id);

   return outcome;
}

// ── One place that maps a failed check to an HTTP response ──────────────────────
export function sendSecondFactorFailure(
   res: Response,
   failure: SecondFactorFailure
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
      .status(401)
      .json(createErrorResponse('UNAUTHORIZED', `Invalid code.`, requestId));
}
