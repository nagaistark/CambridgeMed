import type { Request } from 'express';
import {
   getUserCollection,
   UserPasswordResetTargetValidator,
   type IUserDocument,
   type IUserPasswordResetTarget,
} from '@models/User_v3.model.ts';
import {
   getPasswordResetCollection,
   PasswordResetDocumentCreateValidator,
   type IPasswordResetDocumentCreate,
   type IPasswordResetDocumentRead,
} from '@models/PasswordReset_v3.model.ts';
import {
   generateRandomToken,
   generateStandardHash,
} from '@ssot/node_crypto_constants.ts';
import { USER_PASSWORD_RESET_TARGET_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import {
   PASSWORD_RESET_COOLDOWN_MS,
   PASSWORD_RESET_TOKEN_EXPIRY_MS,
} from '@ssot/password_reset_constants.ts';
import { sendPasswordResetEmail } from '@auth/passwordReset.email.ts';
import type { ResponseWithValidatedBody } from '@utils/customTypedResponses.ts';
import type { ForgotPasswordBody } from '@auth/forgotPassword.schema.ts';
import { myEnv } from '../validateConfig.ts';
import type {
   StrictFindOneOptions,
   StrictMongoFilter,
   StrictUpdate,
} from '@utils/pathFinder_v3.ts';
import { isDuplicateKeyOnField } from '@utils/mongoErrors.ts';
import logger from '../logger.ts';
import { sanitizeError } from '../mongoDBConnect.ts';
import { Either, Schema } from 'effect';
import { ObjectId } from 'mongodb';

/* The one and only body this endpoint ever sends. Defined once so no code path can drift from it. */
const GENERIC_RESPONSE_MESSAGE =
   `If an account with that email address exists, a reset link has been sent.` as const;

// ── The deferred work ────────────────────────────────────────────────────────────
/* Everything whose duration or outcome depends on whether the account exists lives in here, and runs only AFTER the response has been sent. If this work ran before the response, an attacker could tell "exists" from "doesn't" by timing alone (a missing user returns instantly; a real one costs an upsert plus an outbound email), and a failed email send would turn into a 500 that only existing accounts can trigger. The invariant response is only invariant if its latency is invariant too. */
async function issuePasswordReset(
   email: IUserDocument['email'],
   requestId: string
): Promise<void> {
   // ── Lookup: active accounts only, minimal projection, validated ────────────────
   const userRaw = await getUserCollection().findOne<IUserPasswordResetTarget>(
      { email, isActive: true } satisfies StrictMongoFilter<IUserDocument>,
      {
         projection: USER_PASSWORD_RESET_TARGET_PROJECTION,
      } satisfies StrictFindOneOptions<IUserPasswordResetTarget>
   );

   if (userRaw === null) return;

   const decodedUser = Schema.decodeUnknownEither(
      UserPasswordResetTargetValidator
   )(userRaw);
   if (Either.isLeft(decodedUser)) {
      throw decodedUser.left;
   }
   const validatedUser = decodedUser.right;

   // ── Build and validate the would-be document ───────────────────────────────────
   /* One `now` for every timestamp, so createdAt, updatedAt and expiresAt are consistent by construction. The `email` stored here is what binds the token to this address. */
   const rawToken = generateRandomToken();
   const tokenHash = generateStandardHash(rawToken);
   const now = new Date();
   const expiresAt = new Date(now.getTime() + PASSWORD_RESET_TOKEN_EXPIRY_MS);

   const candidate: IPasswordResetDocumentCreate = {
      _id: new ObjectId(),
      userId: validatedUser._id,
      tokenHash,
      email: validatedUser.email,
      expiresAt,
      createdAt: now,
      updatedAt: now,
   };

   const decodedCandidate = Schema.decodeUnknownEither(
      PasswordResetDocumentCreateValidator
   )(candidate);
   if (Either.isLeft(decodedCandidate)) {
      throw decodedCandidate.left;
   }
   const validatedCandidate = decodedCandidate.right;

   // ── Atomic "replace, but not too often" ────────────────────────────────────────
   /* The filter only matches an existing document that is OLDER than the cooldown. Three cases, all decided inside MongoDB with no read-then-write gap:
      1. No document for this user    → upsert inserts one.
      2. Document older than cooldown → it is replaced (old link dies, new link lives).
      3. Document younger than cooldown → the filter misses, the upsert tries to insert, and the unique `userId` index rejects it with a duplicate-key error. We treat that as "a link was sent very recently" and do nothing.
   Case 3 is what stops an attacker from inbox-bombing a victim, or from endlessly invalidating the victim's live link, even when rotating IP addresses (the IP-based rate limiter cannot see that). A concurrent identical request lands in case 3 as well, so exactly one email goes out. */
   const cooldownCutoff = new Date(now.getTime() - PASSWORD_RESET_COOLDOWN_MS);

   try {
      const upsertResult = await getPasswordResetCollection().updateOne(
         {
            userId: validatedCandidate.userId,
            updatedAt: { $lte: cooldownCutoff },
         } satisfies StrictMongoFilter<IPasswordResetDocumentRead>,
         {
            $set: {
               tokenHash: validatedCandidate.tokenHash,
               email: validatedCandidate.email,
               expiresAt: validatedCandidate.expiresAt,
               updatedAt: validatedCandidate.updatedAt,
            },
            /* `userId` is NOT repeated here: on insert it is seeded from the equality clause of the filter. */
            $setOnInsert: {
               _id: validatedCandidate._id,
               createdAt: validatedCandidate.createdAt,
            },
         } satisfies StrictUpdate<IPasswordResetDocumentRead>,
         { upsert: true }
      );

      if (upsertResult.matchedCount === 0 && upsertResult.upsertedCount === 0) {
         throw new Error(
            `Password reset document was neither created nor replaced for userId: ${validatedUser._id.toHexString()}`
         );
      }
   } catch (upsertErr) {
      if (isDuplicateKeyOnField(upsertErr, 'userId')) {
         logger.debug(
            `Password reset skipped (cooldown or concurrent request). requestId=${requestId}`
         );
         return;
      }
      throw upsertErr;
   }

   // ── Email delivery with rollback ───────────────────────────────────────────────
   /* A reset document whose email never left the building is dead weight that also blocks the next request for the cooldown. The rollback is scoped to OUR token hash, so it can never delete a newer document written by a concurrent request. */
   const resetUrl = `${myEnv.appBaseUrl}/reset-password/${rawToken}`;

   try {
      await sendPasswordResetEmail({
         firstName: validatedUser.firstName,
         email: validatedUser.email,
         resetUrl,
         expiresAt: validatedCandidate.expiresAt,
      });
   } catch (emailErr) {
      try {
         await getPasswordResetCollection().deleteOne({
            userId: validatedCandidate.userId,
            tokenHash: validatedCandidate.tokenHash,
         } satisfies StrictMongoFilter<IPasswordResetDocumentRead>);
      } catch (rollbackErr) {
         logger.error(
            `Failed to roll back orphaned password reset after email delivery failure. requestId=${requestId} | ${sanitizeError(rollbackErr).message}`
         );
      }
      throw emailErr;
   }
}

// ── Controller ───────────────────────────────────────────────────────────────────
/* Deliberately takes no `next`: once the response is out, there is nobody left to hand an error to (the global handlers would only find `headersSent` and make Express destroy the socket). Failures here are logged, never surfaced; the caller can simply ask again after the cooldown. Make sure these log lines are monitored. */
export async function forgotPasswordController(
   _req: Request,
   res: ResponseWithValidatedBody<ForgotPasswordBody>
): Promise<void> {
   const { email } = res.locals.validatedBody;
   const requestId = res.locals.requestId;

   res.status(200).json({ success: true, message: GENERIC_RESPONSE_MESSAGE });

   try {
      await issuePasswordReset(email, requestId);
   } catch (err) {
      const sanitized = sanitizeError(err);
      logger.error(
         `Password reset issuance failed. requestId=${requestId} | ${sanitized.stack ?? sanitized.message}`
      );
   }
}
