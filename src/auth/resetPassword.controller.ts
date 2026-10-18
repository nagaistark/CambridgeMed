import type { Request, NextFunction } from 'express';
import type { ClientSession, CountDocumentsOptions, ObjectId } from 'mongodb';
import { Either, Schema } from 'effect';
import {
   getUserCollection,
   type IUserDocument,
} from '@models/User_v3.model.ts';
import {
   getPasswordResetCollection,
   type IPasswordResetDocumentRead,
   PasswordResetDocumentReadValidator,
} from '@models/PasswordReset_v3.model.ts';
import {
   getSessionCollection,
   type ISessionDocument,
} from '@models/Session_v3.model.ts';
import {
   getEmailChangeCollection,
   type IEmailChangeDocumentRead,
} from '@models/EmailChange_v3.model.ts';
import { hashPassword } from '@utils/hashAndVerify.ts';
import { clearAuthCookies } from '@utils/tokenUtils.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import { DatabaseManager } from '../mongoDBConnect.ts';
import { generateStandardHash } from '@ssot/node_crypto_constants.ts';
import type { ResponseWithValidatedBody } from '@utils/customTypedResponses.ts';
import type { ResetPasswordBody } from '@auth/resetPassword.schema.ts';
import type { StrictMongoFilter, StrictUpdate } from '@utils/pathFinder_v3.ts';
import type { ExpandType } from '@utils/helperTypes.ts';
import logger from '../logger.ts';

type ResetPasswordParams = { token: string };

const INVALID_LINK_MESSAGE = `This link is invalid or has expired.` as const;

// ── Transaction outcome ──────────────────────────────────────────────────────────
/* Every settled result the transaction can produce. 'stale_claim' means the token was genuine and has now been consumed, but the account no longer matches what the token was issued for (the email changed since, or the account was deactivated). The client sees the same 404 as for any bad link; the distinction exists only so we can log it. */
type ResetOutcome =
   | { status: 'invalid' }
   | { status: 'stale_claim'; userId: ObjectId }
   | { status: 'reset'; userId: ObjectId };

type ResetTransactionParams = ExpandType<
   Pick<IPasswordResetDocumentRead, 'tokenHash'> &
      Pick<IUserDocument, 'passwordHash'>
>;

// ── Transaction helper ───────────────────────────────────────────────────────────
async function runResetTransaction(
   session: ClientSession,
   params: ResetTransactionParams
): Promise<ResetOutcome> {
   const { tokenHash, passwordHash } = params;

   return session.withTransaction(async (): Promise<ResetOutcome> => {
      const now = new Date();

      // ── Atomic, single-use claim ─────────────────────────────────────────────
      /* One operation decides "exists AND not expired AND now mine": a delete that returns the document. Two concurrent redemptions cannot both get it; the loser sees null (or a write conflict that the driver retries into null). Expiry is checked HERE, in the same atomic step as the claim, not in an earlier read that could be stale by the time the Argon2 hash finishes. */
      const claimedRaw = await getPasswordResetCollection().findOneAndDelete(
         {
            tokenHash,
            expiresAt: { $gt: now },
         } satisfies StrictMongoFilter<IPasswordResetDocumentRead>,
         { session }
      );

      if (claimedRaw === null) return { status: 'invalid' };

      const decodedClaim = Schema.decodeUnknownEither(
         PasswordResetDocumentReadValidator
      )(claimedRaw);

      if (Either.isLeft(decodedClaim)) {
         throw decodedClaim.left;
      }
      const validatedClaim = decodedClaim.right;

      // ── Compare-and-swap on the account's current state ──────────────────────
      /* `email: claim.email` is the binding. A link mailed to an address the account no longer uses (attacker's address after a revert, old address after a confirm) matches nothing here. `isActive: true` closes the "deactivated user redeems an old link, later gets reactivated with a password somebody else chose" gap. Returning normally commits the transaction, so the dead token stays consumed. */
      const applied = await getUserCollection().updateOne(
         {
            _id: validatedClaim.userId,
            email: validatedClaim.email,
            isActive: true,
         } satisfies StrictMongoFilter<IUserDocument>,
         {
            $set: {
               passwordHash,
               passwordResetRequired: false,
               updatedAt: now,
            },
         } satisfies StrictUpdate<IUserDocument>,
         { session }
      );

      if (applied.matchedCount === 0) {
         return { status: 'stale_claim', userId: validatedClaim.userId };
      }

      // ── Void every credential minted under the old password ──────────────────
      /* Sessions: every device re-authenticates against the new password. The user just proved control of the mailbox on file, which is the recovery credential. */
      await getSessionCollection().deleteMany(
         {
            userId: validatedClaim.userId,
         } satisfies StrictMongoFilter<ISessionDocument>,
         { session }
      );

      /* Spare keys: an email change that was started (and authorised) under the old password but not yet confirmed must die with that password. Otherwise the person who started it could still confirm it from the link in their own inbox. A CONFIRMED change is deliberately left alone: its cancel link is the owner's recovery handle until `cancelExpiresAt`. */
      await getEmailChangeCollection().deleteMany(
         {
            userId: validatedClaim.userId,
            confirmedAt: null,
         } satisfies StrictMongoFilter<IEmailChangeDocumentRead>,
         { session }
      );

      return { status: 'reset', userId: validatedClaim.userId };
   });
}

// ── Controller ───────────────────────────────────────────────────────────────────
export async function resetPasswordController(
   req: Request<ResetPasswordParams>,
   res: ResponseWithValidatedBody<ResetPasswordBody>,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { token } = req.params; // Shape already enforced by requireValidRawToken on the route.
      const { newPassword } = res.locals.validatedBody;

      const tokenHash = generateStandardHash(token);

      // ── Step 1: Cheap pre-flight (before Argon2) ───────────────────────────────
      /* Advisory only: it stops an attacker from forcing a 100-300ms Argon2 hash for every guessed token. The atomic claim inside the transaction remains the authority. */
      const isRedeemable =
         (await getPasswordResetCollection().countDocuments(
            {
               tokenHash,
               expiresAt: { $gt: new Date() },
            } satisfies StrictMongoFilter<IPasswordResetDocumentRead>,
            { limit: 1 } satisfies CountDocumentsOptions
         )) > 0;

      if (!isRedeemable) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', INVALID_LINK_MESSAGE, requestId)
            );
      }

      // ── Step 2: Hash BEFORE opening the transaction ────────────────────────────
      const passwordHash = await hashPassword(newPassword);

      // ── Step 3: Run the transaction ────────────────────────────────────────────
      const authConnection = DatabaseManager.getInstance().auth.client;
      if (!authConnection) {
         throw new Error(
            `Auth database connection unavailable during password reset.`
         );
      }

      const session = authConnection.startSession();
      let outcome: ResetOutcome;

      try {
         outcome = await runResetTransaction(session, {
            tokenHash,
            passwordHash,
         });
      } finally {
         await session.endSession();
      }

      // ── Step 4: Respond ────────────────────────────────────────────────────────
      if (outcome.status === 'invalid') {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', INVALID_LINK_MESSAGE, requestId)
            );
      }

      if (outcome.status === 'stale_claim') {
         /* A genuine token met an account that has since changed. Usually harmless (a user who changed their email after requesting a reset), but it is exactly the footprint of a stolen-link attempt after a revert, so it is worth a warning. */
         logger.warn(
            `Password reset token redeemed against a changed account state; refused.`,
            { userId: outcome.userId, requestId }
         );

         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', INVALID_LINK_MESSAGE, requestId)
            );
      }

      clearAuthCookies(res);

      logger.info(`Password reset completed.`, {
         userId: outcome.userId,
         requestId,
      });

      return void res.status(200).json({
         success: true,
         message: `Password reset successfully. Please log in with your new password.`,
      });
   } catch (err) {
      next(err);
   }
}
