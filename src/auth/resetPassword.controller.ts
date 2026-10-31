import type { Request, NextFunction } from 'express';
import type { ClientSession, ObjectId } from 'mongodb';
import { Either, Schema } from 'effect';
import {
   getUserCollection,
   UserSecondFactorValidator,
   type IUserDocument,
   type IUserSecondFactor,
} from '@models/User_v3.model.ts';
import {
   getPasswordResetCollection,
   type IPasswordResetDocumentRead,
   type IPasswordResetRedeemCheck,
   PasswordResetDocumentReadValidator,
   PasswordResetRedeemCheckValidator,
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
import { createErrorResponse, makeAppError } from '../errorHandlers.ts';
import { generateStandardHash } from '@ssot/node_crypto_constants.ts';
import {
   PASSWORD_RESET_REDEEM_CHECK_PROJECTION,
   USER_SECOND_FACTOR_PROJECTION,
} from '@ssot/user_mongodb_query_projection_constants.ts';
import type { ResponseWithValidatedBody } from '@utils/customTypedResponses.ts';
import type { ResetPasswordBody } from '@auth/resetPassword.schema.ts';
import type {
   StrictFindOneOptions,
   StrictMongoFilter,
   StrictUpdate,
} from '@utils/pathFinder_v3.ts';
import type { ExpandType } from '@utils/helperTypes.ts';
import logger from '../logger.ts';
import {
   clearSecondFactorAttempts,
   consumeSecondFactor,
   recordFactorUsage,
   sendSecondFactorFailure,
   toSecondFactorInput,
   verifySecondFactor,
   type FactorClaim,
   type SecondFactorContext,
} from './secondFactor.ts';
import { requestContext, securityLog } from '@services/securityLog.service.ts';
import { withAuthTransaction } from '@utils/withAuthTransaction.ts';

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
      Pick<IUserDocument, 'passwordHash' | 'isTotpEnabled'> & {
         /* null = the account has no second factor. */
         readonly claim: FactorClaim | null;
      }
>;

/* ORDER MATTERS. Each step is placed so a failure undoes exactly what it should:
   1. Claim the token. 2. Compare-and-swap the account (the "stale" test).
      If the account no longer matches, return normally: the commit keeps the token consumed, and NO factor has been spent yet.
   3. Spend the second factor. If it was replayed or raced, THROW: the whole transaction rolls back, so the token is un-claimed and the password unchanged. The user can retry with a fresh code.
   4. Sweep. */
async function runResetTransaction(
   session: ClientSession,
   params: ResetTransactionParams
): Promise<ResetOutcome> {
   const { tokenHash, passwordHash, claim, isTotpEnabled } = params;
   const now = new Date();

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

   /* Defensive: the factor we verified must belong to the account this token resets. Tokens are unique, so this "cannot happen"; if it ever does, abort (plain Error: logged, vague 500, nothing consumed). */
   if (claim !== null && !claim.userId.equals(validatedClaim.userId)) {
      throw new Error(
         `Second-factor claim does not belong to the password-reset account.`
      );
   }

   const applied = await getUserCollection().updateOne(
      {
         _id: validatedClaim.userId,
         email: validatedClaim.email,
         isActive: true,
         isTotpEnabled,
      } satisfies StrictMongoFilter<IUserDocument>,
      {
         $set: { passwordHash, passwordResetRequired: false, updatedAt: now },
      } satisfies StrictUpdate<IUserDocument>,
      { session }
   );

   if (applied.matchedCount === 0) {
      return { status: 'stale_claim', userId: validatedClaim.userId };
   }

   if (claim !== null) {
      const consumption = await consumeSecondFactor(claim, { session });
      if (consumption.status === 'rejected') {
         throw makeAppError(
            'FACTOR_REJECTED',
            401,
            'INVALID_CREDENTIALS',
            `Invalid code.`
         );
      }
   }

   await getSessionCollection().deleteMany(
      {
         userId: validatedClaim.userId,
      } satisfies StrictMongoFilter<ISessionDocument>,
      { session }
   );

   await getEmailChangeCollection().deleteMany(
      {
         userId: validatedClaim.userId,
         confirmedAt: null,
      } satisfies StrictMongoFilter<IEmailChangeDocumentRead>,
      { session }
   );

   return { status: 'reset', userId: validatedClaim.userId };
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
      const { newPassword, totpCode, recoveryCode } = res.locals.validatedBody;

      const tokenHash = generateStandardHash(token);

      /// ── Step 1: Non-consuming pre-flight (before Argon2) ───────────────────────
      /* Advisory, but it now also yields the userId we need for the step-up. It must NOT consume the token: a mistyped code would otherwise burn the reset link. The atomic claim inside the transaction remains the authority. */
      const redeemRaw =
         await getPasswordResetCollection().findOne<IPasswordResetRedeemCheck>(
            {
               tokenHash,
               expiresAt: { $gt: new Date() },
            } satisfies StrictMongoFilter<IPasswordResetDocumentRead>,
            {
               projection: PASSWORD_RESET_REDEEM_CHECK_PROJECTION,
            } satisfies StrictFindOneOptions<IPasswordResetRedeemCheck>
         );

      if (redeemRaw === null) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', INVALID_LINK_MESSAGE, requestId)
            );
      }

      const decodedRedeem = Schema.decodeUnknownEither(
         PasswordResetRedeemCheckValidator
      )(redeemRaw);
      if (Either.isLeft(decodedRedeem)) {
         throw new Error(`Stored password reset failed validation.`, {
            cause: decodedRedeem.left,
         });
      }

      // ── Step 2: second-factor step-up (phase 1: verify only) ───────────────────
      const userRaw = await getUserCollection().findOne<IUserSecondFactor>(
         {
            _id: decodedRedeem.right.userId,
         } satisfies StrictMongoFilter<IUserDocument>,
         {
            projection: USER_SECOND_FACTOR_PROJECTION,
         } satisfies StrictFindOneOptions<IUserSecondFactor>
      );

      if (userRaw === null) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', INVALID_LINK_MESSAGE, requestId)
            );
      }

      const decodedUser = Schema.decodeUnknownEither(UserSecondFactorValidator)(
         userRaw
      );
      if (Either.isLeft(decodedUser)) {
         throw new Error(
            `Stored user failed validation during password reset.`,
            { cause: decodedUser.left }
         );
      }
      const user = decodedUser.right;

      let claim: FactorClaim | null = null;
      const context: SecondFactorContext = {
         purpose: 'password-reset',
         actorId: null, // the holder of a link has no session
         ...requestContext(req, res),
      };

      if (user.isTotpEnabled) {
         const factor = toSecondFactorInput({ totpCode, recoveryCode });

         if (factor === null) {
            return void res
               .status(403)
               .json(
                  createErrorResponse(
                     'FORBIDDEN',
                     `A two-factor authentication code is required to reset this password.`,
                     requestId,
                     { requiresTotp: true }
                  )
               );
         }

         const verification = await verifySecondFactor(user, factor, context);
         if (verification.status !== 'verified') {
            sendSecondFactorFailure(res, verification, 401); // pre-session route
            return;
         }
         claim = verification.claim;
      }

      // ── Step 3: Hash BEFORE opening the transaction ────────────────────────────
      const passwordHash = await hashPassword(newPassword);

      // ── Step 4: Run the transaction ────────────────────────────────────────────
      const outcome = await withAuthTransaction(session =>
         runResetTransaction(session, {
            tokenHash,
            passwordHash,
            claim,
            isTotpEnabled: user.isTotpEnabled,
         })
      );

      // ── Step 5: Respond ────────────────────────────────────────────────────────
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

      if (claim !== null) {
         await clearSecondFactorAttempts(user._id);
         recordFactorUsage(claim, context);
      }

      securityLog.record({
         event: 'PASSWORD_RESET_COMPLETED',
         actorId: null, // the holder of a link has no session
         targetUserId: outcome.userId,
         ...requestContext(req, res),
      });

      clearAuthCookies(res);

      return void res.status(200).json({
         success: true,
         message: `Password reset successfully. Please log in with your new password.`,
      });
   } catch (err) {
      next(err);
   }
}
