import type { Request, NextFunction } from 'express';
import { Either, Schema } from 'effect';
import { ObjectId } from 'mongodb';
import {
   getUserCollection,
   UserTotpManagementValidator,
   type IUserDocument,
   type IUserTotpManagement,
} from '@models/User_v3.model.ts';
import { verifyPassword } from '@utils/hashAndVerify.ts';
import {
   consumeSecondFactor,
   recordFactorUsage,
   sendSecondFactorFailure,
   toSecondFactorInput,
   verifySecondFactor,
   type SecondFactorContext,
} from '@auth/secondFactor.ts';
import { revokeOtherSessions } from '@auth/revokeOtherSessions.ts';
import { createErrorResponse, makeAppError } from '../errorHandlers.ts';
import { withAuthTransaction } from '@utils/withAuthTransaction.ts';
import { requestContext, securityLog } from '@services/securityLog.service.ts';
import type {
   AuthenticatedResponse,
   ResponseWithValidatedBody,
} from '@utils/customTypedResponses.ts';
import type { DisableTotpBody } from '@auth/totp.schemas.ts';
import { USER_TOTP_MANAGEMENT_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import type {
   StrictFindOneOptions,
   StrictMongoFilter,
   StrictUpdate,
} from '@utils/pathFinder_v3.ts';

export async function disableTotpController(
   req: Request,
   res: ResponseWithValidatedBody<DisableTotpBody> & AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub, sessionId } = res.locals.authenticatedUser;
      const { currentPassword, totpCode, recoveryCode } =
         res.locals.validatedBody;

      const userCollection = getUserCollection();
      const userRaw = await userCollection.findOne<IUserTotpManagement>(
         { _id: new ObjectId(sub) } satisfies StrictMongoFilter<IUserDocument>,
         {
            projection: USER_TOTP_MANAGEMENT_PROJECTION,
         } satisfies StrictFindOneOptions<IUserTotpManagement>
      );

      if (userRaw === null) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `Account not found.`, requestId)
            );
      }

      const decodedUser = Schema.decodeUnknownEither(
         UserTotpManagementValidator
      )(userRaw);
      if (Either.isLeft(decodedUser)) {
         throw new Error(
            `Stored user failed validation while disabling TOTP.`,
            { cause: decodedUser.left }
         );
      }
      const user = decodedUser.right;

      // ── Factor 1: the password ─────────────────────────────────────────────────
      /* The session is valid (requireLiveSession), so a wrong password is a 403 INVALID_CREDENTIALS, never a 401. */
      const isPasswordValid = await verifyPassword(
         user.passwordHash,
         currentPassword
      );
      if (!isPasswordValid) {
         return void res
            .status(403)
            .json(
               createErrorResponse(
                  'INVALID_CREDENTIALS',
                  `Incorrect password.`,
                  requestId
               )
            );
      }

      if (!user.isTotpEnabled) {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `Two-factor authentication is not currently enabled.`,
                  requestId
               )
            );
      }

      // ── Factor 2, phase 1: is the code correct? (nothing is spent yet) ─────────
      const factor = toSecondFactorInput({ totpCode, recoveryCode });
      if (factor === null) {
         /* The schema guarantees exactly one; this branch exists so the type system doesn't have to trust that. */
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `Provide exactly one of totpCode or recoveryCode.`,
                  requestId
               )
            );
      }

      const context: SecondFactorContext = {
         purpose: 'disable',
         actorId: user._id,
         ...requestContext(req, res),
      };

      const verification = await verifySecondFactor(user, factor, context);
      if (verification.status !== 'verified') {
         sendSecondFactorFailure(res, verification, 403);
         return;
      }

      // ── Factor 2, phase 2 + the downgrade: ONE transaction ─────────────────────
      /* The code is spent in the same transaction as the work it authorises. If the flag flip or the session sweep fails, the code is un-spent with them. The write also pins `isActive: true`, closing the window between "I checked" and "I wrote". */
      await withAuthTransaction(async session => {
         const consumption = await consumeSecondFactor(verification.claim, {
            session,
         });
         if (consumption.status === 'rejected') {
            throw makeAppError(
               'FACTOR_REJECTED',
               403,
               'INVALID_CREDENTIALS',
               `Invalid code.`
            );
         }

         const disabled = await userCollection.updateOne(
            {
               _id: user._id,
               isTotpEnabled: true,
               isActive: true,
            } satisfies StrictMongoFilter<IUserDocument>,
            {
               $set: {
                  isTotpEnabled: false,
                  totpSecret: null,
                  totpPendingSecret: null,
                  totpRecoveryCodes: [],
                  totpAttempts: 0,
                  totpAttemptsWindowStartedAt: null,
                  updatedAt: new Date(),
               },
            } satisfies StrictUpdate<IUserDocument>,
            { session }
         );

         if (disabled.matchedCount === 0) {
            throw makeAppError(
               'CONCURRENCY_ERROR',
               409,
               'CONFLICT',
               `Two-factor authentication state changed. Please retry.`
            );
         }

         await revokeOtherSessions(user._id, new ObjectId(sessionId), {
            session,
         });
      });

      // ── Only now, after the commit, do we write the history ────────────────────
      recordFactorUsage(verification.claim, context);
      securityLog.record({
         event: 'TOTP_DISABLED',
         actorId: user._id,
         targetUserId: user._id,
         ...requestContext(req, res),
      });

      return void res.status(200).json({
         success: true,
         message: `Two-factor authentication has been disabled.`,
      });
   } catch (err) {
      next(err);
   }
}
