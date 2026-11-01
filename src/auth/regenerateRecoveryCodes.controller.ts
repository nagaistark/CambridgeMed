import type { Request, NextFunction } from 'express';
import { ObjectId } from 'mongodb';
import {
   getUserCollection,
   UserTotpManagementValidator,
   type IUserDocument,
   type IUserTotpManagement,
} from '@models/User_v3.model.ts';
import { generateRecoveryCodes, hashRecoveryCode } from '@utils/totpCrypto.ts';
import { verifyPassword } from '@utils/hashAndVerify.ts';
import {
   clearSecondFactorAttempts,
   consumeSecondFactor,
   recordFactorUsage,
   sendSecondFactorFailure,
   toSecondFactorInput,
   verifySecondFactor,
   type SecondFactorContext,
} from '@auth/secondFactor.ts';
import { createErrorResponse, makeAppError } from '../errorHandlers.ts';
import { withAuthTransaction } from '@utils/withAuthTransaction.ts';
import { requestContext, securityLog } from '@services/securityLog.service.ts';
import type {
   AuthenticatedResponse,
   ResponseWithValidatedBody,
} from '@utils/customTypedResponses.ts';
import type { RegenerateRecoveryCodesBody } from '@auth/totp.schemas.ts';
import { USER_TOTP_MANAGEMENT_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import type {
   StrictFindOneOptions,
   StrictMongoFilter,
   StrictUpdate,
} from '@utils/pathFinder_v3.ts';
import { decodeStored } from '@utils/decodeStored.ts';

/* POST /api/auth/totp/recovery-codes/regenerate
   Replaces the WHOLE set: every old code stops working the moment this commits. Same bar as disabling 2FA (password + one current factor), because a fresh set of break-glass credentials is exactly what an attacker with a hijacked session would want. */
export async function regenerateRecoveryCodesController(
   req: Request,
   res: ResponseWithValidatedBody<RegenerateRecoveryCodesBody> &
      AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub } = res.locals.authenticatedUser;
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

      const validatedUser = decodeStored(
         UserTotpManagementValidator,
         userRaw,
         'TOTP recovery-code regeneration user'
      );

      const isPasswordValid = await verifyPassword(
         validatedUser.passwordHash,
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

      if (!validatedUser.isTotpEnabled) {
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

      const factor = toSecondFactorInput({ totpCode, recoveryCode });
      if (factor === null) {
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
         purpose: 'regenerate-codes',
         actorId: validatedUser._id,
         ...requestContext(req, res),
      };

      const verification = await verifySecondFactor(
         validatedUser,
         factor,
         context
      );
      if (verification.status !== 'verified') {
         sendSecondFactorFailure(res, verification, 403);
         return;
      }

      /* Plaintext exists only in this scope and in the response. Only hashes are persisted. */
      const plainTextCodes = generateRecoveryCodes();
      const hashedCodes = plainTextCodes.map(hashRecoveryCode);

      /* Spend the presented code and swap the set in ONE transaction: there is no moment where the old set is gone but the new one is not (or the old code is spent but nothing replaced it). */
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

         const replaced = await userCollection.updateOne(
            {
               _id: validatedUser._id,
               isTotpEnabled: true,
               isActive: true,
            } satisfies StrictMongoFilter<IUserDocument>,
            {
               $set: {
                  totpRecoveryCodes: hashedCodes,
                  updatedAt: new Date(),
               },
            } satisfies StrictUpdate<IUserDocument>,
            { session }
         );

         if (replaced.matchedCount === 0) {
            throw makeAppError(
               'CONCURRENCY_ERROR',
               409,
               'CONFLICT',
               `Two-factor authentication state changed. Please retry.`
            );
         }
      });

      await clearSecondFactorAttempts(validatedUser._id);
      recordFactorUsage(verification.claim, context);
      securityLog.record({
         event: 'TOTP_RECOVERY_CODES_REGENERATED',
         actorId: validatedUser._id,
         targetUserId: validatedUser._id,
         ...requestContext(req, res),
      });

      return void res.status(200).json({
         success: true,
         message: `New recovery codes generated. Your previous codes no longer work.`,
         recoveryCodes: plainTextCodes,
         recoveryCodesWarning: `Save these codes somewhere safe. Each can be used once if you lose access to your authenticator app. They will not be shown again.`,
      });
   } catch (err) {
      next(err);
   }
}
