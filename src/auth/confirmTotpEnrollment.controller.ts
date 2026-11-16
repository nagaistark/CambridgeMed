import type { Request, NextFunction } from 'express';
import {
   getUserCollection,
   UserTotpManagementValidator,
   type IUserDocument,
   type IUserTotpManagement,
} from '@models/User_v3.model.ts';
import { generateRecoveryCodes, hashRecoveryCode } from '@utils/totpCrypto.ts';
import { verifyTotpCode } from '@auth/secondFactor.ts';

import { keepOnlyCurrentSession } from '@auth/keepOnlyCurrentSession.ts';
import { withAuthTransaction } from '@utils/withAuthTransaction.ts';

import { createErrorResponse, makeAppError } from '../errorHandlers.ts';
import type {
   AuthenticatedResponse,
   ResponseWithValidatedBody,
} from '@utils/customTypedResponses.ts';
import type { TotpCodeBody } from '@auth/totp.schemas.ts';
import { USER_TOTP_MANAGEMENT_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import type {
   StrictFindOneOptions,
   StrictMongoFilter,
   StrictUpdate,
} from '@utils/pathFinder_v3.ts';

import { requestContext, securityLog } from '@services/securityLog.service.ts';
import { decodeStored } from '@utils/decodeStored.ts';

export async function confirmTotpEnrollmentController(
   req: Request,
   res: ResponseWithValidatedBody<TotpCodeBody> & AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { userId, sessionId } = res.locals.authenticatedUser;
      const { code } = res.locals.validatedBody;

      const userCollection = getUserCollection();
      const userRaw = await userCollection.findOne<IUserTotpManagement>(
         { _id: userId } satisfies StrictMongoFilter<IUserDocument>,
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
         'TOTP confirm user'
      );

      if (validatedUser.isTotpEnabled) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  `Two-factor authentication is already enabled.`,
                  requestId
               )
            );
      }

      if (validatedUser.totpPendingSecret === null) {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `No pending TOTP enrollment found. Please start the enrollment process first.`,
                  requestId
               )
            );
      }

      // ── Verify against the PENDING secret ──────────────────────────────────────
      const check = await verifyTotpCode({
         encryptedSecret: validatedUser.totpPendingSecret,
         code,
         lastUsedStep: validatedUser.totpLastUsedStep,
         userId: validatedUser._id,
      });

      if (!check.valid) {
         return void res
            .status(403)
            .json(
               createErrorResponse(
                  'INVALID_CREDENTIALS',
                  `Invalid code. Please check your authenticator app and try again.`,
                  requestId
               )
            );
      }

      // ── Plaintext codes: generated, hashed for storage, shown exactly once ─────
      const plainTextCodes = generateRecoveryCodes();
      const hashedCodes = plainTextCodes.map(hashRecoveryCode);

      // ── Promote pending → live, atomically ─────────────────────────────────────
      /* ONE transaction: the promotion, the version bump, the re-stamp of THIS session and the sweep of every other session commit together or not at all. The filter pins every fact the decision rested on: still disabled, the SAME pending secret we verified against, the SAME credentialsVersion we read, and a step strictly newer than the last used (replay protection). If any of them moved, nothing is written. */
      const { timeStep } = check;
      const pendingSecret = validatedUser.totpPendingSecret;
      const nextCredentialsVersion = validatedUser.credentialsVersion + 1;

      await withAuthTransaction(async session => {
         const enabled = await userCollection.updateOne(
            {
               _id: validatedUser._id,
               isTotpEnabled: false,
               isActive: true,
               credentialsVersion: validatedUser.credentialsVersion,
               totpPendingSecret: pendingSecret,
               totpLastUsedStep: { $lt: timeStep },
            } satisfies StrictMongoFilter<IUserDocument>,
            {
               $set: {
                  isTotpEnabled: true,
                  totpSecret: pendingSecret,
                  totpPendingSecret: null,
                  totpRecoveryCodes: hashedCodes,
                  totpLastUsedStep: timeStep,
                  updatedAt: new Date(),
               },
               $inc: { credentialsVersion: 1 },
            } satisfies StrictUpdate<IUserDocument>,
            { session }
         );

         if (enabled.matchedCount === 0) {
            throw makeAppError(
               'CONCURRENCY_ERROR',
               409,
               'CONFLICT',
               `Enrollment state changed. Please restart the enrollment process.`
            );
         }

         await keepOnlyCurrentSession(
            {
               userId: validatedUser._id,
               sessionId,
               credentialsVersion: nextCredentialsVersion,
            },
            { session }
         );
      });

      securityLog.record({
         event: 'TOTP_ENABLED',
         actorId: validatedUser._id,
         targetUserId: validatedUser._id,
         ...requestContext(req, res),
      });

      return void res.status(200).json({
         success: true,
         message: `Two-factor authentication enabled successfully.`,
         recoveryCodes: plainTextCodes,
         recoveryCodesWarning: `Save these codes somewhere safe. Each can be used once if you lose access to your authenticator app. They will not be shown again.`,
      });
   } catch (err) {
      next(err);
   }
}
