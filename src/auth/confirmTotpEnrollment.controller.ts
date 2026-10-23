import type { Request, NextFunction } from 'express';
import { Either, Schema } from 'effect';
import { ObjectId } from 'mongodb';
import {
   getUserCollection,
   UserTotpManagementValidator,
   type IUserDocument,
   type IUserTotpManagement,
} from '@models/User_v3.model.ts';
import { generateRecoveryCodes, hashRecoveryCode } from '@utils/totpCrypto.ts';
import { verifyTotpCode } from '@auth/secondFactor.ts';
import { revokeOtherSessions } from '@auth/revokeOtherSessions.ts';
import { createErrorResponse } from '../errorHandlers.ts';
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
import { sanitizeError } from '../mongoDBConnect.ts';
import logger from '../logger.ts';
import { requestContext, securityLog } from '@services/securityLog.service.ts';

export async function confirmTotpEnrollmentController(
   req: Request,
   res: ResponseWithValidatedBody<TotpCodeBody> & AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub, sessionId } = res.locals.authenticatedUser;
      const { code } = res.locals.validatedBody;

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
            `Stored user failed validation during TOTP confirmation.`,
            { cause: decodedUser.left }
         );
      }
      const user = decodedUser.right;

      if (user.isTotpEnabled) {
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

      if (user.totpPendingSecret === null) {
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
         encryptedSecret: user.totpPendingSecret,
         code,
         lastUsedStep: user.totpLastUsedStep,
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
      /* The filter pins every fact the decision rested on: still disabled, the SAME pending secret we verified against, and a step strictly newer than the last used (replay protection). If any of them moved, nothing is written. */
      const enabled = await userCollection.updateOne(
         {
            _id: user._id,
            isTotpEnabled: false,
            isActive: true,
            totpPendingSecret: user.totpPendingSecret,
            totpLastUsedStep: { $lt: check.timeStep },
         } satisfies StrictMongoFilter<IUserDocument>,
         {
            $set: {
               isTotpEnabled: true,
               totpSecret: user.totpPendingSecret,
               totpPendingSecret: null,
               totpRecoveryCodes: hashedCodes,
               totpLastUsedStep: check.timeStep,
               updatedAt: new Date(),
            },
         } satisfies StrictUpdate<IUserDocument>
      );

      if (enabled.matchedCount === 0) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  `Enrollment state changed. Please restart the enrollment process.`,
                  requestId
               )
            );
      }

      /* Sessions created before 2FA existed are pre-2FA keys. Best effort on purpose: enabling is an UPGRADE, so a failure here must not hide the recovery codes (shown only once), but it must not pass silently either. */
      try {
         await revokeOtherSessions(user._id, new ObjectId(sessionId));
      } catch (revokeErr) {
         logger.error(
            `Failed to revoke other sessions after TOTP enrollment: ${sanitizeError(revokeErr).message}`,
            { requestId, userId: sub }
         );
      }

      securityLog.record({
         event: 'TOTP_ENABLED',
         actorId: user._id,
         targetUserId: user._id,
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
