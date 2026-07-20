import type { Request, NextFunction } from 'express';
import { getUserCollection } from '@models/User_v3.model.ts';
import { hashRecoveryCode } from '@utils/totpCrypto.ts';
import { clearTotpChallengeCookie } from '@utils/tokenUtils.ts';
import { buildAuthResponse } from '@utils/buildResponses.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import {
   TotpChallengeResponse,
   ResponseWithValidatedBody,
} from '@utils/customTypedResponses.ts';
import type { RecoveryCodeBody } from '@auth/totp.schemas.ts';
import { issueSession } from '@utils/issueSession.ts';
import { ObjectId } from 'mongodb';

export async function recoverTotpController(
   req: Request,
   res: ResponseWithValidatedBody<RecoveryCodeBody> & TotpChallengeResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { totpChallengeSub } = res.locals;
      const { code } = res.locals.validatedBody;

      const userCollection = getUserCollection();
      const user = await userCollection.findOne({
         _id: new ObjectId(totpChallengeSub),
      });

      if (!user || !user.isActive) {
         clearTotpChallengeCookie(res);
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `Account not found or deactivated.`,
                  requestId
               )
            );
      }

      if (!user.isTotpEnabled) {
         clearTotpChallengeCookie(res);
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `Two-factor authentication is not enabled on this account.`,
                  requestId
               )
            );
      }

      if (user.totpRecoveryCodes.length === 0) {
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

      // ── Find and consume the matching code ─────────────────────────────────────
      const submittedHash = hashRecoveryCode(code);

      const updateResult = await userCollection.findOneAndUpdate(
         { _id: user._id, totpRecoveryCodes: submittedHash },
         { $pull: { totpRecoveryCodes: submittedHash } }
      );

      if (!updateResult) {
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `Invalid recovery code.`,
                  requestId
               )
            );
      }

      // ── Complete the login ─────────────────────────────────────────────────────
      await issueSession(user, req, res);

      clearTotpChallengeCookie(res);

      const remainingCodes = updateResult.totpRecoveryCodes.length;

      return void res.status(200).json({
         ...buildAuthResponse(`Login successful via recovery code.`, user),
         remainingRecoveryCodes: remainingCodes,
         ...(remainingCodes <= 2 && {
            warning: `You have ${remainingCodes} recovery code${remainingCodes === 1 ? '' : 's'} remaining. Consider disabling and re-enabling 2FA to generate new ones.`,
         }),
      });
   } catch (err) {
      next(err);
   }
}
