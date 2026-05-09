import type { Request, NextFunction } from 'express';
import { getUserModel } from '@models/User.model.ts';
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

export async function recoverTotpController(
   req: Request,
   res: ResponseWithValidatedBody<RecoveryCodeBody> & TotpChallengeResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { totpChallengeSub } = res.locals;
      const { code } = res.locals.validatedBody;

      const User = getUserModel();
      const user = await User.findById(totpChallengeSub).lean();

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
      /* We hash the submitted code with the same HMAC key used at storage time, then look for that hash in the stored array. HMAC-SHA256 is deterministic, so hash(input) == hash(input) always — we can compare directly without the verify-and-timing-safe dance that Argon2 requires. */
      const submittedHash = hashRecoveryCode(code);
      const matchIndex = user.totpRecoveryCodes.indexOf(submittedHash);

      if (matchIndex === -1) {
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

      // ── Atomically remove the used code ───────────────────────────────────────
      /* $pull removes the matched element from the array in a single operation. If two requests somehow arrive simultaneously with the same code, one will win and the other's $pull will find nothing to remove — the code will be used twice but not persisted twice, which is acceptable. For a 12-user clinic this race condition is entirely theoretical. */
      await User.updateOne(
         { _id: user._id },
         { $pull: { totpRecoveryCodes: submittedHash } }
      );

      // ── Complete the login ─────────────────────────────────────────────────────
      await issueSession(user, req, res);

      clearTotpChallengeCookie(res);

      /* Warn if they're running low. Zero remaining is handled above as a 409  before we even check the code, so here `remaining` is always >= 0. */
      const remainingCodes = user.totpRecoveryCodes.length - 1;

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
