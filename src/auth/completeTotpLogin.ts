import type { Request } from 'express';
import {
   getUserCollection,
   UserTotpLoginValidator,
   type IUserDocument,
   type IUserTotpLogin,
} from '@models/User_v3.model.ts';
import {
   checkSecondFactor,
   sendSecondFactorFailure,
   type SecondFactorContext,
   type SecondFactorInput,
} from '@auth/secondFactor.ts';
import { sendRecoveryCodeUsedEmail } from '@auth/recoveryCodeUsed.email.ts';
import {
   consumeTotpChallenge,
   TOTP_CHALLENGE_EXPIRED_MESSAGE,
} from '@auth/totpChallenge.ts';
import { issueSession } from '@utils/issueSession.ts';
import { clearTotpChallengeCookie } from '@utils/tokenUtils.ts';
import { buildAuthResponse } from '@utils/buildResponses.ts';
import type { TotpChallengeResponse } from '@utils/customTypedResponses.ts';
import { requestContext } from '@services/securityLog.service.ts';
import { TOTP_RECOVERY_CODE_LOW_THRESHOLD } from '@ssot/totp_constants.ts';
import { USER_TOTP_LOGIN_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import type {
   StrictFindOneOptions,
   StrictMongoFilter,
} from '@utils/pathFinder_v3.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import { sanitizeError } from '@utils/sanitizeError.ts';
import logger from '../logger.ts';
import { loadEmailChangeStatus } from '@users/loadEmailChangeStatus.ts';
import { decodeStored } from '@utils/decodeStored.ts';
import { trackBackgroundTask } from '@utils/backgroundTasks.ts';

/* A failed notification must never undo a successful login, but it must not vanish silently either. This function cannot reject, which is what makes it safe to run AFTER the response has been sent. */
async function notifyRecoveryCodeUsed(
   user: IUserTotpLogin,
   remaining: number
): Promise<void> {
   try {
      await sendRecoveryCodeUsedEmail({
         firstName: user.firstName,
         email: user.email,
         remainingRecoveryCodes: remaining,
      });
   } catch (err) {
      logger.error(
         `Recovery-code notification failed: ${sanitizeError(err).message}`
      );
   }
}

/* Ends the challenge for good: the DOCUMENT is deleted (not merely the cookie forgotten), so the credential is dead even if somebody kept a copy of it. Returns whether THIS call spent it. */
async function endChallenge(res: TotpChallengeResponse): Promise<boolean> {
   const consumed = await consumeTotpChallenge(
      res.locals.totpChallenge._id,
      new Date()
   );
   clearTotpChallengeCookie(res);
   return consumed;
}

/* The single definition of "finish a login that is waiting on a second factor". Always sends a response. */
export async function completeTotpLogin(
   req: Request,
   res: TotpChallengeResponse,
   input: SecondFactorInput
): Promise<void> {
   const requestId = res.locals.requestId;

   const userRaw = await getUserCollection().findOne<IUserTotpLogin>(
      {
         _id: res.locals.totpChallenge.userId,
      } satisfies StrictMongoFilter<IUserDocument>,
      {
         projection: USER_TOTP_LOGIN_PROJECTION,
      } satisfies StrictFindOneOptions<IUserTotpLogin>
   );

   let validatedUser: IUserTotpLogin | null = null;
   if (userRaw !== null) {
      validatedUser = decodeStored(
         UserTotpLoginValidator,
         userRaw,
         'TOTP login user'
      );
   }

   if (validatedUser === null || !validatedUser.isActive) {
      await endChallenge(res);
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

   if (validatedUser.passwordResetRequired) {
      await endChallenge(res);
      return void res
         .status(403)
         .json(
            createErrorResponse(
               'FORBIDDEN',
               `A password reset is required before you can log in.`,
               requestId
            )
         );
   }

   if (!validatedUser.isTotpEnabled) {
      await endChallenge(res);
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

   /* BEFORE checkSecondFactor: that call SPENDS the code. A read that failed after it would burn a recovery code and still fail the login. The status is only ever sent once the factor has verified. */
   const emailChange = await loadEmailChangeStatus(
      validatedUser._id,
      new Date()
   );

   /* `actorId: null`: the caller has proven a password but holds no session yet. */
   const context: SecondFactorContext = {
      purpose: 'login',
      actorId: null,
      ...requestContext(req, res),
   };

   /* On failure we deliberately do NOT end the challenge: a mistyped code should be retryable without re-entering the password. The attempt gate, not the cookie, bounds retries. Pre-session route, hence 401. */
   const outcome = await checkSecondFactor(validatedUser, input, context);
   if (outcome.status !== 'verified') {
      sendSecondFactorFailure(res, outcome, 401);
      return;
   }

   /* Single-use: the challenge is spent BEFORE the session exists. If somebody else spent it first (two requests raced with the same cookie), this login ends here and no session is issued. The code presented was already spent by that point, so the user has to log in again; that only ever happens to a client double-submitting, and it fails closed. */
   if (!(await endChallenge(res))) {
      return void res
         .status(401)
         .json(
            createErrorResponse(
               'UNAUTHORIZED',
               TOTP_CHALLENGE_EXPIRED_MESSAGE,
               requestId
            )
         );
   }

   await issueSession(validatedUser, req, res);

   const remaining = outcome.remainingRecoveryCodes;
   if (remaining === null) {
      return void res
         .status(200)
         .json(
            buildAuthResponse(`Login successful.`, validatedUser, emailChange)
         );
   }

   /* The response goes out FIRST. The email provider's round trip (hundreds of ms, occasionally seconds) is none of the user's business. */
   res.status(200).json({
      ...buildAuthResponse(
         `Login successful via recovery code.`,
         validatedUser,
         emailChange
      ),
      remainingRecoveryCodes: remaining,
      ...(remaining <= TOTP_RECOVERY_CODE_LOW_THRESHOLD
         ? {
              warning: `You have ${remaining} recovery code${remaining === 1 ? '' : 's'} remaining. Generate a fresh set from your security settings.`,
           }
         : {}),
   });

   trackBackgroundTask(notifyRecoveryCodeUsed(validatedUser, remaining));
}
