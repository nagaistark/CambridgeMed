import type { Request } from 'express';
import { Either, Schema } from 'effect';
import { ObjectId } from 'mongodb';
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
import { sanitizeError } from '../mongoDBConnect.ts';
import logger from '../logger.ts';
import { loadEmailChangeStatus } from '@users/loadEmailChangeStatus.ts';

/* A failed notification must never undo a successful login, but it must not vanish silently either. This function cannot reject, which is what makes it safe to await AFTER the response has been sent. */
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

/* The single definition of "finish a login that is waiting on a second factor". Always sends a response. */
export async function completeTotpLogin(
   req: Request,
   res: TotpChallengeResponse,
   input: SecondFactorInput
): Promise<void> {
   const requestId = res.locals.requestId;

   const userRaw = await getUserCollection().findOne<IUserTotpLogin>(
      {
         _id: new ObjectId(res.locals.totpChallengeSub),
      } satisfies StrictMongoFilter<IUserDocument>,
      {
         projection: USER_TOTP_LOGIN_PROJECTION,
      } satisfies StrictFindOneOptions<IUserTotpLogin>
   );

   let user: IUserTotpLogin | null = null;
   if (userRaw !== null) {
      const decodedUser = Schema.decodeUnknownEither(UserTotpLoginValidator)(
         userRaw
      );
      if (Either.isLeft(decodedUser)) {
         throw new Error(`Stored user failed validation during TOTP login.`, {
            cause: decodedUser.left,
         });
      }
      user = decodedUser.right;
   }

   if (user === null || !user.isActive) {
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

   if (user.passwordResetRequired) {
      clearTotpChallengeCookie(res);
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

   /* BEFORE checkSecondFactor: that call SPENDS the code. A read that failed after it would burn a recovery code and still fail the login. The status is only ever sent once the factor has verified. */
   const emailChange = await loadEmailChangeStatus(user._id, new Date());

   /* `actorId: null`: the caller has proven a password but holds no session yet. */
   const context: SecondFactorContext = {
      purpose: 'login',
      actorId: null,
      ...requestContext(req, res),
   };

   /* On failure we deliberately do NOT clear the challenge cookie: a mistyped code should be retryable without re-entering the password. The attempt gate, not the cookie, bounds retries. Pre-session route, hence 401. */
   const outcome = await checkSecondFactor(user, input, context);
   if (outcome.status !== 'verified') {
      sendSecondFactorFailure(res, outcome, 401);
      return;
   }

   await issueSession(user, req, res);
   clearTotpChallengeCookie(res);

   const remaining = outcome.remainingRecoveryCodes;
   if (remaining === null) {
      return void res
         .status(200)
         .json(buildAuthResponse(`Login successful.`, user, emailChange));
   }

   /* The response goes out FIRST. The email provider's round trip (hundreds of ms, occasionally seconds) is none of the user's business. We still `await` the notification afterwards, so the work stays owned by this request's async chain (no floating promise) and cannot reject. */
   res.status(200).json({
      ...buildAuthResponse(
         `Login successful via recovery code.`,
         user,
         emailChange
      ),
      remainingRecoveryCodes: remaining,
      ...(remaining <= TOTP_RECOVERY_CODE_LOW_THRESHOLD
         ? {
              warning: `You have ${remaining} recovery code${remaining === 1 ? '' : 's'} remaining. Generate a fresh set from your security settings.`,
           }
         : {}),
   });

   await notifyRecoveryCodeUsed(user, remaining);
}
