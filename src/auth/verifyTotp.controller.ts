import type { Request, NextFunction } from 'express';
import { verify } from 'otplib';
import { getUserCollection, IUserDocument } from '@models/User_v3.model.ts';
import { decryptTotpSecret } from '@utils/totpCrypto.ts';
import { clearTotpChallengeCookie } from '@utils/tokenUtils.ts';
import { buildAuthResponse } from '@utils/buildResponses.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import {
   TotpChallengeResponse,
   ResponseWithValidatedBody,
} from '@utils/customTypedResponses.ts';
import type { TotpCodeBody } from '@auth/totp.schemas.ts';
import { issueSession } from '@utils/issueSession.ts';
import { ObjectId } from 'mongodb';
import { StrictMongoFilter, StrictUpdate } from '@utils/pathFinder_v3.ts';

export async function verifyTotpController(
   req: Request,
   res: ResponseWithValidatedBody<TotpCodeBody> & TotpChallengeResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { totpChallengeSub } = res.locals;
      const { code } = res.locals.validatedBody;

      const userCollection = getUserCollection();
      const user = await userCollection.findOne({
         _id: new ObjectId(totpChallengeSub),
      } satisfies StrictMongoFilter<IUserDocument>);

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

      if (!user.isTotpEnabled || !user.totpSecret) {
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

      // ── Verify the code ────────────────────────────────────────────────────────
      /* On failure we deliberately do NOT clear the challenge cookie. The user may have mis-typed the code — they should be able to retry within the challenge window without having to re-enter their password. */
      const rawSecret = decryptTotpSecret(user.totpSecret);
      const result = await verify({
         token: code,
         secret: rawSecret,
         epochTolerance: 5,
         afterTimeStep: user.totpLastUsedStep,
      });

      if (!result.valid) {
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `Invalid code. Please try again.`,
                  requestId
               )
            );
      }

      // ── Update the Time Step ───────────────────────────────────────────────────
      if ('timeStep' in result) {
         await userCollection.updateOne(
            { _id: user._id } satisfies StrictMongoFilter<IUserDocument>,
            {
               $set: { totpLastUsedStep: result.timeStep },
            } satisfies StrictUpdate<IUserDocument>
         );
      }

      // ── Complete the login: create session + issue tokens ──────────────────────
      await issueSession(user, req, res);

      clearTotpChallengeCookie(res);

      return void res
         .status(200)
         .json(buildAuthResponse(`Login successful.`, user));
   } catch (err) {
      next(err);
   }
}
