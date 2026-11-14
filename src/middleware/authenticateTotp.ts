import type { Request, Response, NextFunction } from 'express';
import {
   getTotpChallengeCollection,
   TotpChallengeAuthValidator,
   type ITotpChallengeAuth,
   type ITotpChallengeDocument,
} from '@models/TotpChallenge_v3.model.ts';
import { generateStandardHash } from '@ssot/node_crypto_constants.ts';
import { TOTP_CHALLENGE_AUTH_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import type {
   StrictFindOneOptions,
   StrictMongoFilter,
} from '@utils/pathFinder_v3.ts';
import {
   clearTotpChallengeCookie,
   readTotpChallengeCookie,
} from '@utils/tokenUtils.ts';
import { decodeStored } from '@utils/decodeStored.ts';
import { TOTP_CHALLENGE_EXPIRED_MESSAGE } from '@auth/totpChallenge.ts';
import { createErrorResponse } from '../errorHandlers.ts';

/* Guards /totp/verify and /totp/recover. The user at this point has proven their password but not yet their second factor. They hold a challenge cookie instead of a session cookie.

   This middleware only LOOKS UP the challenge: a mistyped code must stay retryable without re-entering the password (the per-account attempt gate, not the cookie, bounds retries). The challenge is spent by completeTotpLogin once the second factor has verified. A session cookie presented here is just an unknown value: it cannot be found in the challenge collection. */
export async function authenticateTotp(
   req: Request,
   res: Response,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const rawToken = readTotpChallengeCookie(req);

      if (rawToken === undefined) {
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `TOTP verification required.`,
                  requestId
               )
            );
      }

      const challengeRaw =
         await getTotpChallengeCollection().findOne<ITotpChallengeAuth>(
            {
               tokenHash: generateStandardHash(rawToken),
               expiresAt: { $gt: new Date() },
            } satisfies StrictMongoFilter<ITotpChallengeDocument>,
            {
               projection: TOTP_CHALLENGE_AUTH_PROJECTION,
            } satisfies StrictFindOneOptions<ITotpChallengeAuth>
         );

      if (challengeRaw === null) {
         clearTotpChallengeCookie(res);
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

      res.locals.totpChallenge = decodeStored(
         TotpChallengeAuthValidator,
         challengeRaw,
         'authenticateTotp: challenge'
      );
      next();
   } catch (err) {
      next(err);
   }
}
