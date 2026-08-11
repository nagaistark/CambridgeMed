import type { Request, Response, NextFunction } from 'express';
import { jwtVerify } from 'jose';
import { getPublicKey } from '@utils/jwtUtils.ts';
import {
   TOTP_CHALLENGE_COOKIE_NAME,
   TOTP_CHALLENGE_AUDIENCE,
} from '@ssot/totp_constants.ts';
import { createErrorResponse } from '../errorHandlers.ts';

/* Guards /totp/verify and /totp/recover. The user at this point has proven their password is correct but has not yet proven their TOTP code. They hold a challenge token cookie rather than an access token cookie. */
export async function authenticateTotp(
   req: Request,
   res: Response,
   next: NextFunction
): Promise<void> {
   try {
      const rawToken: string | undefined =
         req.cookies[TOTP_CHALLENGE_COOKIE_NAME];

      if (!rawToken) {
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `TOTP verification required.`,
                  res.locals.requestId
               )
            );
      }

      const publicKey = await getPublicKey();

      /* jwtVerify enforces signature,expiry, AND audience simultaneously. An access token or email-verification token presented here will be rejected because its audience claim won't match 'totp-challenge'. */
      const { payload } = await jwtVerify(rawToken, publicKey, {
         algorithms: ['RS256'],
         audience: TOTP_CHALLENGE_AUDIENCE,
      });

      const { sub } = payload;

      if (typeof sub !== 'string') {
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `Invalid challenge token.`,
                  res.locals.requestId
               )
            );
      }

      res.locals.totpChallengeSub = sub;
      next();
   } catch (err) {
      // JOSEErrors (expired token, bad signature) travel to handleJwtError.
      next(err);
   }
}
