import type { Request, NextFunction } from 'express';
import { verify } from 'otplib';
import { getUserModel } from '@models/User.model.ts';
import { getSessionModel } from '@models/Session.model.ts';
import { decryptTotpSecret } from '@utils/totpCrypto.ts';
import {
   signAccessToken,
   generateRefreshToken,
   setAuthCookies,
   clearTotpChallengeCookie,
} from '@utils/tokenUtils.ts';
import { getMaxAgeTokens } from '@utils/getMaxAgeTokens.ts';
import { buildAuthResponse } from '@utils/buildResponses.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import {
   TotpChallengeResponse,
   ResponseWithValidatedBody,
} from '@utils/customTypedResponses.ts';
import type { TotpCodeBody } from '@auth/totp.schemas.ts';

export async function verifyTotpController(
   req: Request,
   res: ResponseWithValidatedBody<TotpCodeBody> & TotpChallengeResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { totpChallengeSub } = res.locals;
      const { code } = res.locals.validatedBody;

      const user = await getUserModel().findById(totpChallengeSub).lean();

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
      /* On failure we deliberately do NOT clear the challenge cookie. The user may have mis-typed the code — they should be able to retry within the 5-minute challenge window without having to re-enter their password. */
      const rawSecret = decryptTotpSecret(user.totpSecret);
      const result = await verify({
         token: code,
         secret: rawSecret,
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

      // ── Complete the login: create session + issue tokens ──────────────────────
      /* This is the same token-issuing logic as `loginController`, just reached via a different path. The challenge token has now been fully redeemed. */
      const {
         ATMA: accessTokenMaxAge,
         RTMA: refreshTokenMaxAge,
         ATEXP: accessTokenExpirationTime,
         RTEXP: refreshTokenExpirationTime,
      } = getMaxAgeTokens();

      const { raw: rawRefreshToken, hash: refreshTokenHash } =
         generateRefreshToken();

      const sessionDoc = await getSessionModel().create({
         userId: user._id,
         currentTokenHash: refreshTokenHash,
         previousTokenHash: null,
         rotatedAt: new Date(),
         expiresAt: new Date(refreshTokenExpirationTime),
         ipAddress: req.ip ?? 'unknown',
         userAgent: req.headers['user-agent']?.slice(0, 512) ?? 'unknown',
      });

      const accessToken = await signAccessToken({
         sub: user._id.toString(),
         role: user.role,
         canIssueInvites: user.canIssueInvites,
         sessionId: sessionDoc._id.toString(),
         expirationTime: accessTokenExpirationTime,
      });

      setAuthCookies(
         res,
         accessToken,
         accessTokenMaxAge,
         rawRefreshToken,
         refreshTokenMaxAge
      );

      clearTotpChallengeCookie(res);

      return void res
         .status(200)
         .json(buildAuthResponse(`Login successful.`, user));
   } catch (err) {
      next(err);
   }
}
