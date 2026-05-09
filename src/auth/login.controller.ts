import type { Request, NextFunction } from 'express';
import { getUserModel } from '@models/User.model.ts';
import { buildAuthResponse } from '@utils/buildResponses.ts';
import { getSessionModel } from '@models/Session.model.ts';
import { verifyPassword } from '@utils/hashAndVerify.ts';

import {
   signAccessToken,
   generateRefreshToken,
   setAuthCookies,
   signTotpChallengeToken,
   setTotpChallengeCookie,
} from '@utils/tokenUtils.ts';

import { getMaxAgeTokens } from '@utils/getMaxAgeTokens.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import type { LoginBody } from '@auth/login.schema.ts';
import { ResponseWithValidatedBody } from '@utils/customTypedResponses.ts';

// ── Timing-safe dummy hash ───────────────────────────────────────────────────────
/* A syntactically valid argon2id hash with parameters matching ARGON2_CONFIG. When no user is found for the submitted email, we still run a full Argon2 verification against this dummy (to make the response time indistinguishable from a "user found but wrong password"). This prevents an attacker from enumerating valid email addresses by measuring latency differences.

• The salt (22 chars) represents 16 zero-bytes in base64.
• The hash (43 chars) represents 32 zero-bytes in base64.

These values will never match any real password, which is the entire point. */

const TIMING_DUMMY_HASH =
   '$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

export async function loginController(
   req: Request,
   res: ResponseWithValidatedBody<LoginBody>,
   next: NextFunction
): Promise<void> {
   try {
      const { email, password } = res.locals['validatedBody'];
      const User = getUserModel();
      const Session = getSessionModel();

      const user = await User.findOne({ email }).lean();

      const isPasswordValid = await verifyPassword(
         user?.passwordHash ?? TIMING_DUMMY_HASH,
         password
      );

      // Deliberately vague: same message for "no such user" and "wrong password".
      if (!user || !isPasswordValid) {
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `Invalid email or password.`,
                  res.locals.requestId
               )
            );
      }

      /* This check comes AFTER the credential check deliberately. Failing here reveals that the email exists, but only to someone who already proved they know the correct password — so enumeration risk is acceptable. */
      if (!user.isActive) {
         return void res
            .status(403)
            .json(
               createErrorResponse(
                  'FORBIDDEN',
                  `This account has been deactivated. Please contact an administrator.`,
                  res.locals.requestId
               )
            );
      }

      // ── TOTP gate ──────────────────────────────────────────────────────────────
      /* If the user has TOTP enabled, we cannot issue session tokens yet. Instead, we issue a narrow challenge token and return 202 to signal to the frontend that a second factor is required. The client should redirect to the TOTP input screen. The real session is created only after /totp/verify succeeds. */
      if (user.isTotpEnabled) {
         const challengeToken = await signTotpChallengeToken(
            user._id.toString()
         );
         setTotpChallengeCookie(res, challengeToken);

         return void res.status(202).json({
            success: true,
            requiresTotp: true,
            message: `Two-factor authentication required.`,
         });
      }

      // ── Issue tokens ───────────────────────────────────────────────────────────
      const {
         ATMA: accessTokenMaxAge,
         RTMA: refreshTokenMaxAge,
         ATEXP: accessTokenExpirationTime,
         RTEXP: refreshTokenExpirationTime,
      } = getMaxAgeTokens();

      const { raw: rawRefreshToken, hash: refreshTokenHash } =
         generateRefreshToken();

      const sessionDoc = await Session.create({
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

      /* Return only the safe, non-sensitive subset of the user record. Never echo passwordHash, __v, or internal flags back to the client. */
      return void res
         .status(200)
         .json(buildAuthResponse('Login successful', user));
   } catch (err) {
      next(err);
   }
}
