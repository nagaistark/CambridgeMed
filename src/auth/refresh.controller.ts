import type { Request, Response, NextFunction } from 'express';
import { getSessionModel } from '@models/Session.model.ts';
import { buildAuthResponse } from '@utils/buildResponses.ts';
import { getUserModel } from '@models/User.model.ts';
import {
   signAccessToken,
   generateRefreshToken,
   setAuthCookies,
   clearAuthCookies,
   REFRESH_TOKEN_COOKIE_NAME,
} from '@utils/tokenUtils.ts';
import { getMaxAgeTokens } from '@utils/getMaxAgeTokens.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import { SESSION_REUSE_GRACE_WINDOW_MS } from '@ssot/access_refresh_tokens_constants.ts';
import { generateStandardHash } from '@ssot/node_crypto_constants.ts';

export async function refreshController(
   req: Request,
   res: Response,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const rawToken: string | undefined =
         req.cookies[REFRESH_TOKEN_COOKIE_NAME];

      // ── Cookie presence check ──────────────────────────────────────────
      /* A missing cookie means the session has already expired or the client never had one. Same vague 401 as any other unauthenticated request. */
      if (!rawToken) {
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `Authentication required.`,
                  requestId
               )
            );
      }

      const tokenHash = generateStandardHash(rawToken);
      const Session = getSessionModel();

      // ── Primary lookup: is this the current token? ─────────────────────--------
      /* This query resolves the vast majority of legitimate refresh requests in a single indexed hit. If it returns a document, we are on the HAPPY PATH and no further session queries are needed. */
      const session = await Session.findOne({
         currentTokenHash: tokenHash,
      }).lean();

      if (session) {
         // ── Case 1: HAPPY PATH: valid rotation ─────────────────────────────────-
         /* Two reasons we fetch the user record:
            a) We need role and canIssueInvites to sign the new access token. The session document deliberately does not cache these so they are always fresh. */
         const user = await getUserModel().findById(session.userId).lean();

         /* b) We check isActive here. If an admin deactivated this account since the session was created, we must not mint new tokens. */
         if (!user || !user.isActive) {
            /* The account is gone or deactivated. Kill the session and clear cookies so the client is not left holding dead credentials. */
            await Session.deleteOne({ _id: session._id });
            clearAuthCookies(res);
            return void res
               .status(401)
               .json(
                  createErrorResponse(
                     'UNAUTHORIZED',
                     `The user does not exist or has been deactivated.`,
                     requestId
                  )
               );
         }

         /* Generate the new token pair before touching the database. */
         const {
            ATMA: accessTokenMaxAge,
            RTMA: refreshTokenMaxAge,
            ATEXP: accessTokenExpirationTime,
         } = getMaxAgeTokens();

         const { raw: newRawToken, hash: newTokenHash } =
            generateRefreshToken();

         const accessToken = await signAccessToken({
            sub: user._id.toString(),
            role: user.role,
            canIssueInvites: user.canIssueInvites,
            expirationTime: accessTokenExpirationTime,
         });

         /* Rotate the session document in-place. The current hash steps back to previousTokenHash, and the newly generated hash becomes the live currentTokenHash. expiresAt is deliberately NOT updated — it represents when this entire session expires (Monday reset), not when this token expires. */
         await Session.updateOne(
            { _id: session._id },
            {
               $set: {
                  currentTokenHash: newTokenHash,
                  previousTokenHash: tokenHash,
                  rotatedAt: new Date(),
               },
            },
            { runValidators: true }
         );

         setAuthCookies(
            res,
            accessToken,
            accessTokenMaxAge,
            newRawToken,
            refreshTokenMaxAge
         );

         return void res
            .status(200)
            .json(buildAuthResponse('Token refreshed successfully.', user));
      }

      // ── Secondary lookup: is this a previous (already rotated) token? ──
      /* If the primary lookup failed, the token is either stale (rotated away) or completely unknown. The secondary lookup tells us which. */
      const staleSession = await Session.findOne({
         previousTokenHash: tokenHash,
      }).lean();

      if (staleSession) {
         const millisecondsSinceRotation =
            Date.now() - staleSession.rotatedAt.getTime();
         const isWithinGraceWindow =
            millisecondsSinceRotation < SESSION_REUSE_GRACE_WINDOW_MS;

         if (isWithinGraceWindow) {
            // ── Case 2: benign multi-tab race condition ────────────────────------
            /* Another tab's refresh request won the race and already rotated this token. That winning request set fresh cookies in the browser's shared vault. We respond with 409, not 401 (which would trigger another refresh attempt and cause a loop), as the signal for the frontend interceptor to simply retry the original failed request using the cookies already in the vault. */
            return void res
               .status(409)
               .json(
                  createErrorResponse(
                     'CONFLICT',
                     `Session was already refreshed. Please retry your request.`,
                     requestId
                  )
               );
         }

         // ── Case 3/4: reuse detected outside the grace window ─────────────------
         /* A rotated token arrived too late to be a race condition. This is either a stale client bug or (more seriously) an attacker presenting a stolen token after the legitimate user already rotated it. We cannot tell which, and we don't need to. The response is "nuclear option". Delete every active session for this user, forcing a full re-authentication from all devices. */
         await Session.deleteMany({ userId: staleSession.userId });
         clearAuthCookies(res);
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `Session compromised. Please log in again.`,
                  requestId
               )
            );
      }

      // ── Token not found in either position ─────────────────────────────--------
      /* The hash matches neither currentTokenHash nor previousTokenHash in any session document. This token is either completely fabricated, or it belongs to a session that was already deleted (logout, TTL expiry, or a prior nuclear option). In all cases: plain 401. */
      return void res
         .status(401)
         .json(
            createErrorResponse(
               'UNAUTHORIZED',
               `Session not found. Please log in again.`,
               requestId
            )
         );
   } catch (err) {
      next(err);
   }
}
