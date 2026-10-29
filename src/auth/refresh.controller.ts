import type { Request, Response, NextFunction } from 'express';
import { Either, Schema } from 'effect';
import {
   getSessionCollection,
   SessionRefreshValidator,
   type ISessionDocument,
   type ISessionRefresh,
} from '@models/Session_v3.model.ts';
import {
   getUserCollection,
   UserRefreshValidator,
   type IUserDocument,
   type IUserRefresh,
} from '@models/User_v3.model.ts';
import { buildAuthResponse } from '@utils/buildResponses.ts';
import {
   signAccessToken,
   generateRefreshToken,
   setAuthCookies,
   clearAuthCookies,
   readRefreshTokenCookie,
} from '@utils/tokenUtils.ts';
import { getMaxAgeTokens } from '@utils/getMaxAgeTokens.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import { SESSION_REUSE_GRACE_WINDOW_MS } from '@ssot/access_refresh_tokens_constants.ts';
import { generateStandardHash } from '@ssot/node_crypto_constants.ts';
import {
   SESSION_REFRESH_PROJECTION,
   USER_REFRESH_PROJECTION,
} from '@ssot/user_mongodb_query_projection_constants.ts';
import type {
   StrictFindOneOptions,
   StrictMongoFilter,
   StrictUpdate,
} from '@utils/pathFinder_v3.ts';
import { requestContext, securityLog } from '@services/securityLog.service.ts';
import { loadEmailChangeStatus } from '@users/loadEmailChangeStatus.ts';

// ── The presented token is NOT the current one ───────────────────────────────────
/* Always sends a response. Either the token was rotated away moments ago (benign multi-tab race, 409), rotated away long ago (reuse, nuclear option, 401), or unknown (401). Expired sessions are treated as nonexistent. */
async function respondToNonCurrentToken(
   req: Request,
   res: Response,
   tokenHash: string,
   now: Date
): Promise<void> {
   const requestId = res.locals.requestId;
   const sessionCollection = getSessionCollection();

   const staleRaw = await sessionCollection.findOne<ISessionRefresh>(
      {
         previousTokenHash: tokenHash,
         expiresAt: { $gt: now },
      } satisfies StrictMongoFilter<ISessionDocument>,
      {
         projection: SESSION_REFRESH_PROJECTION,
      } satisfies StrictFindOneOptions<ISessionRefresh>
   );

   if (staleRaw === null) {
      /* Fabricated, or belongs to a session already deleted (logout, TTL, an earlier nuclear option). */
      return void res
         .status(401)
         .json(
            createErrorResponse(
               'UNAUTHORIZED',
               `Session not found. Please log in again.`,
               requestId
            )
         );
   }

   const decodedStale = Schema.decodeUnknownEither(SessionRefreshValidator)(
      staleRaw
   );
   if (Either.isLeft(decodedStale)) {
      throw new Error(`Stored session failed validation during refresh.`, {
         cause: decodedStale.left,
      });
   }
   const stale = decodedStale.right;

   /* A negative difference (rotation landed between our `now` and this read) is, correctly, "within the grace window". */
   if (
      now.getTime() - stale.rotatedAt.getTime() <
      SESSION_REUSE_GRACE_WINDOW_MS
   ) {
      /* Another request already rotated this token and set fresh cookies. 409, NOT 401 (which would trigger yet another refresh and a loop): the client waits for the in-flight refresh to settle, then retries. */
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

   /* Reuse outside the grace window: stale client bug or a stolen token. We can't tell which and don't need to. Nuclear option: every session of this user dies. */
   securityLog.record({
      event: 'SESSION_REUSE_DETECTED',
      actorId: null,
      targetUserId: stale.userId,
      ...requestContext(req, res),
   });

   await sessionCollection.deleteMany({
      userId: stale.userId,
   } satisfies StrictMongoFilter<ISessionDocument>);
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

// ── Controller ───────────────────────────────────────────────────────────────────
export async function refreshController(
   req: Request,
   res: Response,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const rawToken = readRefreshTokenCookie(req);

      if (rawToken === undefined) {
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
      const sessionCollection = getSessionCollection();
      const now = new Date();

      // ── Primary lookup: current token AND not expired ─────────────────────────
      const sessionRaw = await sessionCollection.findOne<ISessionRefresh>(
         {
            currentTokenHash: tokenHash,
            expiresAt: { $gt: now },
         } satisfies StrictMongoFilter<ISessionDocument>,
         {
            projection: SESSION_REFRESH_PROJECTION,
         } satisfies StrictFindOneOptions<ISessionRefresh>
      );

      if (sessionRaw === null) {
         await respondToNonCurrentToken(req, res, tokenHash, now);
         return;
      }

      const decodedSession = Schema.decodeUnknownEither(
         SessionRefreshValidator
      )(sessionRaw);
      if (Either.isLeft(decodedSession)) {
         throw new Error(`Stored session failed validation during refresh.`, {
            cause: decodedSession.left,
         });
      }
      const session = decodedSession.right;

      // ── The account must still be allowed to hold a session ───────────────────
      /* Role and permissions are fetched fresh (never cached on the session), so the new access token always reflects the database. */
      const userRaw = await getUserCollection().findOne<IUserRefresh>(
         { _id: session.userId } satisfies StrictMongoFilter<IUserDocument>,
         {
            projection: USER_REFRESH_PROJECTION,
         } satisfies StrictFindOneOptions<IUserRefresh>
      );

      let user: IUserRefresh | null = null;
      if (userRaw !== null) {
         const decodedUser =
            Schema.decodeUnknownEither(UserRefreshValidator)(userRaw);
         if (Either.isLeft(decodedUser)) {
            throw new Error(
               `Stored user failed validation during token refresh.`,
               { cause: decodedUser.left }
            );
         }
         user = decodedUser.right;
      }

      if (user === null || !user.isActive || user.passwordResetRequired) {
         /* Gone or deactivated: kill the session and clear cookies so the client isn't left holding dead credentials. */
         await sessionCollection.deleteOne({
            _id: session._id,
         } satisfies StrictMongoFilter<ISessionDocument>);
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

      // ── Everything fallible happens BEFORE the commit point ───────────────────
      const {
         accessTokenMaxAgeMS,
         refreshTokenMaxAgeMS,
         accessTokenExpirationTimestampMS,
      } = getMaxAgeTokens();

      const { raw: newRawToken, hash: newTokenHash } = generateRefreshToken();

      const accessToken = await signAccessToken({
         sub: user._id.toString(),
         role: user.role,
         permissions: user.permissions,
         sessionId: session._id.toString(),
         expirationTime: accessTokenExpirationTimestampMS,
      });

      /* Read-only, so it belongs above the commit point. If this threw AFTER the rotation, the new cookies would never reach the client, and its retry would look like token reuse and trigger the nuclear option. */
      const emailChange = await loadEmailChangeStatus(user._id, now);

      // ── Commit: atomic compare-and-swap rotation ──────────────────────────────
      /* The filter IS the decision: "this token is STILL the current one and the session is STILL alive". Of two concurrent requests presenting the same token exactly one matches; the loser sees matchedCount 0. expiresAt is deliberately NOT updated: it is the Monday reset, not this token's lifetime. */
      const rotation = await sessionCollection.updateOne(
         {
            _id: session._id,
            currentTokenHash: tokenHash,
            expiresAt: { $gt: now },
         } satisfies StrictMongoFilter<ISessionDocument>,
         {
            $set: {
               currentTokenHash: newTokenHash,
               previousTokenHash: tokenHash,
               rotatedAt: now,
               updatedAt: now,
            },
         } satisfies StrictUpdate<ISessionDocument>
      );

      if (rotation.matchedCount === 0) {
         /* Lost the race: someone rotated (or deleted) this session between our read and our write. Same contract as the grace-window case. The tokens we just minted are discarded unsent. */
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

      setAuthCookies(
         res,
         accessToken,
         accessTokenMaxAgeMS,
         newRawToken,
         refreshTokenMaxAgeMS
      );

      return void res
         .status(200)
         .json(
            buildAuthResponse(
               'Token refreshed successfully.',
               user,
               emailChange
            )
         );
   } catch (err) {
      next(err);
   }
}
