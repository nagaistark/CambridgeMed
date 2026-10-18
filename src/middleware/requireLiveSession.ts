import type { Request, NextFunction } from 'express';
import type { CountDocumentsOptions } from 'mongodb';
import { Either, Schema } from 'effect';
import {
   getSessionCollection,
   type ISessionDocument,
} from '@models/Session_v3.model.ts';
import { stringToObjectId } from '@utils/effectSchemaReusables.ts';
import type { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import type { StrictMongoFilter } from '@utils/pathFinder_v3.ts';
import { createErrorResponse } from '../errorHandlers.ts';

/* `authenticate` is stateless by design: a valid signature means "this token was good when it was minted", for up to JWT_ACCESS_TOKEN_EXPIRY_MS (60s). That is the right trade-off for ordinary reads, and the wrong one for actions that can hand an account to someone else.

Think of a hotel key card. The door reader normally only checks that the card is genuine (cheap, offline). The vault, though, phones reception to confirm the guest hasn't checked out. This middleware is the phone call. Mount it AFTER `authenticate`, only on sensitive routes (password change, email change, TOTP management), so everything else keeps its zero-database-hit fast path.

It closes the window left open by every "delete all sessions" operation we already perform (password change, email confirm/revert, password reset, deactivation, reuse detection): once the session document is gone, the 60-second access token that outlived it stops working on these routes immediately. */
export async function requireLiveSession(
   _req: Request,
   res: AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const { sub, sessionId } = res.locals.authenticatedUser;

      const decodedSessionId =
         Schema.decodeUnknownEither(stringToObjectId)(sessionId);

      const decodedUserId = Schema.decodeUnknownEither(stringToObjectId)(sub);

      /* Both values were minted by us, so a decode failure means a malformed token slipped through; refuse it with the same vague 401 as everything else. */
      if (Either.isLeft(decodedSessionId) || Either.isLeft(decodedUserId)) {
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `Invalid or malformed token.`,
                  res.locals.requestId
               )
            );
      }

      /* Binding the lookup to `userId` as well means a token can only vouch for a session that actually belongs to its own subject. `expiresAt` is checked explicitly because the TTL janitor lags. A primary-key lookup, so the cost is one indexed read. */
      const isLive =
         (await getSessionCollection().countDocuments(
            {
               _id: decodedSessionId.right,
               userId: decodedUserId.right,
               expiresAt: { $gt: new Date() },
            } satisfies StrictMongoFilter<ISessionDocument>,
            { limit: 1 } satisfies CountDocumentsOptions
         )) > 0;

      if (!isLive) {
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `Your session is no longer valid. Please log in again.`,
                  res.locals.requestId
               )
            );
      }

      next();
   } catch (err) {
      next(err);
   }
}
