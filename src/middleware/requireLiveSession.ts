import type { Request, NextFunction } from 'express';
import type { CountDocumentsOptions } from 'mongodb';
import { Either, Schema } from 'effect';
import {
   getSessionCollection,
   type ISessionDocument,
} from '@models/Session_v3.model.ts';
import {
   getUserCollection,
   type IUserDocument,
} from '@models/User_v3.model.ts';
import { stringToObjectId } from '@utils/effectSchemaReusables.ts';
import type { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import type { StrictMongoFilter } from '@utils/pathFinder_v3.ts';
import { createErrorResponse } from '../errorHandlers.ts';

/* `authenticate` is stateless: a valid signature means "good when minted", for up to JWT_ACCESS_TOKEN_EXPIRY_MS. This middleware is the phone call to reception before the vault opens. Mount it AFTER `authenticate`, only on sensitive routes.

It confirms TWO facts, in parallel (independent indexed reads):
  1. the session document still exists, belongs to this subject, and has not expired;
  2. the account is still active.

Why (2) is not redundant with (1): deactivation deletes every session, but a login that read the user BEFORE the deactivation can still insert its session AFTER the sweep (Argon2 verification sits between the read and the insert). That orphan session would pass check (1) until its first refresh. This is the single place on sensitive routes where that gap is closed, so controllers behind it do not re-check `isActive` on READS. Sensitive WRITES still pin `isActive: true` in their own filters, which closes the remaining check-then-act window. */
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

      const userId = decodedUserId.right;

      const [liveSessions, activeAccounts] = await Promise.all([
         getSessionCollection().countDocuments(
            {
               _id: decodedSessionId.right,
               userId,
               expiresAt: { $gt: new Date() },
            } satisfies StrictMongoFilter<ISessionDocument>,
            { limit: 1 } satisfies CountDocumentsOptions
         ),
         getUserCollection().countDocuments(
            {
               _id: userId,
               isActive: true,
            } satisfies StrictMongoFilter<IUserDocument>,
            { limit: 1 } satisfies CountDocumentsOptions
         ),
      ]);

      if (liveSessions === 0) {
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

      if (activeAccounts === 0) {
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

      next();
   } catch (err) {
      next(err);
   }
}
