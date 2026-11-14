import type { Request, NextFunction } from 'express';
import {
   getSessionCollection,
   SessionAuthValidator,
   type ISessionAuth,
   type ISessionDocument,
} from '@models/Session_v3.model.ts';
import {
   getUserCollection,
   UserAuthValidator,
   type IUserAuth,
   type IUserDocument,
} from '@models/User_v3.model.ts';
import type { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import type { AuthenticatedUser } from '@ssot/authenticated_user_constants.ts';
import { generateStandardHash } from '@ssot/node_crypto_constants.ts';
import {
   SESSION_AUTH_PROJECTION,
   USER_AUTH_PROJECTION,
} from '@ssot/user_mongodb_query_projection_constants.ts';
import type {
   StrictFindOneOptions,
   StrictMongoFilter,
} from '@utils/pathFinder_v3.ts';
import { clearAuthCookies, readSessionTokenCookie } from '@utils/tokenUtils.ts';
import { decodeStored } from '@utils/decodeStored.ts';
import { slideSession } from '@utils/slideSession.ts';
import { createErrorResponse } from '../errorHandlers.ts';

const AUTH_REQUIRED_MESSAGE = `Authentication required.` as const;
const SESSION_INVALID_MESSAGE =
   `Your session is no longer valid. Please log in again.` as const;
const ACCOUNT_DEACTIVATED_MESSAGE =
   `This account has been deactivated. Please contact an administrator.` as const;
/* Same wording as loginController: one contract for "a reset is required". */
const PASSWORD_RESET_REQUIRED_MESSAGE =
   `For your security, you must reset your password before logging in. Use "Forgot password" to receive a reset link.` as const;

type AuthenticateOptions = {
   /* true: this request counts as deliberate activity and slides the idle deadline. false: a PASSIVE route (e.g. /me, which reports the remaining time) that must never extend it. */
   readonly slidesSession: boolean;
};

type AuthMiddleware = (
   req: Request,
   res: AuthenticatedResponse,
   next: NextFunction
) => Promise<void>;

/* The single door. The session document is the SOURCE OF TRUTH, so there is nothing to go stale: on every request, both the session and the account are read fresh, and `authenticatedUser` is built from the database, never from anything the client holds. Role and permissions therefore reflect the database at this very request.

   Every refusal is deliberate and the order is deliberate:
   1. No cookie / junk cookie  -> 401 (the shape check costs nothing).
   2. Unknown or expired token -> 401 (indistinguishable on purpose).
   3. Account gone, deactivated, or awaiting a password reset -> the session is DELETED (a login that raced the deactivation sweep can leave an orphan; refusing is not enough, the credential must die) and the cookie cleared. */
function buildAuthenticate(options: AuthenticateOptions): AuthMiddleware {
   return async (req, res, next) => {
      try {
         const requestId = res.locals.requestId;
         const rawToken = readSessionTokenCookie(req);

         if (rawToken === undefined) {
            return void res
               .status(401)
               .json(
                  createErrorResponse(
                     'UNAUTHORIZED',
                     AUTH_REQUIRED_MESSAGE,
                     requestId
                  )
               );
         }

         const now = new Date();
         const sessionCollection = getSessionCollection();

         /* Both clocks are checked, so a document whose sliding deadline were ever corrupted still cannot outlive the weekly reset. The unique index on `tokenHash` makes this a single point read; the token is 384 random bits hashed with SHA-256, so lookup timing reveals nothing an attacker can use. */
         const sessionRaw = await sessionCollection.findOne<ISessionAuth>(
            {
               tokenHash: generateStandardHash(rawToken),
               expiresAt: { $gt: now },
               absoluteExpiresAt: { $gt: now },
            } satisfies StrictMongoFilter<ISessionDocument>,
            {
               projection: SESSION_AUTH_PROJECTION,
            } satisfies StrictFindOneOptions<ISessionAuth>
         );

         if (sessionRaw === null) {
            clearAuthCookies(res);
            return void res
               .status(401)
               .json(
                  createErrorResponse(
                     'UNAUTHORIZED',
                     SESSION_INVALID_MESSAGE,
                     requestId
                  )
               );
         }

         const validatedSession = decodeStored(
            SessionAuthValidator,
            sessionRaw,
            'authenticate: session'
         );

         const userRaw = await getUserCollection().findOne<IUserAuth>(
            {
               _id: validatedSession.userId,
            } satisfies StrictMongoFilter<IUserDocument>,
            {
               projection: USER_AUTH_PROJECTION,
            } satisfies StrictFindOneOptions<IUserAuth>
         );

         /* Fails CLOSED: role/permissions that contradict each other throw StoredDataError (500) rather than grant anything. */
         const validatedUser =
            userRaw === null
               ? null
               : decodeStored(UserAuthValidator, userRaw, 'authenticate: user');

         if (
            validatedUser === null ||
            !validatedUser.isActive ||
            validatedUser.passwordResetRequired
         ) {
            await sessionCollection.deleteOne({
               _id: validatedSession._id,
            } satisfies StrictMongoFilter<ISessionDocument>);
            clearAuthCookies(res);

            if (validatedUser === null) {
               return void res
                  .status(401)
                  .json(
                     createErrorResponse(
                        'UNAUTHORIZED',
                        SESSION_INVALID_MESSAGE,
                        requestId
                     )
                  );
            }

            return void res
               .status(403)
               .json(
                  createErrorResponse(
                     'FORBIDDEN',
                     validatedUser.isActive
                        ? PASSWORD_RESET_REQUIRED_MESSAGE
                        : ACCOUNT_DEACTIVATED_MESSAGE,
                     requestId
                  )
               );
         }

         if (options.slidesSession) {
            await slideSession(validatedSession, now);
         }

         const authenticatedUser: AuthenticatedUser = {
            sub: validatedUser._id.toHexString(),
            role: validatedUser.role,
            permissions: validatedUser.permissions,
            sessionId: validatedSession._id.toHexString(),
         };
         res.locals.authenticatedUser = authenticatedUser;
         next();
      } catch (err) {
         next(err);
      }
   };
}

/* The safe default: a request through here is deliberate activity. */
export const authenticate: AuthMiddleware = buildAuthenticate({
   slidesSession: true,
});

/* For routes that only REPORT session state (GET /api/auth/me). Identical checks, but it never extends the idle deadline. */
export const authenticatePassive: AuthMiddleware = buildAuthenticate({
   slidesSession: false,
});
