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

type Principal =
   | { readonly status: 'no_session' }
   | { readonly status: 'no_user'; readonly session: ISessionAuth }
   | {
        readonly status: 'found';
        readonly session: ISessionAuth;
        readonly user: IUserAuth;
     };

/* Two reads, session first, then its owner. They are NOT one snapshot: a transaction can commit between them (see the retry in buildAuthenticate). */
async function loadPrincipal(tokenHash: string, now: Date): Promise<Principal> {
   const sessionRaw = await getSessionCollection().findOne<ISessionAuth>(
      {
         tokenHash,
         expiresAt: { $gt: now },
         absoluteExpiresAt: { $gt: now },
      } satisfies StrictMongoFilter<ISessionDocument>,
      {
         projection: SESSION_AUTH_PROJECTION,
      } satisfies StrictFindOneOptions<ISessionAuth>
   );
   if (sessionRaw === null) return { status: 'no_session' };

   const session = decodeStored(
      SessionAuthValidator,
      sessionRaw,
      'authenticate: session'
   );

   const userRaw = await getUserCollection().findOne<IUserAuth>(
      { _id: session.userId } satisfies StrictMongoFilter<IUserDocument>,
      {
         projection: USER_AUTH_PROJECTION,
      } satisfies StrictFindOneOptions<IUserAuth>
   );
   if (userRaw === null) return { status: 'no_user', session };

   /* Fails CLOSED: contradictory role/permissions throw StoredDataError (500). */
   const user = decodeStored(UserAuthValidator, userRaw, 'authenticate: user');
   return { status: 'found', session, user };
}

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
         const tokenHash = generateStandardHash(rawToken);
         const sessionCollection = getSessionCollection();

         let principal = await loadPrincipal(tokenHash, now);

         /* A stamp mismatch can be a mirage: keepOnlyCurrentSession re-stamps the actor's session in the same transaction that bumps the user, and our two reads may straddle that commit. One re-read settles it, because after the commit point both documents agree. */
         if (
            principal.status === 'found' &&
            principal.session.credentialsVersion !==
               principal.user.credentialsVersion
         ) {
            principal = await loadPrincipal(tokenHash, now);
         }

         if (principal.status === 'no_session') {
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

         if (principal.status === 'no_user') {
            await sessionCollection.deleteOne({
               _id: principal.session._id,
            } satisfies StrictMongoFilter<ISessionDocument>);
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

         const { session: validatedSession, user: validatedUser } = principal;

         /* Unconditional delete is correct here: these states kill ANY session of this account. */
         if (!validatedUser.isActive || validatedUser.passwordResetRequired) {
            await sessionCollection.deleteOne({
               _id: validatedSession._id,
            } satisfies StrictMongoFilter<ISessionDocument>);
            clearAuthCookies(res);
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

         /* Still different after the re-read: a genuine stale stamp. The delete is conditional on the stamp we read, so a session that was legitimately re-stamped in the meantime can never be shredded. */
         if (
            validatedSession.credentialsVersion !==
            validatedUser.credentialsVersion
         ) {
            const killed = await sessionCollection.deleteOne({
               _id: validatedSession._id,
               credentialsVersion: validatedSession.credentialsVersion,
            } satisfies StrictMongoFilter<ISessionDocument>);

            if (killed.deletedCount === 1) {
               clearAuthCookies(res);
            }

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

         if (options.slidesSession) {
            await slideSession(validatedSession, now);
         }

         const authenticatedUser: AuthenticatedUser = {
            userId: validatedUser._id,
            sessionId: validatedSession._id,
            role: validatedUser.role,
            permissions: validatedUser.permissions,
            idleExpiresAt: validatedSession.expiresAt,
            absoluteExpiresAt: validatedSession.absoluteExpiresAt,
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
