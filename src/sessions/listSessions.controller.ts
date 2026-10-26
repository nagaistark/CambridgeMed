import type { Request, NextFunction } from 'express';
import { Either, Schema } from 'effect';
import { ObjectId } from 'mongodb';
import {
   getSessionCollection,
   SessionAdminViewArrayValidator,
   SessionSelfViewArrayValidator,
   type ISessionAdminListItem,
   type ISessionAdminView,
   type ISessionDocument,
   type ISessionSelfListItem,
   type ISessionSelfView,
} from '@models/Session_v3.model.ts';
import {
   getUserCollection,
   UserIdNameEmailArrayValidator,
   type IUserDocument,
   type IUserIdNameEmail,
} from '@models/User_v3.model.ts';
import {
   SESSION_ADMIN_VIEW_PROJECTION,
   SESSION_SELF_VIEW_PROJECTION,
   USER_ID_NAME_EMAIL_PROJECTION,
} from '@ssot/user_mongodb_query_projection_constants.ts';
import { LIST_QUERY_MAX_TIME_MS } from '@ssot/pagination_constants.ts';
import type {
   AuthenticatedResponse,
   ResponseWithValidatedQuery,
} from '@utils/customTypedResponses.ts';
import type { IObjectIdCursorPagination } from '@utils/effectSchemaReusables.ts';
import type {
   StrictFindOptions,
   StrictMongoFilter,
} from '@utils/pathFinder_v3.ts';
import { takePage } from '@utils/cursorPagination.ts';
import { buildListSessionsResponse } from '@utils/buildResponses.ts';

export async function listSessionsController(
   _req: Request,
   res: AuthenticatedResponse &
      ResponseWithValidatedQuery<IObjectIdCursorPagination>,
   next: NextFunction
): Promise<void> {
   try {
      const { sub, role, sessionId } = res.locals.authenticatedUser;
      const { cursor, limit } = res.locals.validatedQuery;
      const isSuperAdmin = role === 'superadmin';
      const currentSessionId = new ObjectId(sessionId);

      /* Every clause must hold; `{}` is the neutral element.
         1. Liveness: the TTL janitor lags by up to a minute, so expired documents are filtered explicitly.
         2. Ownership: non-superadmins see only their own sessions.
         3. Cursor: the next page starts strictly after the last _id. */
      const filter = {
         $and: [
            { expiresAt: { $gt: new Date() } },
            isSuperAdmin ? {} : { userId: new ObjectId(sub) },
            cursor === undefined ? {} : { _id: { $lt: cursor } },
         ],
      } satisfies StrictMongoFilter<ISessionDocument>;

      const sessionCollection = getSessionCollection();

      if (isSuperAdmin) {
         const rowsRaw = await sessionCollection
            .find<ISessionAdminView>(filter, {
               projection: SESSION_ADMIN_VIEW_PROJECTION,
               sort: { _id: -1 },
               limit: limit + 1, // the +1 is the "is there a next page?" probe
               maxTimeMS: LIST_QUERY_MAX_TIME_MS,
            } satisfies StrictFindOptions<ISessionDocument>)
            .toArray();

         const { items, hasNextPage } = takePage(rowsRaw, limit);
         const decoded = Schema.decodeUnknownEither(
            SessionAdminViewArrayValidator
         )(items);
         if (Either.isLeft(decoded)) {
            throw new Error(`Stored sessions failed validation in the list.`, {
               cause: decoded.left,
            });
         }
         const sessions = decoded.right;

         // ── Batch-fetch owner names (same pattern as listInvitesController) ───
         const ownersById = new Map<string, IUserIdNameEmail>();

         if (sessions.length > 0) {
            /* Keyed by hex: a Set of ObjectId instances compares identity, not value, and would never deduplicate. */
            const uniqueUserIds = [
               ...new Map(
                  sessions.map(s => [s.userId.toHexString(), s.userId])
               ).values(),
            ];

            const ownersRaw = await getUserCollection()
               .find<IUserIdNameEmail>(
                  {
                     _id: { $in: uniqueUserIds },
                  } satisfies StrictMongoFilter<IUserDocument>,
                  {
                     projection: USER_ID_NAME_EMAIL_PROJECTION,
                  } satisfies StrictFindOptions<IUserIdNameEmail>
               )
               .toArray();

            const decodedOwners = Schema.decodeUnknownEither(
               UserIdNameEmailArrayValidator
            )(ownersRaw);

            if (Either.isLeft(decodedOwners)) {
               throw new Error(
                  `Stored users failed validation in the session list.`,
                  { cause: decodedOwners.left }
               );
            }

            for (const owner of decodedOwners.right) {
               ownersById.set(owner._id.toHexString(), owner);
            }
         }

         /* Field-by-field on purpose: if a field is ever added to ISessionAdminView, this stops compiling until it is mapped. Drift is impossible. */
         const result: ISessionAdminListItem[] = sessions.map(s => ({
            _id: s._id,
            userId: s.userId,
            ipAddress: s.ipAddress,
            userAgent: s.userAgent,
            createdAt: s.createdAt,
            expiresAt: s.expiresAt,
            lastActiveAt: s.rotatedAt,
            isCurrent: s._id.equals(currentSessionId),
            user: ownersById.get(s.userId.toHexString()) ?? null,
         }));

         return void res
            .status(200)
            .json(buildListSessionsResponse(result, hasNextPage, limit));
      }

      const rowsRaw = await sessionCollection
         .find<ISessionSelfView>(filter, {
            projection: SESSION_SELF_VIEW_PROJECTION,
            sort: { _id: -1 },
            limit: limit + 1,
            maxTimeMS: LIST_QUERY_MAX_TIME_MS,
         } satisfies StrictFindOptions<ISessionDocument>)
         .toArray();

      const { items, hasNextPage } = takePage(rowsRaw, limit);
      const decoded = Schema.decodeUnknownEither(SessionSelfViewArrayValidator)(
         items
      );
      if (Either.isLeft(decoded)) {
         throw new Error(`Stored sessions failed validation in the list.`, {
            cause: decoded.left,
         });
      }

      const result: ISessionSelfListItem[] = decoded.right.map(s => ({
         _id: s._id,
         ipAddress: s.ipAddress,
         userAgent: s.userAgent,
         createdAt: s.createdAt,
         expiresAt: s.expiresAt,
         isCurrent: s._id.equals(currentSessionId),
         lastActiveAt: s.rotatedAt,
      }));

      return void res
         .status(200)
         .json(buildListSessionsResponse(result, hasNextPage, limit));
   } catch (err) {
      next(err);
   }
}
