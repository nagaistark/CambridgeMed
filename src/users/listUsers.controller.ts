import type { Request, NextFunction } from 'express';
import {
   getUserCollection,
   type IPublicUser,
   type ISafeUser,
   type IUserDocument,
   PublicUserArrayValidator,
   SafeUserArrayValidator,
} from '@models/User_v3.model.ts';
import {
   SAFE_USER_PROJECTION,
   PUBLIC_USER_PROJECTION,
} from '@ssot/user_mongodb_query_projection_constants.ts';
import { LIST_QUERY_MAX_TIME_MS } from '@ssot/pagination_constants.ts';
import type {
   AuthenticatedResponse,
   ResponseWithValidatedQuery,
} from '@utils/customTypedResponses.ts';
import type {
   StrictFindOptions,
   StrictMongoFilter,
} from '@utils/pathFinder_v3.ts';
import { Either, Schema } from 'effect';
import { buildListUsersResponse } from '@utils/buildResponses.ts';
import type { IObjectIdCursorPagination } from '@utils/effectSchemaReusables.ts';
import { buildUserVisibilityFilter } from '@utils/userVisibility.ts';
import { takePage } from '@utils/cursorPagination.ts';

export async function listUsersController(
   _req: Request,
   res: AuthenticatedResponse &
      ResponseWithValidatedQuery<IObjectIdCursorPagination>,
   next: NextFunction
): Promise<void> {
   try {
      const { role } = res.locals.authenticatedUser;
      const { cursor, limit } = res.locals.validatedQuery;

      /* Every clause must hold; none can overwrite another. `{}` is the neutral "no constraint" element. */
      const filter = {
         $and: [
            buildUserVisibilityFilter(role),
            cursor === undefined ? {} : { _id: { $lt: cursor } },
         ],
      } satisfies StrictMongoFilter<IUserDocument>;

      const userCollection = getUserCollection();

      if (role === 'superadmin') {
         const safeUsersRaw = await userCollection
            .find<ISafeUser>(filter, {
               projection: SAFE_USER_PROJECTION,
               sort: { _id: -1 },
               limit: limit + 1, // the +1 is the "is there a next page?" probe
               maxTimeMS: LIST_QUERY_MAX_TIME_MS,
            } satisfies StrictFindOptions<IUserDocument>)
            .toArray();

         const { items, hasNextPage } = takePage(safeUsersRaw, limit);
         const decoded = Schema.decodeUnknownEither(SafeUserArrayValidator)(
            items
         );
         if (Either.isLeft(decoded)) {
            throw decoded.left;
         }

         return void res
            .status(200)
            .json(buildListUsersResponse(decoded.right, hasNextPage, limit));
      }

      const publicUsersRaw = await userCollection
         .find<IPublicUser>(filter, {
            projection: PUBLIC_USER_PROJECTION,
            sort: { _id: -1 },
            limit: limit + 1,
            maxTimeMS: LIST_QUERY_MAX_TIME_MS,
         } satisfies StrictFindOptions<IUserDocument>)
         .toArray();

      const { items, hasNextPage } = takePage(publicUsersRaw, limit);
      const decoded = Schema.decodeUnknownEither(PublicUserArrayValidator)(
         items
      );
      if (Either.isLeft(decoded)) {
         throw decoded.left;
      }

      return void res
         .status(200)
         .json(buildListUsersResponse(decoded.right, hasNextPage, limit));
   } catch (err) {
      next(err);
   }
}
