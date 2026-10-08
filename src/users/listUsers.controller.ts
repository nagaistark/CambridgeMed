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
import type { EmptyOr } from '@utils/helperTypes.ts';

export async function listUsersController(
   _req: Request,
   res: AuthenticatedResponse &
      ResponseWithValidatedQuery<IObjectIdCursorPagination>,
   next: NextFunction
): Promise<void> {
   try {
      const { role } = res.locals.authenticatedUser;
      const { cursor, limit } = res.locals.validatedQuery;

      const userCollection = getUserCollection();

      /* The only place `_id` and `$lt` are written for this fragment. The parameter type is derived from the pagination schema, not restated. */
      const buildCursorFilter = (
         cursor: NonNullable<IObjectIdCursorPagination['cursor']>
      ) =>
         ({ _id: { $lt: cursor } }) satisfies StrictMongoFilter<IUserDocument>;

      const cursorFilter: EmptyOr<ReturnType<typeof buildCursorFilter>> =
         cursor === undefined ? {} : buildCursorFilter(cursor);

      const filter = { ...buildUserVisibilityFilter(role), ...cursorFilter };

      const pageOptions = {
         sort: { _id: -1 },
         limit: limit + 1, // the +1 is the "is there a next page?" probe
         maxTimeMS: 5_000,
      } satisfies StrictFindOptions<IUserDocument>;

      if (role === 'superadmin') {
         const safeUsersRaw = await userCollection
            .find<ISafeUser>(filter, {
               ...pageOptions,
               projection: SAFE_USER_PROJECTION,
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
            ...pageOptions,
            projection: PUBLIC_USER_PROJECTION,
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
