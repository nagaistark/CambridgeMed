import type { Request, NextFunction } from 'express';
import {
   getUserCollection,
   IPublicUser,
   ISafeUser,
   IUserDocument,
   PublicUserArrayValidator,
   SafeUserArrayValidator,
} from '@models/User_v3.model.ts';
import {
   SAFE_USER_PROJECTION,
   PUBLIC_USER_PROJECTION,
} from '@ssot/user_mongodb_query_projection_constants.ts';
import { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import { StrictFindOptions, StrictMongoFilter } from '@utils/pathFinder_v3.ts';
import { Either, Schema } from 'effect';
import { buildListUsersResponse } from '@utils/buildResponses.ts';

export async function listUsersController(
   _req: Request,
   res: AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const { role } = res.locals.authenticatedUser;
      const isSuperAdmin = role === 'superadmin';
      const userCollection = getUserCollection();

      if (isSuperAdmin) {
         const safeUsersRaw = await userCollection
            .find<ISafeUser>({}, {
               projection: SAFE_USER_PROJECTION,
            } satisfies StrictFindOptions<IUserDocument>)
            .toArray();

         const decodedUsers = Schema.decodeUnknownEither(
            SafeUserArrayValidator
         )(safeUsersRaw);
         if (Either.isLeft(decodedUsers)) {
            throw decodedUsers.left;
         }

         return void res
            .status(200)
            .json(buildListUsersResponse(decodedUsers.right));
      }

      /* Non-superadmin users see the minimal public shape: name, email, role, and permissions. */
      const publicUsersRaw = await userCollection
         .find<IPublicUser>(
            {
               invitedBy: { $exists: true },
            } satisfies StrictMongoFilter<IUserDocument>,
            {
               projection: PUBLIC_USER_PROJECTION,
            } satisfies StrictFindOptions<IPublicUser>
         )
         .toArray();

      const decodedPublicUsers = Schema.decodeUnknownEither(
         PublicUserArrayValidator
      )(publicUsersRaw);
      if (Either.isLeft(decodedPublicUsers)) {
         throw decodedPublicUsers.left;
      }

      return void res
         .status(200)
         .json(buildListUsersResponse(decodedPublicUsers.right));
   } catch (err) {
      next(err);
   }
}
