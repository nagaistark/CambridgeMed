import type { Request, NextFunction } from 'express';
import {
   getUserCollection,
   IPublicUser,
   ISafeUser,
   IUserDocument,
   PublicUserValidator,
   SafeUserValidator,
} from '@models/User_v3.model.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import {
   SAFE_USER_PROJECTION,
   PUBLIC_USER_PROJECTION,
} from '@ssot/user_mongodb_query_projection_constants.ts';
import {
   AuthenticatedResponse,
   ResponseWithValidatedParams,
} from '@utils/customTypedResponses.ts';
import { IMongoIdParam } from '@utils/effectSchemaReusables.ts';
import {
   StrictFindOneOptions,
   StrictMongoFilter,
} from '@utils/pathFinder_v3.ts';
import { Either, Schema } from 'effect';

export async function getUserController(
   _req: Request,
   res: AuthenticatedResponse & ResponseWithValidatedParams<IMongoIdParam>,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { role } = res.locals.authenticatedUser;
      const { id } = res.locals.validatedParams;

      const isSuperAdmin = role === 'superadmin';
      const userCollection = getUserCollection();

      if (isSuperAdmin) {
         const safeUserRaw = await userCollection.findOne<ISafeUser>(
            { _id: id } satisfies StrictMongoFilter<IUserDocument>,
            {
               projection: SAFE_USER_PROJECTION,
            } satisfies StrictFindOneOptions<IUserDocument>
         );
         if (!safeUserRaw) {
            return void res
               .status(404)
               .json(
                  createErrorResponse('NOT_FOUND', `User not found.`, requestId)
               );
         }

         const decodedSafeUser =
            Schema.decodeUnknownEither(SafeUserValidator)(safeUserRaw);
         if (Either.isLeft(decodedSafeUser)) {
            throw decodedSafeUser.left;
         }

         return void res
            .status(200)
            .json({ success: true, user: decodedSafeUser.right });
      }

      const publicUserRaw = await userCollection.findOne<IPublicUser>(
         { _id: id } satisfies StrictMongoFilter<IUserDocument>,
         {
            projection: PUBLIC_USER_PROJECTION,
         } satisfies StrictFindOneOptions<IUserDocument>
      );
      if (!publicUserRaw) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `User not found.`, requestId)
            );
      }

      const decodedPublicUser =
         Schema.decodeUnknownEither(PublicUserValidator)(publicUserRaw);
      if (Either.isLeft(decodedPublicUser)) {
         throw decodedPublicUser.left;
      }

      return void res
         .status(200)
         .json({ success: true, user: decodedPublicUser.right });
   } catch (err) {
      next(err);
   }
}
