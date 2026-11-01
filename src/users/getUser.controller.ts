import type { Request, NextFunction } from 'express';
import {
   getUserCollection,
   type IPublicUser,
   type ISafeUser,
   type IUserDocument,
   PublicUserValidator,
   SafeUserValidator,
} from '@models/User_v3.model.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import {
   SAFE_USER_PROJECTION,
   PUBLIC_USER_PROJECTION,
} from '@ssot/user_mongodb_query_projection_constants.ts';
import type {
   AuthenticatedResponse,
   ResponseWithValidatedParams,
} from '@utils/customTypedResponses.ts';
import type { IMongoIdParam } from '@utils/effectSchemaReusables.ts';
import type {
   StrictFindOneOptions,
   StrictMongoFilter,
} from '@utils/pathFinder_v3.ts';
import { buildGetUserResponse } from '@utils/buildResponses.ts';
import { buildUserVisibilityFilter } from '@utils/userVisibility.ts';
import { decodeStored } from '@/utils/decodeStored.ts';

export async function getUserController(
   _req: Request,
   res: AuthenticatedResponse & ResponseWithValidatedParams<IMongoIdParam>,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { role } = res.locals.authenticatedUser;
      const { id } = res.locals.validatedParams;

      /* The same visibility policy as the list endpoint. A user the caller may not see is indistinguishable from one that doesn't exist. */
      const filter = {
         $and: [buildUserVisibilityFilter(role), { _id: id }],
      } satisfies StrictMongoFilter<IUserDocument>;

      const userCollection = getUserCollection();

      if (role === 'superadmin') {
         const safeUserRaw = await userCollection.findOne<ISafeUser>(filter, {
            projection: SAFE_USER_PROJECTION,
         } satisfies StrictFindOneOptions<IUserDocument>);

         if (!safeUserRaw) {
            return void res
               .status(404)
               .json(
                  createErrorResponse('NOT_FOUND', `User not found.`, requestId)
               );
         }

         const validatedSafeUser = decodeStored(
            SafeUserValidator,
            safeUserRaw,
            'user (safe view)'
         );

         return void res
            .status(200)
            .json(buildGetUserResponse(validatedSafeUser));
      }

      const publicUserRaw = await userCollection.findOne<IPublicUser>(filter, {
         projection: PUBLIC_USER_PROJECTION,
      } satisfies StrictFindOneOptions<IUserDocument>);

      if (!publicUserRaw) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `User not found.`, requestId)
            );
      }

      const validatedPublicUser = decodeStored(
         PublicUserValidator,
         publicUserRaw,
         'user (public view)'
      );

      return void res
         .status(200)
         .json(buildGetUserResponse(validatedPublicUser));
   } catch (err) {
      next(err);
   }
}
