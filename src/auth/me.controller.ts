import type { Request, NextFunction } from 'express';
import { Either, Schema } from 'effect';
import {
   getUserCollection,
   SafeUserValidator,
   type IUserDocument,
   type ISafeUser,
} from '@models/User_v3.model.ts';
import type { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import { buildMeResponse } from '@utils/buildResponses.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import { SAFE_USER_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import { ObjectId } from 'mongodb';
import type {
   StrictFindOneOptions,
   StrictMongoFilter,
} from '@utils/pathFinder_v3.ts';
import { loadEmailChangeStatus } from '@users/loadEmailChangeStatus.ts';

export async function meController(
   _req: Request,
   res: AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub } = res.locals.authenticatedUser;
      const userId = new ObjectId(sub);

      /* Independent reads, run in parallel (same idea as requireLiveSession). */
      const [userRaw, emailChange] = await Promise.all([
         getUserCollection().findOne<ISafeUser>(
            { _id: userId } satisfies StrictMongoFilter<IUserDocument>,
            {
               projection: SAFE_USER_PROJECTION,
            } satisfies StrictFindOneOptions<ISafeUser>
         ),
         loadEmailChangeStatus(userId, new Date()),
      ]);

      if (userRaw === null) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `Account not found.`, requestId)
            );
      }

      const decodedUser =
         Schema.decodeUnknownEither(SafeUserValidator)(userRaw);
      if (Either.isLeft(decodedUser)) {
         throw new Error(`Stored user failed validation in /me.`, {
            cause: decodedUser.left,
         });
      }
      const user = decodedUser.right;

      return void res
         .status(200)
         .json(buildMeResponse('Session valid.', user, emailChange));
   } catch (err) {
      next(err);
   }
}
