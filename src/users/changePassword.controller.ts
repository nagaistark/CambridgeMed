import type { Request, NextFunction } from 'express';

import {
   getUserCollection,
   IUserDocument,
   IUserIdPasswordHash,
   UserIdPasswordHashValidator,
} from '@models/User_v3.model.ts';
import {
   getSessionCollection,
   ISessionDocument,
} from '@models/Session_v3.model.ts';
import { hashPassword, verifyPassword } from '@utils/hashAndVerify.ts';
import { clearAuthCookies } from '@utils/tokenUtils.ts';
import { createErrorResponse, makeAppError } from '../errorHandlers.ts';
import { DatabaseManager } from '../mongoDBConnect.ts';
import {
   AuthenticatedResponse,
   ResponseWithValidatedBody,
} from '@utils/customTypedResponses.ts';
import type { ChangePasswordBody } from '@users/User_v3.schemas.ts';
import { ObjectId } from 'mongodb';
import {
   StrictFindOneOptions,
   StrictMongoFilter,
   StrictUpdate,
} from '@utils/pathFinder_v3.ts';
import { Either, Schema } from 'effect';
import logger from '../logger.ts';
import { USER_ID_PASSWORDHASH_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';

export async function changePasswordController(
   _req: Request,
   res: ResponseWithValidatedBody<ChangePasswordBody> & AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub } = res.locals.authenticatedUser;
      const { currentPassword, newPassword } = res.locals.validatedBody;

      const userCollection = getUserCollection();
      const userRaw = await userCollection.findOne<IUserIdPasswordHash>(
         {
            _id: new ObjectId(sub),
         } satisfies StrictMongoFilter<IUserDocument>,
         {
            projection: USER_ID_PASSWORDHASH_PROJECTION,
         } satisfies StrictFindOneOptions<IUserIdPasswordHash>
      );

      /* Should never be null (the user just passed authenticate), but we guard defensively rather than using a non-null assertion. */
      if (!userRaw) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `Account not found.`, requestId)
            );
      }

      // ── Step 1: Validate the fetched document against the schema ───────────────
      const decodedUser = Schema.decodeUnknownEither(
         UserIdPasswordHashValidator
      )(userRaw);
      if (Either.isLeft(decodedUser)) {
         throw decodedUser.left;
      }

      // ── Use the validated invite document from now on ──────────────────────────
      const validatedUser = decodedUser.right;

      // ── Step 2: verify the current password ────────────────────────────────────
      const isCurrentValid = await verifyPassword(
         validatedUser.passwordHash,
         currentPassword
      );

      if (!isCurrentValid) {
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `Current password is incorrect.`,
                  requestId
               )
            );
      }

      // ── Step 3: hash the new password before opening the transaction ───────────
      /* Hashing optimistically up front. If anything downstream fails, the hash is discarded. The same-password case is already caught by the cross-field validation in ChangePasswordSchema. No duplicate `verifyPassword` call is needed here. */
      const newPasswordHash = await hashPassword(newPassword);

      // ── Step 4: atomic update + session destruction ────────────────────────────
      /* Transaction because the two writes must succeed OR fail as a unit. */
      const authConnection = DatabaseManager.getInstance().auth.client;
      if (!authConnection) {
         throw new Error(
            `Auth database connection unavailable during password change.`
         );
      }

      const session = authConnection.startSession();
      try {
         await session.withTransaction(async () => {
            const updateResult = await userCollection.updateOne(
               {
                  _id: new ObjectId(sub),
               } satisfies StrictMongoFilter<IUserDocument>,
               {
                  $set: { passwordHash: newPasswordHash },
               } satisfies StrictUpdate<IUserDocument>,
               { session }
            );

            if (updateResult.matchedCount === 0) {
               throw makeAppError(
                  'CONCURRENCY_ERROR',
                  409,
                  'CONFLICT',
                  `User ${sub} not found...`
               );
            }

            const deleteResult = await getSessionCollection().deleteMany(
               {
                  userId: new ObjectId(sub),
               } satisfies StrictMongoFilter<ISessionDocument>,
               { session }
            );

            logger.info(
               `Password changed and ${deleteResult.deletedCount} session(s) invalidated.`,
               { userId: sub, requestId }
            );
         });
      } finally {
         await session.endSession();
      }

      clearAuthCookies(res);

      return void res.status(200).json({
         success: true,
         message: `Password changed successfully. You have been logged out of all devices.`,
      });
   } catch (err) {
      next(err);
   }
}
