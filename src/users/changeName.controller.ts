import type { Request, NextFunction } from 'express';
import { Either, Schema } from 'effect';
import {
   getUserCollection,
   IUserDocument,
   IUserNameEmail,
   UserNameEmailValidator,
} from '@models/User_v3.model.ts';
import { createErrorResponse, makeAppError } from '../errorHandlers.ts';
import {
   AuthenticatedResponse,
   ResponseWithValidatedBody,
} from '@utils/customTypedResponses.ts';
import type { ChangeNameBody } from '@users/User_v3.schemas.ts';
import { NAME_CHANGE_CAP } from '@ssot/user_change_constants.ts';
import { USER_NAME_EMAIL_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import { ObjectId } from 'mongodb';
import {
   StrictFindOneOptions,
   StrictMongoFilter,
   StrictUpdate,
} from '@utils/pathFinder_v3.ts';

export async function changeNameController(
   _req: Request,
   res: ResponseWithValidatedBody<ChangeNameBody> & AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub } = res.locals.authenticatedUser;
      const { firstName, lastName } = res.locals.validatedBody;

      const userCollection = getUserCollection();
      const userRaw = await userCollection.findOne<IUserNameEmail>(
         {
            _id: new ObjectId(sub),
         } satisfies StrictMongoFilter<IUserDocument>,
         {
            projection: USER_NAME_EMAIL_PROJECTION,
         } satisfies StrictFindOneOptions<IUserNameEmail>
      );

      if (!userRaw) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `Account not found.`, requestId)
            );
      }

      const decodedUser = Schema.decodeUnknownEither(UserNameEmailValidator)(
         userRaw
      );
      if (Either.isLeft(decodedUser)) {
         throw decodedUser.left;
      }

      const validatedUser = decodedUser.right;

      // ── Cap check ──────────────────────────────────────────────────────────────
      if (validatedUser.nameChangesUsed >= NAME_CHANGE_CAP) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  `You have reached the maximum number of name changes (${NAME_CHANGE_CAP}). Please contact an administrator.`,
                  requestId
               )
            );
      }

      // ── No-op guard ────────────────────────────────────────────────────────────
      /* If the submitted values are identical to what's already stored, we reject early to avoid burning a name-change credit for a pointless write. */
      const newFirstName = firstName ?? validatedUser.firstName;
      const newLastName = lastName ?? validatedUser.lastName;

      if (
         newFirstName === validatedUser.firstName &&
         newLastName === validatedUser.lastName
      ) {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `The submitted name is identical to your current name.`,
                  requestId
               )
            );
      }

      // ── Atomic archive-and-update ──────────────────────────────────────────────
      /* We always archive the *full name pair* (firstName + lastName together), even when only one field changes. $push, $set, and $inc execute in a single findAndModify round-trip. There is no window where the document is partially updated. */
      const updateFields: Partial<{ firstName: string; lastName: string }> = {};
      if (firstName !== undefined) updateFields.firstName = firstName;
      if (lastName !== undefined) updateFields.lastName = lastName;

      const updateResult = await userCollection.updateOne(
         { _id: new ObjectId(sub) } satisfies StrictMongoFilter<IUserDocument>,
         {
            $set: updateFields,
            $push: {
               previousNames: {
                  firstName: validatedUser.firstName,
                  lastName: validatedUser.lastName,
                  archivedAt: new Date(),
               },
            },
            $inc: { nameChangesUsed: 1 },
         } satisfies StrictUpdate<IUserDocument>
      );

      if (updateResult.matchedCount === 0) {
         throw makeAppError(
            'CONCURRENCY_ERROR',
            409,
            'CONFLICT',
            `User ${sub} not found...`
         );
      }

      return void res.status(200).json({
         success: true,
         message: `Name updated successfully.`,
      });
   } catch (err) {
      next(err);
   }
}
