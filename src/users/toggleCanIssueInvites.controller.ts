import type { Request, NextFunction } from 'express';
import {
   getUserCollection,
   ISafeUser,
   IUserDocument,
   SafeUserValidator,
} from '@models/User_v3.model.ts';
import { createErrorResponse, makeAppError } from '../errorHandlers.ts';
import {
   AuthenticatedResponse,
   ResponseWithValidatedBody,
   ResponseWithValidatedParams,
} from '@utils/customTypedResponses.ts';
import type { SetCanIssueInvitesBody } from '@users/User_v3.schemas.ts';
import { Permissions } from '@ssot/permissions_constants.ts';
import { ObjectId } from 'mongodb';
import { IMongoIdParam } from '@utils/effectSchemaReusables.ts';
import {
   StrictFindOptions,
   StrictMongoFilter,
   StrictUpdate,
} from '@utils/pathFinder_v3.ts';
import { Either, Schema } from 'effect';
import { SAFE_USER_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';

export async function toggleCanIssueInvitesController(
   _req: Request,
   res: ResponseWithValidatedBody<SetCanIssueInvitesBody> &
      ResponseWithValidatedParams<IMongoIdParam> &
      AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub, role } = res.locals.authenticatedUser;
      const { id } = res.locals.validatedParams;
      const { canIssueInvites } = res.locals.validatedBody;

      const userCollection = getUserCollection();
      const targetUserRaw = await userCollection.findOne<ISafeUser>(
         {
            _id: new ObjectId(id),
         } satisfies StrictMongoFilter<IUserDocument>,
         {
            projection: SAFE_USER_PROJECTION,
         } satisfies StrictFindOptions<ISafeUser>
      );

      if (!targetUserRaw) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `User not found.`, requestId)
            );
      }

      const decodedTargetUser =
         Schema.decodeUnknownEither(SafeUserValidator)(targetUserRaw);

      if (Either.isLeft(decodedTargetUser)) {
         throw decodedTargetUser.left;
      }

      const validatedTargetUser = decodedTargetUser.right;

      // ── Authorisation ──────────────────────────────────────────────────────────
      /* Two principals may toggle this privilege:
         1. The superadmin — unrestricted access to all users.
         2. The user who issued the original invite to this person (invitedBy).
      
      Crucially, the inviter retains this authority even if their *own* canIssueInvites has since been revoked — the invitedBy relationship is permanent and represents a lasting accountability link, not a delegated permission that expires when the delegator's own is removed. The chain is exactly one level deep: User 1 can toggle User 2 (if User 1 invited User 2), but NOT User 3 even if User 2 invited User 3. */
      const isSuperAdmin = role === 'superadmin';
      const isDirectInviter =
         validatedTargetUser.invitedBy !== null &&
         validatedTargetUser.invitedBy.toString() === sub;

      if (!isSuperAdmin && !isDirectInviter) {
         return void res
            .status(403)
            .json(
               createErrorResponse(
                  'FORBIDDEN',
                  `You do not have permission to modify this user's invite privileges.`,
                  requestId
               )
            );
      }

      // ── No-op guard ────────────────────────────────────────────────────────────
      /* Reject if the submitted value matches what's already stored. This prevents burning a database write on a meaningless operation, and gives the caller clear feedback that the request had no effect. */

      const currentlyHas =
         (validatedTargetUser.permissions & Permissions.ISSUE_INVITES) !== 0;

      if (currentlyHas === canIssueInvites) {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `This user's invite privilege is already set to ${canIssueInvites}.`,
                  requestId
               )
            );
      }

      const newPermissions = canIssueInvites
         ? validatedTargetUser.permissions | Permissions.ISSUE_INVITES
         : validatedTargetUser.permissions & ~Permissions.ISSUE_INVITES;

      const updateResult = await userCollection.updateOne(
         {
            _id: validatedTargetUser._id,
         } satisfies StrictMongoFilter<IUserDocument>,
         {
            $set: { permissions: newPermissions },
         } satisfies StrictUpdate<IUserDocument>
      );

      if (updateResult.matchedCount === 0) {
         throw makeAppError(
            'CONCURRENCY_ERROR',
            409,
            'CONFLICT',
            `User ${id} not found...`
         );
      }

      return void res.status(200).json({
         success: true,
         message: `Invite privilege ${canIssueInvites ? 'granted' : 'revoked'} successfully.`,
      });
   } catch (err) {
      next(err);
   }
}
