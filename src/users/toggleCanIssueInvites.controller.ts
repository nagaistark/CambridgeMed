import type { Request, NextFunction } from 'express';
import { getUserCollection } from '@models/User_v3.model.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import {
   AuthenticatedResponse,
   ResponseWithValidatedBody,
} from '@utils/customTypedResponses.ts';
import type { SetCanIssueInvitesBody } from '@users/User_v3.schemas.ts';
import { Permissions } from '@ssot/permissions_constants.ts';
import { ObjectId } from 'mongodb';

type ToggleCanIssueInvitesParams = { id: string };

export async function toggleCanIssueInvitesController(
   req: Request<ToggleCanIssueInvitesParams>,
   res: ResponseWithValidatedBody<SetCanIssueInvitesBody> &
      AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub, role } = res.locals.authenticatedUser;
      const { id } = req.params;
      const { canIssueInvites } = res.locals.validatedBody;

      if (!ObjectId.isValid(id)) {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `Invalid user ID.`,
                  requestId
               )
            );
      }

      const userCollection = getUserCollection();
      const targetUser = await userCollection.findOne(new ObjectId(id));

      if (!targetUser) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `User not found.`, requestId)
            );
      }

      // ── Authorisation ──────────────────────────────────────────────────────────
      /* Two principals may toggle this privilege:
         1. The superadmin — unrestricted access to all users.
         2. The user who issued the original invite to this person (invitedBy).
      
      Crucially, the inviter retains this authority even if their *own* canIssueInvites has since been revoked — the invitedBy relationship is permanent and represents a lasting accountability link, not a delegated permission that expires when the delegator's own is removed. The chain is exactly one level deep: User 1 can toggle User 2 (if User 1 invited User 2), but NOT User 3 even if User 2 invited User 3. */
      const isSuperAdmin = role === 'superadmin';
      const isDirectInviter =
         targetUser.invitedBy !== undefined &&
         targetUser.invitedBy.toString() === sub;

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
         (targetUser.permissions & Permissions.ISSUE_INVITES) !== 0;

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
         ? targetUser.permissions | Permissions.ISSUE_INVITES
         : targetUser.permissions & ~Permissions.ISSUE_INVITES;

      await userCollection.updateOne(
         { _id: targetUser._id },
         { $set: { permissions: newPermissions } }
      );

      return void res.status(200).json({
         success: true,
         message: `Invite privilege ${canIssueInvites ? 'granted' : 'revoked'} successfully.`,
      });
   } catch (err) {
      next(err);
   }
}
