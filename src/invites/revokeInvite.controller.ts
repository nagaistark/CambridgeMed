import type { Request, NextFunction } from 'express';
import { getInviteCollection } from '@models/Invite_v3.model.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import { ObjectId } from 'mongodb';

/* Request<P> threads P into req.params, narrowing each value from `string | string[]` down to plain `string`. */
type RevokeInviteParams = { id: string };

export async function revokeInviteController(
   req: Request<RevokeInviteParams>,
   res: AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub, role } = res.locals.authenticatedUser;
      const { id } = req.params;

      // ── Validate the ID format before touching the database ────────────────────
      /* ObjectId.isValid catches malformed strings early. */
      if (!ObjectId.isValid(id)) {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `Invalid invite ID.`,
                  requestId
               )
            );
      }

      const inviteCollection = getInviteCollection();

      // ── Fetch the invite ───────────────────────────────────────────────────────
      const invite = await inviteCollection.findOne(new ObjectId(id));
      if (!invite) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `Invite not found.`, requestId)
            );
      }

      // ── Accepted invites are immutable — refuse revocation ─────────────────────
      if (invite.usedAt !== null) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  `This invite has already been accepted and cannot be revoked.`,
                  requestId
               )
            );
      }

      // ── Ownership check ────────────────────────────────────────────────────────
      /* The superadmin can revoke any invite regardless of who issued it. Any other canIssueInvites user may only revoke their own. */
      const isSuperAdmin: boolean = role === 'superadmin';
      const isIssuer: boolean = invite.issuedBy.toString() === sub;

      if (!isSuperAdmin && !isIssuer) {
         return void res
            .status(403)
            .json(
               createErrorResponse(
                  'FORBIDDEN',
                  `You can only revoke invites that you issued.`,
                  requestId
               )
            );
      }

      // ── Hard delete ────────────────────────────────────────────────────────────
      await inviteCollection.deleteOne({ _id: invite._id });

      return void res.status(200).json({
         success: true,
         message: `Invite revoked successfully`,
      });
   } catch (err) {
      next(err);
   }
}
