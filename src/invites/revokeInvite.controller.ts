import type { Request, Response, NextFunction } from 'express';
import mongoose from 'mongoose';
import { getInviteModel } from '@models/Invite.model.ts';
import { createErrorResponse } from 'errorHandlers.ts';

/* Request<P> threads P into req.params, narrowing each value from `string | string[]` down to plain `string`. */
type RevokeInviteParams = { id: string };

export async function revokeInviteController(
   req: Request<RevokeInviteParams>,
   res: Response,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub, role } = res.locals.authenticatedUser!;
      const { id } = req.params;

      // ── Validate the ID format before touching the database ────────────────────
      /* mongoose.Types.ObjectId.isValid catches malformed strings early and prevents a Mongoose CastError from bubbling up as an unexpected 500. */
      if (!mongoose.Types.ObjectId.isValid(id)) {
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

      const Invite = getInviteModel();

      // ── Fetch the invite ───────────────────────────────────────────────────────
      const invite = await Invite.findById(id).lean();
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
      await Invite.deleteOne({ _id: invite._id });

      return void res.status(200).json({
         success: true,
         message: `Invite revoked successfully`,
      });
   } catch (err) {
      next(err);
   }
}
