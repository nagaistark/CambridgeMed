import type { Request, NextFunction } from 'express';
import mongoose from 'mongoose';
import { getUserModel } from '@models/User.model.ts';
import { getSessionModel } from '@models/Session.model.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import { TypedResponse } from '@utils/typedResponse.ts';
import type { SetIsActiveBody } from '@users/User.schemas.ts';

type ToggleIsActiveParams = { id: string };

export async function toggleIsActiveController(
   req: Request<ToggleIsActiveParams>,
   res: TypedResponse<SetIsActiveBody>,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { role } = res.locals.authenticatedUser!;
      const { id } = req.params;
      const { isActive } = res.locals.validatedBody;

      // ── Authorisation ──────────────────────────────────────────────────────────
      /* isActive is exclusively a superadmin concern — deactivation covers contract termination, security incidents, and leave of absence. No other role has a legitimate reason to flip this flag. */
      if (role !== 'superadmin') {
         return void res
            .status(403)
            .json(
               createErrorResponse(
                  'FORBIDDEN',
                  `Only the superadmin can activate or deactivate accounts.`,
                  undefined,
                  requestId
               )
            );
      }

      if (!mongoose.Types.ObjectId.isValid(id)) {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `Invalid user ID.`,
                  undefined,
                  requestId
               )
            );
      }

      const User = getUserModel();
      const targetUser = await User.findById(id).lean();

      if (!targetUser) {
         return void res
            .status(404)
            .json(
               createErrorResponse(
                  'NOT_FOUND',
                  `User not found.`,
                  undefined,
                  requestId
               )
            );
      }

      // ── Superadmin self-deactivation guard ─────────────────────────────────────
      /* The superadmin deactivating themselves would immediately lock the only administrative account out of the system with no recovery path short of a direct database intervention. This is almost certainly a mistake. */
      if (targetUser.role === 'superadmin') {
         return void res
            .status(403)
            .json(
               createErrorResponse(
                  'FORBIDDEN',
                  `The superadmin account cannot be deactivated.`,
                  undefined,
                  requestId
               )
            );
      }

      // ── No-op guard ────────────────────────────────────────────────────────────
      if (targetUser.isActive === isActive) {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `This account is already ${isActive ? 'active' : 'inactive'}.`,
                  undefined,
                  requestId
               )
            );
      }

      await User.updateOne(
         { _id: targetUser._id },
         { $set: { isActive } },
         { runValidators: true }
      );

      // ── Kill sessions on deactivation ──────────────────────────────────────────
      /* Deactivating an account must immediately invalidate all live sessions. Without this, a deactivated user holding a valid refresh token could continue rotating for up to a week. The loginController and meController check isActive, which blocks access token use — but a session kill here removes the refresh token lifeline entirely. On reactivation, no session work is needed: the user simply logs in fresh, which creates a new session. */
      if (!isActive) {
         await getSessionModel().deleteMany({ userId: targetUser._id });
      }

      return void res.status(200).json({
         success: true,
         message: `Account ${isActive ? 'activated' : 'deactivated'} successfully.`,
      });
   } catch (err) {
      next(err);
   }
}
