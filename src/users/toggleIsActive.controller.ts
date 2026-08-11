import type { Request, NextFunction } from 'express';
import { getUserCollection, IUserDocument } from '@models/User_v3.model.ts';
import {
   getSessionCollection,
   ISessionDocument,
} from '@models/Session_v3.model.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import {
   AuthenticatedResponse,
   ResponseWithValidatedBody,
   ResponseWithValidatedParams,
} from '@utils/customTypedResponses.ts';
import type { SetIsActiveBody } from '@users/User_v3.schemas.ts';
import { ObjectId } from 'mongodb';
import { IMongoIdParam } from '@utils/effectSchemaReusables.ts';
import { StrictMongoFilter, StrictUpdate } from '@utils/pathFinder_v3.ts';

export async function toggleIsActiveController(
   _req: Request,
   res: ResponseWithValidatedBody<SetIsActiveBody> &
      ResponseWithValidatedParams<IMongoIdParam> &
      AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { role } = res.locals.authenticatedUser;
      const { id } = res.locals.validatedParams;
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
                  requestId
               )
            );
      }

      const userCollection = getUserCollection();
      const targetUser = await userCollection.findOne({
         _id: new ObjectId(id),
      } satisfies StrictMongoFilter<IUserDocument>);

      if (!targetUser) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `User not found.`, requestId)
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
                  requestId
               )
            );
      }

      await userCollection.updateOne(
         { _id: targetUser._id } satisfies StrictMongoFilter<IUserDocument>,
         { $set: { isActive } } satisfies StrictUpdate<IUserDocument>
      );

      // ── Kill sessions on deactivation ──────────────────────────────────────────
      /* Deactivating an account must immediately invalidate all live sessions. Without this, a deactivated user holding a valid refresh token could continue rotating for up to a week. The loginController and meController check isActive, which blocks access token use — but a session kill here removes the refresh token lifeline entirely. On reactivation, no session work is needed: the user simply logs in fresh, which creates a new session. */
      if (!isActive) {
         await getSessionCollection().deleteMany({
            userId: targetUser._id,
         } satisfies StrictMongoFilter<ISessionDocument>);
      }

      return void res.status(200).json({
         success: true,
         message: `Account ${isActive ? 'activated' : 'deactivated'} successfully.`,
      });
   } catch (err) {
      next(err);
   }
}
