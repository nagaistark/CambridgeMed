import type { Request, NextFunction } from 'express';
import {
   getInviteCollection,
   type IInviteDocumentRead,
} from '@models/Invite_v3.model.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import type {
   AuthenticatedResponse,
   ResponseWithValidatedParams,
} from '@utils/customTypedResponses.ts';
import type { IMongoIdParam } from '@utils/effectSchemaReusables.ts';
import type { StrictMongoFilter } from '@utils/pathFinder_v3.ts';
import { ObjectId } from 'mongodb';

export async function revokeInviteController(
   _req: Request,
   res: AuthenticatedResponse & ResponseWithValidatedParams<IMongoIdParam>,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub, role } = res.locals.authenticatedUser;
      const { id } = res.locals.validatedParams;

      const inviteCollection = getInviteCollection();

      /* The caller's visibility scope. Superadmin sees every invite; everyone else only their own. */

      const ownershipClause =
         role === 'superadmin' ? {} : { issuedBy: new ObjectId(sub) };

      const deleteFilter = {
         $and: [{ _id: id, usedAt: null }, ownershipClause],
      } satisfies StrictMongoFilter<IInviteDocumentRead>;

      // ── One atomic decision: exists AND visible AND pending → delete ───────────
      const deleteResult = await inviteCollection.deleteOne(deleteFilter);

      if (deleteResult.deletedCount === 1) {
         return void res.status(200).json({
            success: true,
            message: `Invite revoked successfully`,
         });
      }

      // ── Failure path: disambiguate, but ONLY within the caller's scope ─────────
      /* A non-owner's lookup matches nothing and falls through to the same 404 a missing id gets. */
      const acceptedFilter = {
         $and: [{ _id: id, usedAt: { $ne: null } }, ownershipClause],
      } satisfies StrictMongoFilter<IInviteDocumentRead>;

      const isRevocationBlockedByAcceptance =
         (await inviteCollection.countDocuments(acceptedFilter, { limit: 1 })) >
         0;

      if (isRevocationBlockedByAcceptance) {
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

      return void res
         .status(404)
         .json(
            createErrorResponse('NOT_FOUND', `Invite not found.`, requestId)
         );
   } catch (err) {
      next(err);
   }
}
