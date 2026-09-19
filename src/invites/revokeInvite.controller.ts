import type { Request, NextFunction } from 'express';
import {
   getInviteCollection,
   IInviteDocument,
   IInviteRevocation,
   InviteRevocationValidator,
} from '@models/Invite_v3.model.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import {
   AuthenticatedResponse,
   ResponseWithValidatedParams,
} from '@utils/customTypedResponses.ts';
import { IMongoIdParam } from '@utils/effectSchemaReusables.ts';
import {
   StrictFindOneOptions,
   StrictMongoFilter,
} from '@utils/pathFinder_v3.ts';
import { ObjectId } from 'mongodb';
import { Schema, Either } from 'effect';
import { INVITE_REVOCATION_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';

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

      // ── Fetch the invite ───────────────────────────────────────────────────────
      const inviteRaw = await inviteCollection.findOne<IInviteRevocation>(
         {
            _id: id,
         } satisfies StrictMongoFilter<IInviteDocument>,
         {
            projection: INVITE_REVOCATION_PROJECTION,
         } satisfies StrictFindOneOptions<IInviteRevocation>
      );
      if (!inviteRaw) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `Invite not found.`, requestId)
            );
      }

      // ── Validate the fetched document against the schema ───────────────────────
      const decodedInvite = Schema.decodeUnknownEither(
         InviteRevocationValidator
      )(inviteRaw);

      if (Either.isLeft(decodedInvite)) {
         throw decodedInvite.left;
      }

      // ── Use the validated invite document from now on ──────────────────────────
      const validatedInvite = decodedInvite.right;

      // ── Accepted invites are immutable — refuse revocation ─────────────────────
      if (validatedInvite.usedAt !== null) {
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
      const isIssuer: boolean = validatedInvite.issuedBy.toString() === sub;

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
      const ownershipFilter: Pick<
         StrictMongoFilter<IInviteDocument>,
         'issuedBy'
      > = !isSuperAdmin ? { issuedBy: new ObjectId(sub) } : {};

      const deleteResult = await inviteCollection.deleteOne({
         _id: validatedInvite._id,
         usedAt: null, // atomically fails if it was accepted between your findOne and this call
         ...ownershipFilter,
      } satisfies StrictMongoFilter<IInviteDocument>);

      if (deleteResult.deletedCount === 0) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  `This invite was just accepted and can no longer be revoked.`,
                  requestId
               )
            );
      }

      return void res.status(200).json({
         success: true,
         message: `Invite revoked successfully`,
      });
   } catch (err) {
      next(err);
   }
}
