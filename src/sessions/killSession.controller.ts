import type { Request, NextFunction } from 'express';
import { Either, Schema } from 'effect';
import { ObjectId } from 'mongodb';
import {
   getSessionCollection,
   SessionOwnerValidator,
   type ISessionDocument,
   type ISessionOwner,
} from '@models/Session_v3.model.ts';
import { SESSION_OWNER_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import type {
   AuthenticatedResponse,
   ResponseWithValidatedParams,
} from '@utils/customTypedResponses.ts';
import type { IMongoIdParam } from '@utils/effectSchemaReusables.ts';
import type {
   StrictFindOneAndDeleteOptions,
   StrictMongoFilter,
} from '@utils/pathFinder_v3.ts';
import { requestContext, securityLog } from '@services/securityLog.service.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import logger from '../logger.ts';

export async function killSessionController(
   req: Request,
   res: AuthenticatedResponse & ResponseWithValidatedParams<IMongoIdParam>,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub, role, sessionId } = res.locals.authenticatedUser;
      const { id } = res.locals.validatedParams;

      const actorId = new ObjectId(sub);

      /* ObjectId comparison, never string comparison: hex input is case-insensitive. */
      if (id.equals(new ObjectId(sessionId))) {
         return void res
            .status(400)
            .json(
               createErrorResponse(
                  'VALIDATION_ERROR',
                  `Use the logout endpoint to terminate your current session.`,
                  requestId
               )
            );
      }

      /* Visibility scope: the superadmin may terminate any live session; everyone else only their own, from whichever device. A non-owner's attempt matches nothing and gets the same 404 as a missing id. */
      const ownershipClause = role === 'superadmin' ? {} : { userId: actorId };

      /* One atomic decision: exists AND live AND visible → delete. */
      const deletedRaw = await getSessionCollection().findOneAndDelete(
         {
            $and: [
               { _id: id, expiresAt: { $gt: new Date() } },
               ownershipClause,
            ],
         } satisfies StrictMongoFilter<ISessionDocument>,
         {
            projection: SESSION_OWNER_PROJECTION,
         } satisfies StrictFindOneAndDeleteOptions<ISessionOwner>
      );

      if (deletedRaw === null) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `Session not found.`, requestId)
            );
      }

      const decodedOwner = Schema.decodeUnknownEither(SessionOwnerValidator)(
         deletedRaw
      );
      if (Either.isLeft(decodedOwner)) {
         /* The deletion committed, so the client must hear success; only the trail is lost, and that is logged loudly. */
         logger.error(
            `Terminated session failed validation; security event not recorded. requestId=${requestId}`
         );
      } else {
         const ownerId = decodedOwner.right.userId;
         securityLog.record({
            event: ownerId.equals(actorId)
               ? 'SESSION_TERMINATED'
               : 'SESSION_TERMINATED_BY_ADMIN',
            actorId,
            targetUserId: ownerId,
            ...requestContext(req, res),
         });
      }

      return void res.status(200).json({
         success: true,
         message: `Session terminated successfully.`,
      });
   } catch (err) {
      next(err);
   }
}
