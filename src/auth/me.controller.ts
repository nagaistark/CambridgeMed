import type { Request, NextFunction } from 'express';
import { getUserModel, SafeUser } from '@models/User.model.ts';
import { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import { buildMeResponse } from '@utils/buildResponses.ts';
import { createErrorResponse } from 'errorHandlers.ts';
import { SAFE_USER_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';

export async function meController(
   _req: Request,
   res: AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;

      /* res.locals.authenticatedUser is guaranteed to be populated here because this controller only runs behind the `authenticate` middleware. If `authenticate` had not set this, the request would have already been rejected with a 401 before reaching us. */
      const { sub } = res.locals.authenticatedUser;

      /* Only fetch the data that is safe to expose (SAFE_USER_PROJECTION). */
      const user = (await getUserModel()
         .findById(sub, SAFE_USER_PROJECTION)
         .lean()) as SafeUser | null;

      if (!user) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `Account not found.`, requestId)
            );
      }
      /* isActive is authoritative only in the database. A user deactivated mid-session should be caught here immediately, not up to a minute later when the access token finally expires. */
      if (!user.isActive) {
         return void res
            .status(403)
            .json(
               createErrorResponse(
                  'FORBIDDEN',
                  `This account has been deactivated. Please contact an administrator.`,
                  requestId
               )
            );
      }

      /* At this point the `user` is already `SafeUser`. */
      return void res.status(200).json(buildMeResponse('Session valid.', user));
   } catch (err) {
      next(err);
   }
}
