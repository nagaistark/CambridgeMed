import type { Request, Response, NextFunction } from 'express';
import { getUserModel } from '@models/User.model.ts';
import { buildAuthResponse } from '@utils/buildResponses.ts';
import { createErrorResponse } from 'errorHandlers.ts';

export async function meController(
   req: Request,
   res: Response,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;

      /* res.locals.authenticatedUser is guaranteed to be populated here because this controller only runs behind the `authenticate` middleware. If `authenticate` had not set this, the request would have already been rejected with a 401 before reaching us. */
      const { sub } = res.locals.authenticatedUser!;

      /* A single indexed primary-key lookup. A direct _id B-tree hit. Two reasons why we do this:
         1. The JWT only carries sub, role, and canIssueInvites. The frontend also needs firstName, lastName, and email to render the UI.
         2. isActive is authoritative only in the database. A user deactivated mid-session should be caught here immediately, not up to a minute later when the access token finally expires. */
      const user = await getUserModel().findById(sub).lean();

      if (!user) {
         return void res
            .status(404)
            .json(
               createErrorResponse(
                  'NOT_FOUND',
                  `Account not found.`,
                  undefined,
                  requestId
               )
            );
      }

      if (!user.isActive) {
         return void res
            .status(403)
            .json(
               createErrorResponse(
                  'FORBIDDEN',
                  `This account has been deactivated. Please contact an administrator.`,
                  undefined,
                  requestId
               )
            );
      }

      /* Mirror the login response's user shape exactly. A consistent contract means the frontend can handle both responses with the same normaliser. */
      return void res.status(200).json(buildAuthResponse('', user));
   } catch (err) {
      next(err);
   }
}
