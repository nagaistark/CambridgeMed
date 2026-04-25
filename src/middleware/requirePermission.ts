import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import type { AuthenticatedUser } from '@ssot/authenticated_user_constants.ts';
import { createErrorResponse } from 'errorHandlers.ts';

type PermissionKey = {
   [K in keyof AuthenticatedUser]: AuthenticatedUser[K] extends boolean
      ? K
      : never;
}[keyof AuthenticatedUser];

export function requirePermission(key: PermissionKey): RequestHandler {
   return (req: Request, res: Response, next: NextFunction): void => {
      /* The cast is justified by contract: requirePermission is only ever placed after authenticate in a route chain. authenticate guarantees authenticatedUser is populated before calling next(). */
      const authenticatedRes = res as AuthenticatedResponse;
      const user = authenticatedRes.locals.authenticatedUser;

      /* If somehow authenticate didn't run first, we fail safely with a 401 rather than crashing on a property access */
      if (!user) {
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `Authentication required.`,
                  res.locals.requestId
               )
            );
      }

      if (!user[key]) {
         return void res
            .status(403)
            .json(
               createErrorResponse(
                  'FORBIDDEN',
                  `You do not have permission to perform this action.`,
                  res.locals.requestId
               )
            );
      }

      next();
   };
}
