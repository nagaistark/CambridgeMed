import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { createErrorResponse } from 'errorHandlers.ts';

/* Extract all keys of `authenticatedUser` whose value type is boolean. Currently resolves to: `canIssueInvites`. Any future boolean permission added to Express.Locals automatically becomes valid here. */
type AuthenticatedUser = NonNullable<Express.Locals['authenticatedUser']>;
type PermissionKey = {
   [K in keyof AuthenticatedUser]: AuthenticatedUser[K] extends boolean
      ? K
      : never;
}[keyof AuthenticatedUser];

export function requirePermission(key: PermissionKey): RequestHandler {
   return (_req: Request, res: Response, next: NextFunction): void => {
      const user = res.locals.authenticatedUser;

      /* Defensive guard: this middleware is designed to run after `authenticate`, which guarantees `authenticatedUser` is populated. If somehow it isn't, we respond with 401 rather than crashing on a null-access. */
      if (!user) {
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `Authentication required.`,
                  undefined,
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
                  undefined,
                  res.locals.requestId
               )
            );
      }

      next();
   };
}
