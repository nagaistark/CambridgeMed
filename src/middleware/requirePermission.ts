import type { Request, NextFunction } from 'express';
import type {
   AuthenticatedRequestHandler,
   AuthenticatedResponse,
} from '@utils/customTypedResponses.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import { PermissionFlag, Permissions } from '@ssot/permissions_constants.ts';

export function requirePermissions(
   ...flags: PermissionFlag[]
): AuthenticatedRequestHandler {
   const required = flags.reduce((acc, flag) => acc | Permissions[flag], 0);

   return (
      _req: Request,
      res: AuthenticatedResponse,
      next: NextFunction
   ): void => {
      const user = res.locals.authenticatedUser;

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

      if ((user.permissions & required) !== required) {
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
