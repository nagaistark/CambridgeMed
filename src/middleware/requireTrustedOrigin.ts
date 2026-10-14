import type { Request, Response, NextFunction } from 'express';
import { myEnv } from '../validateConfig.ts';
import { createErrorResponse } from '../errorHandlers.ts';

const SAFE_METHODS: ReadonlySet<string> = new Set(['GET', 'HEAD', 'OPTIONS']);
const TRUSTED_ORIGINS: ReadonlySet<string> = new Set(myEnv.cors.origins);

export function requireTrustedOrigin(
   req: Request,
   res: Response,
   next: NextFunction
): void {
   if (SAFE_METHODS.has(req.method)) return next();

   const origin = req.get('Origin');
   const fetchSite = req.get('Sec-Fetch-Site');

   /* Browsers always send Origin on unsafe methods. If it's absent, fall back to Fetch Metadata. Both absent means a non-browser client (curl, tests), which can't be a CSRF vector because it has no victim cookie jar. */
   const isTrusted =
      origin !== undefined
         ? TRUSTED_ORIGINS.has(origin)
         : fetchSite === undefined ||
           fetchSite === 'same-origin' ||
           fetchSite === 'none';

   if (isTrusted) return next();

   return void res
      .status(403)
      .json(
         createErrorResponse(
            'FORBIDDEN',
            `Cross-site request blocked.`,
            res.locals.requestId
         )
      );
}
