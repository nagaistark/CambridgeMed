import type { Request, Response, NextFunction } from 'express';
import { HEX96_REGEX } from '@ssot/node_crypto_constants.ts';
import { createErrorResponse } from '../errorHandlers.ts';

/* Guards any route whose :token param must be a raw 96-char hex opaque token (email confirm/cancel, password reset redemption, etc.). Deliberately returns the SAME 404 for "malformed" and "well-formed but not found". Collapsing both into one response denies an attacker any signal about which kind of guess they made. Do NOT replace this with generic validateParams()/Schema validation: that would return a distinguishable 422 for the malformed case and defeat the point. */
export function requireValidRawToken(
   message: string = 'This link is invalid.'
): (
   req: Request<{ token: string }>,
   res: Response,
   next: NextFunction
) => void {
   return (req, res, next) => {
      const { token } = req.params;
      if (!HEX96_REGEX.test(token)) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', message, res.locals.requestId)
            );
      }
      next();
   };
}
