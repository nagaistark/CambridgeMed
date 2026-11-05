import { Either, Schema } from 'effect';
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { RawTokenBodySchema } from '@utils/effectSchemaReusables.ts';
import { createErrorResponse } from '../errorHandlers.ts';

const decodeRawTokenBody = Schema.decodeUnknownEither(RawTokenBodySchema);

export function requireValidRawTokenBody(
   message: string = 'This link is invalid.'
): RequestHandler {
   return (req: Request, res: Response, next: NextFunction): void => {
      /* `req.body` is undefined when express.json() didn't parse anything (wrong Content-Type, empty body); decodeUnknown turns that into a Left, so it lands on the same 404. */
      const result = decodeRawTokenBody(req.body);
      if (Either.isLeft(result)) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', message, res.locals.requestId)
            );
      }
      /* The decoded struct contains ONLY `token`; extra keys are dropped. */
      res.locals['validatedBody'] = result.right;
      next();
   };
}
