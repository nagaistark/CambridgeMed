import { Schema } from 'effect';
import type { Request, Response, NextFunction, RequestHandler } from 'express';

export function validateBody<A, I>(
   schema: Schema.Schema<A, I, never>
): RequestHandler {
   return (req: Request, res: Response, next: NextFunction): void => {
      const result = Schema.decodeUnknownEither(schema, { errors: 'all' })(
         req.body
      );
      if (result._tag === 'Left') {
         return next(result.left);
      }
      res.locals['validatedBody'] = result.right;
      next();
   };
}
