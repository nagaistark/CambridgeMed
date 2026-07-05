import { ParseResult, Schema } from 'effect';
import type { Request, Response, NextFunction, RequestHandler } from 'express';

export function validateParams<A, I>(
   schema: Schema.Schema<A, I, never>
): RequestHandler {
   return (req: Request, res: Response, next: NextFunction): void => {
      const result = Schema.decodeUnknownEither(schema, { errors: 'all' })(
         req.params
      );
      if (result._tag === 'Left') {
         return void res.status(400).json({
            error: 'Validation failed',
            issues: ParseResult.ArrayFormatter.formatErrorSync(result.left),
         });
      }
      res.locals['validatedBody'] = result.right;
      next();
   };
}
