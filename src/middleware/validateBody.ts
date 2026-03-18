import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { type GenericSchema, InferOutput, parse } from 'valibot';

export function validateBody<T extends GenericSchema>(
   schema: T
): RequestHandler {
   return (req: Request, res: Response, next: NextFunction): void => {
      try {
         const result: InferOutput<T> = parse(schema, req.body);
         res.locals['validatedBody'] = result;
         next();
      } catch (err) {
         next(err);
      }
   };
}
