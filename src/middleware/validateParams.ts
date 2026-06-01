import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { type GenericSchema, type InferOutput, parse } from 'valibot';

export function validateParams<T extends GenericSchema>(
   schema: T
): RequestHandler {
   return (req: Request, res: Response, next: NextFunction): void => {
      try {
         const result: InferOutput<T> = parse(schema, req.params);
         res.locals['validatedParams'] = result;
         next();
      } catch (err) {
         next(err);
      }
   };
}
