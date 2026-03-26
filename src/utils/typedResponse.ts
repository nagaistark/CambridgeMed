import type { Response } from 'express';

export type TypedResponse<T> = Response & {
   locals: Express.Locals & { validatedBody: T };
};
