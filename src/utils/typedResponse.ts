import type { Response } from 'express';

export type TypedResponse<T> = Response & { locals: { validatedBody: T } };
