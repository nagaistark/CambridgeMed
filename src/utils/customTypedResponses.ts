import type { Response } from 'express';
import type { AuthenticatedUser } from '@ssot/authenticated_user_constants.ts';

export type ResponseWithValidatedBody<T> = Response & {
   locals: Express.Locals & { validatedBody: T };
};

export type AuthenticatedResponse = Response & {
   locals: Express.Locals & { authenticatedUser: AuthenticatedUser };
};
