import type { Response, RequestHandler } from 'express';
import type { AuthenticatedUser } from '@ssot/authenticated_user_constants.ts';

export type ResponseWithValidatedBody<T> = Response & {
   locals: Express.Locals & { validatedBody: T };
};

export type AuthenticatedResponse = Response & {
   locals: Express.Locals & { authenticatedUser: AuthenticatedUser };
};

// For controllers that sit behind authenticateTotp instead of authenticate.
export type TotpChallengeResponse = Response & {
   locals: Express.Locals & { totpChallengeSub: string };
};

export type AuthenticatedRequestHandler<
   P = any,
   ResBody = any,
   ReqBody = any,
   ReqQuery = any,
> = RequestHandler<
   P,
   ResBody,
   ReqBody,
   ReqQuery,
   { authenticatedUser: AuthenticatedUser }
>;
