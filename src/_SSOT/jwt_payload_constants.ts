import { AuthenticatedUser } from '@ssot/authenticated_user_constants.ts';

/* CustomSessionPayload is what `jose` hands back after jwtVerify — AuthenticatedUser's fields plus the standard JWT `exp` claim. Deriving from AuthenticatedUser means any change to the token's core claims propagates here automatically. */
export type CustomSessionPayload = AuthenticatedUser & {
   exp?: number;
};
