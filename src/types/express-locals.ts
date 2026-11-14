import 'express';
import type { AuthenticatedUser } from '@ssot/authenticated_user_constants.ts';
import type { ITotpChallengeAuth } from '@models/TotpChallenge_v3.model.ts';

declare global {
   namespace Express {
      interface Locals {
         requestId: string;
         authenticatedUser?: AuthenticatedUser;
         totpChallenge?: ITotpChallengeAuth;
      }
   }
}
