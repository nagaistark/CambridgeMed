import 'express';
import { AuthenticatedUser } from '@ssot/authenticated_user_constants.ts';

declare global {
   namespace Express {
      interface Locals {
         requestId: string;
         authenticatedUser?: AuthenticatedUser;
      }
   }
}
