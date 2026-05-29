import { UserRole } from '@ssot/user_roles_constants.ts';

export type CustomSessionPayload = {
   sub: string;
   role: UserRole;
   permissions: number;
   sessionId: string;
   exp?: number;
};
