import type { UserRole } from '@ssot/user_roles_constants.ts';

// To the future me: all the keys whose value type is boolean are collected by the `PermissionKey` type!
export type AuthenticatedUser = {
   sub: string;
   role: UserRole;
   permissions: number;
   sessionId: string;
};
