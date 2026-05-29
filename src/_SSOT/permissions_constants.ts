import { UserRole } from '@ssot/user_roles_constants.ts';

export const Permissions = {
   MANAGE_USERS: 1 << 0, // 1
   ISSUE_INVITES: 1 << 1, // 2
   READ_INTAKE: 1 << 2, //  4
   WRITE_INTAKE: 1 << 3, //  8
   READ_CLINICAL: 1 << 4, //  16
   WRITE_CLINICAL: 1 << 5, //  32
} as const;

export type PermissionFlag = (typeof Permissions)[keyof typeof Permissions];

export const ROLE_PERMISSIONS: Record<UserRole, number> = {
   secretary: Permissions.READ_INTAKE | Permissions.WRITE_INTAKE, // 12
   doctor:
      Permissions.READ_INTAKE |
      Permissions.WRITE_INTAKE |
      Permissions.READ_CLINICAL |
      Permissions.WRITE_CLINICAL, // 60
   superadmin: Permissions.MANAGE_USERS | Permissions.ISSUE_INVITES, // 3
};
