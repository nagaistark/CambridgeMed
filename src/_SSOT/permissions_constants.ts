import { type UserRole } from '@ssot/user_roles_constants.ts';

export const Permissions = {
   MANAGE_USERS: 1 << 0, // 1
   ISSUE_INVITES: 1 << 1, // 2
   READ_INTAKE: 1 << 2, //  4
   WRITE_INTAKE: 1 << 3, //  8
   READ_CLINICAL: 1 << 4, //  16
   WRITE_CLINICAL: 1 << 5, //  32
} as const;

export type PermissionFlag = keyof typeof Permissions;

export const ROLE_PERMISSIONS: Record<UserRole, number> = {
   secretary: Permissions.READ_INTAKE | Permissions.WRITE_INTAKE, // 12
   doctor:
      Permissions.READ_INTAKE |
      Permissions.WRITE_INTAKE |
      Permissions.READ_CLINICAL |
      Permissions.WRITE_CLINICAL, // 60
   superadmin: Permissions.MANAGE_USERS | Permissions.ISSUE_INVITES, // 3
};

/* The ceiling: permissions a role MAY be granted on top of its base set. A Record over UserRole means adding a new role is a compile error until someone decides this explicitly. */
export const ROLE_DELEGABLE_PERMISSIONS: Record<UserRole, number> = {
   secretary: 0,
   doctor: Permissions.ISSUE_INVITES,
   superadmin: 0,
};

export function canBeDelegated(role: UserRole, flag: PermissionFlag): boolean {
   return (ROLE_DELEGABLE_PERMISSIONS[role] & Permissions[flag]) !== 0;
}

/* Clamps by construction: a requested delegation outside the ceiling is silently dropped, never granted. Validation upstream produces the friendly errors. */
export function resolvePermissions(
   role: UserRole,
   requestedDelegations: number
): number {
   return (
      ROLE_PERMISSIONS[role] |
      (requestedDelegations & ROLE_DELEGABLE_PERMISSIONS[role])
   );
}

/* floor ⊆ permissions ⊆ ceiling */
export function arePermissionsValidForRole(
   role: UserRole,
   permissions: number
): boolean {
   const floor = ROLE_PERMISSIONS[role];
   const ceiling = floor | ROLE_DELEGABLE_PERMISSIONS[role];
   return (permissions & floor) === floor && (permissions & ~ceiling) === 0;
}
