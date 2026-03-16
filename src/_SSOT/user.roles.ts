export const userRoles = ['doctor', 'secretary', 'superadmin'] as const;
export type UserRole = (typeof userRoles)[number];
