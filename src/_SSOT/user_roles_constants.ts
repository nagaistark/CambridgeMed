export const userRoles = ['doctor', 'secretary'] as const;
export type UserRole = (typeof userRoles)[number];
