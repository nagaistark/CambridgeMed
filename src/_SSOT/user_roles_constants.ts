// Only 'doctor' and 'secretary' for now. There can only be one 'superadmin', and it's hardcoded from the very beginning.
export const userRoles = ['doctor', 'secretary'] as const;
export type UserRole = (typeof userRoles)[number];
