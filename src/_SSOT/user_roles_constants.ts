export const allRoles = ['doctor', 'secretary', 'superadmin'] as const;
export type UserRole = (typeof allRoles)[number];

// The only roles assignable through the invite flow.
// Superadmin is a bootstrap concern — it cannot be created at runtime.
export const allowedRoles = ['doctor', 'secretary'] as const;
export type AllowedUserRole = (typeof allowedRoles)[number];
