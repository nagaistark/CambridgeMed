export const ROLE_DOCTOR = 'doctor' as const;
export const ROLE_SECRETARY = 'secretary' as const;
export const ROLE_SUPERADMIN = 'superadmin' as const;

export const allRoles = [ROLE_DOCTOR, ROLE_SECRETARY, ROLE_SUPERADMIN] as const;
export type UserRole = (typeof allRoles)[number];

/* The only roles assignable through the invite flow. Superadmin cannot be created at runtime. */
export const allowedRoles = [ROLE_DOCTOR, ROLE_SECRETARY] as const;
export type AllowedUserRole = (typeof allowedRoles)[number];
