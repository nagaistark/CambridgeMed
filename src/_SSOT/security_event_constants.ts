export const securityEventTypes = [
   'TOTP_ENROLLMENT_STARTED',
   'TOTP_ENABLED',
   'TOTP_DISABLED',
   'TOTP_RECOVERY_CODES_REGENERATED',
   'TOTP_RESET_BY_ADMIN',
   'SECOND_FACTOR_FAILED',
   'SECOND_FACTOR_LOCKED',
   'RECOVERY_CODE_USED',
   'SESSION_TERMINATED',
   'SESSION_TERMINATED_BY_ADMIN',
] as const;
export type SecurityEventType = (typeof securityEventTypes)[number];

export const securityEventSeverities = ['info', 'warn'] as const;
export type SecurityEventSeverity = (typeof securityEventSeverities)[number];

/* A Record over the event union: adding an event without deciding its severity is a compile error. */
export const SECURITY_EVENT_SEVERITY: Record<
   SecurityEventType,
   SecurityEventSeverity
> = {
   TOTP_ENROLLMENT_STARTED: 'info',
   TOTP_ENABLED: 'info',
   TOTP_DISABLED: 'warn',
   TOTP_RECOVERY_CODES_REGENERATED: 'info',
   TOTP_RESET_BY_ADMIN: 'warn',
   SECOND_FACTOR_FAILED: 'warn',
   SECOND_FACTOR_LOCKED: 'warn',
   RECOVERY_CODE_USED: 'warn',
   SESSION_TERMINATED: 'info',
   SESSION_TERMINATED_BY_ADMIN: 'warn',
};

/* WHY a second factor was being checked. Recorded on every failure and lockout so an investigator can tell a login guess from a reset-link abuse. */
export const secondFactorPurposes = [
   'login',
   'password-reset',
   'disable',
   'regenerate-codes',
   'admin-reset',
] as const;
export type SecondFactorPurpose = (typeof secondFactorPurposes)[number];

export const secondFactorKinds = ['totp', 'recovery'] as const;
export type SecondFactorKind = (typeof secondFactorKinds)[number];
