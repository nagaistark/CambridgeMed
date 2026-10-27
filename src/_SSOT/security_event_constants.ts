export const securityEventTypes = [
   // ── Second factor ──
   'TOTP_ENROLLMENT_STARTED',
   'TOTP_ENABLED',
   'TOTP_DISABLED',
   'TOTP_RECOVERY_CODES_REGENERATED',
   'TOTP_RESET_BY_ADMIN',
   'SECOND_FACTOR_FAILED',
   'SECOND_FACTOR_LOCKED',
   'RECOVERY_CODE_USED',
   // ── Sessions ──
   'SESSION_TERMINATED',
   'SESSION_TERMINATED_BY_ADMIN',
   'SESSION_REUSE_DETECTED',
   // ── Password ──
   'PASSWORD_CHANGED',
   'PASSWORD_RESET_COMPLETED',
   // ── Email ──
   'EMAIL_CHANGE_REQUESTED',
   'EMAIL_CHANGE_CONFIRMED',
   'EMAIL_CHANGE_CANCELLED',
   'EMAIL_CHANGE_REVERTED',
   // ── Account administration ──
   'ACCOUNT_ACTIVATED',
   'ACCOUNT_DEACTIVATED',
   'INVITE_PRIVILEGE_GRANTED',
   'INVITE_PRIVILEGE_REVOKED',
] as const;

export type SecurityEventType = (typeof securityEventTypes)[number];

export const securityEventSeverities = ['info', 'warn'] as const;
export type SecurityEventSeverity = (typeof securityEventSeverities)[number];

/* The rule behind the column: 'warn' = the event weakens or replaces a protection, widens someone's access, or is the footprint of an attack. 'info' = routine, owner-initiated or access-narrowing. A Record over the event union: adding an event without deciding its severity is a compile error. */
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
   SESSION_REUSE_DETECTED: 'warn',
   PASSWORD_CHANGED: 'info',
   PASSWORD_RESET_COMPLETED: 'warn',
   EMAIL_CHANGE_REQUESTED: 'info',
   EMAIL_CHANGE_CONFIRMED: 'warn',
   EMAIL_CHANGE_CANCELLED: 'info',
   EMAIL_CHANGE_REVERTED: 'warn',
   ACCOUNT_ACTIVATED: 'info',
   ACCOUNT_DEACTIVATED: 'warn',
   INVITE_PRIVILEGE_GRANTED: 'warn',
   INVITE_PRIVILEGE_REVOKED: 'info',
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
