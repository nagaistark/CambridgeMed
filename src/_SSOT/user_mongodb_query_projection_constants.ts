import type {
   IInviteEmailCheck,
   IInviteListRead,
   IInvitePreview,
   ISafeInviteRead,
} from '@models/Invite_v3.model.ts';
import type {
   ISafeUser,
   IPublicUser,
   IUserNames,
   IUserIdName,
   IUserIdPasswordHash,
   IUserInviteIssuer,
   IUserEmailChangeInitiator,
   IUserIdRoleActive,
   IUserPasswordResetTarget,
   IUserIdRolePermissions,
   IUserLogin,
   IUserRefresh,
   IUserSecondFactor,
   IUserTotpLogin,
   IUserTotpManagement,
   IUserRecoveryCodes,
   IUserIdNameEmail,
} from '@models/User_v3.model.ts';
import type {
   PatientSummary,
   IPatientDocument,
   IPatientInitial,
} from '@models/Patient_v3.model.ts';
import type {
   ISessionAdminView,
   ISessionOwner,
   ISessionRefresh,
   ISessionSelfView,
} from '@models/Session_v3.model.ts';
import type { IPasswordResetRedeemCheck } from '@models/PasswordReset_v3.model.ts';
import type { StrictIndexConfig } from '@utils/pathFinder_v3.ts';
import type { IServerGeneratedFields } from '@ssot/serverGeneratedFields.ts';

/* Field projections defined once at module level. Using MongoDB-level projection means `passwordHash` never travels over the wire from MongoDB to the Node process. */
export const SAFE_USER_PROJECTION: Record<keyof ISafeUser, 1> = {
   // Annotated with ISafeUser, which excludes (doesn't list) `passwordHash`.
   email: 1,
   firstName: 1,
   lastName: 1,
   role: 1,
   permissions: 1,
   previousNames: 1,
   previousEmails: 1,
   nameChangesUsed: 1,
   emailChangesUsed: 1,
   isTotpEnabled: 1,
   invitedBy: 1,
   isActive: 1,
   passwordResetRequired: 1,
   _id: 1,
   createdAt: 1,
   updatedAt: 1,
} as const;

export const PUBLIC_USER_PROJECTION: Record<keyof IPublicUser, 1> = {
   _id: 1,
   firstName: 1,
   lastName: 1,
   email: 1,
   role: 1,
   permissions: 1,
} as const;

export const USER_EMAIL_CHANGE_INITIATOR_PROJECTION: Record<
   keyof IUserEmailChangeInitiator,
   1
> = {
   _id: 1,
   firstName: 1,
   email: 1,
   emailChangesUsed: 1,
   passwordHash: 1,
   isActive: 1,
};

export const USER_ID_PASSWORDHASH_PROJECTION: Record<
   keyof IUserIdPasswordHash,
   1
> = {
   _id: 1,
   passwordHash: 1,
};

export const USER_ID_NAME_PROJECTION: Record<keyof IUserIdName, 1> = {
   _id: 1,
   firstName: 1,
   lastName: 1,
};

export const USER_ID_NAME_EMAIL_PROJECTION: Record<keyof IUserIdNameEmail, 1> =
   {
      _id: 1,
      firstName: 1,
      lastName: 1,
      email: 1,
   };

export const USER_PASSWORD_RESET_TARGET_PROJECTION: Record<
   keyof IUserPasswordResetTarget,
   1
> = {
   _id: 1,
   firstName: 1,
   email: 1,
};

export const USER_INVITE_ISSUER_PROJECTION: Record<keyof IUserInviteIssuer, 1> =
   {
      _id: 1,
      firstName: 1,
      lastName: 1,
      role: 1,
      permissions: 1,
      isActive: 1,
   };

export const USER_NAME_EMAIL_PROJECTION: Record<keyof IUserNames, 1> = {
   _id: 1,
   firstName: 1,
   lastName: 1,
   nameChangesUsed: 1,
};

export const USER_ID_ROLE_ACTIVE_PROJECTION: Record<
   keyof IUserIdRoleActive,
   1
> = {
   _id: 1,
   role: 1,
   isActive: 1,
};

export const USER_ID_ROLE_PERMISSIONS_PROJECTION: Record<
   keyof IUserIdRolePermissions,
   1
> = {
   _id: 1,
   role: 1,
   permissions: 1,
};

export const USER_SECOND_FACTOR_PROJECTION: Record<keyof IUserSecondFactor, 1> =
   {
      _id: 1,
      isTotpEnabled: 1,
      totpSecret: 1,
      totpLastUsedStep: 1,
      totpRecoveryCodes: 1,
   };

export const USER_TOTP_LOGIN_PROJECTION: Record<keyof IUserTotpLogin, 1> = {
   _id: 1,
   firstName: 1,
   lastName: 1,
   email: 1,
   role: 1,
   permissions: 1,
   isActive: 1,
   passwordResetRequired: 1,
   isTotpEnabled: 1,
   totpSecret: 1,
   totpLastUsedStep: 1,
   totpRecoveryCodes: 1,
};

export const USER_TOTP_MANAGEMENT_PROJECTION: Record<
   keyof IUserTotpManagement,
   1
> = {
   _id: 1,
   email: 1,
   passwordHash: 1,
   isTotpEnabled: 1,
   totpSecret: 1,
   totpPendingSecret: 1,
   totpLastUsedStep: 1,
   totpRecoveryCodes: 1,
};

export const USER_RECOVERY_CODES_PROJECTION: Record<
   keyof IUserRecoveryCodes,
   1
> = {
   _id: 1,
   totpRecoveryCodes: 1,
};

export const PASSWORD_RESET_REDEEM_CHECK_PROJECTION: Record<
   keyof IPasswordResetRedeemCheck,
   1
> = {
   _id: 1,
   userId: 1,
};

export const USER_LOGIN_PROJECTION: Record<keyof IUserLogin, 1> = {
   _id: 1,
   firstName: 1,
   lastName: 1,
   email: 1,
   role: 1,
   permissions: 1,
   passwordHash: 1,
   isActive: 1,
   passwordResetRequired: 1,
   isTotpEnabled: 1,
};

export const USER_REFRESH_PROJECTION: Record<keyof IUserRefresh, 1> = {
   _id: 1,
   firstName: 1,
   lastName: 1,
   email: 1,
   role: 1,
   permissions: 1,
   isActive: 1,
   passwordResetRequired: 1,
};

export const SESSION_REFRESH_PROJECTION: Record<keyof ISessionRefresh, 1> = {
   _id: 1,
   userId: 1,
   rotatedAt: 1,
};

export const SAFE_INVITE_PROJECTION: Record<keyof ISafeInviteRead, 1> = {
   _id: 1,
   email: 1,
   role: 1,
   canIssueInvites: 1,
   expiresAt: 1,
   usedAt: 1,
   issuedBy: 1,
};

export const INVITE_LIST_PROJECTION: Record<keyof IInviteListRead, 1> = {
   ...SAFE_INVITE_PROJECTION,
   acceptedBy: 1,
};

export const INVITE_EMAIL_CHECK_PROJECTION: Record<keyof IInviteEmailCheck, 1> =
   {
      _id: 1,
      email: 1,
   };

export const INVITE_PREVIEW_PROJECTION: Record<keyof IInvitePreview, 1> = {
   role: 1,
   expiresAt: 1,
   usedAt: 1,
};

// ── Sessions projections ─────────────────────────────────────────────────────────
export const SESSION_SELF_VIEW_PROJECTION: Record<keyof ISessionSelfView, 1> = {
   _id: 1,
   ipAddress: 1,
   userAgent: 1,
   createdAt: 1,
   expiresAt: 1,
   rotatedAt: 1,
};

export const SESSION_ADMIN_VIEW_PROJECTION: Record<keyof ISessionAdminView, 1> =
   {
      _id: 1,
      userId: 1,
      ipAddress: 1,
      userAgent: 1,
      createdAt: 1,
      expiresAt: 1,
      rotatedAt: 1,
   };

export const SESSION_OWNER_PROJECTION: Record<keyof ISessionOwner, 1> = {
   _id: 1,
   userId: 1,
};

// ── Patients projections ─────────────────────────────────────────────────────────
/* The inclusion projection for GET /api/patients. Its type is derived directly from PatientSummary via LeafPaths, so it stays in sync automatically. clinicalInfo is absent because PatientSummary doesn't include it — the constraint enforces this without any manual bookkeeping. */
export const LIST_PATIENT_PROJECTION: Partial<
   StrictIndexConfig<PatientSummary>
> = {
   _id: 1,
   isActive: 1,
   primaryDoctorId: 1,
   'intakeInfo.demographics.prefix': 1,
   'intakeInfo.demographics.firstName': 1,
   'intakeInfo.demographics.lastName': 1,
   'intakeInfo.demographics.dateOfBirth': 1,
   'intakeInfo.demographics.deceased': 1,
   'intakeInfo.coreIdentifiers.healthCardNumber': 1,
   'intakeInfo.coreIdentifiers.chartNumber': 1,
   'intakeInfo.coreIdentifiers.enrollmentStatus': 1,
   createdAt: 1,
   updatedAt: 1,
} as const;

/* ClinicalOnlyFields is computed as the set difference between the full and initial patient definitions. Currently that resolves to the single key 'clinicalInfo', but if a second top-level clinical field is ever added to IPatientDocument, TypeScript will require it to appear here too. */
type ClinicalOnlyFields = Exclude<
   keyof IPatientDocument,
   keyof IPatientInitial | keyof IServerGeneratedFields
>;

export const INTAKE_ONLY_PATIENT_PROJECTION: Record<ClinicalOnlyFields, 0> = {
   clinicalInfo: 0,
} as const;
