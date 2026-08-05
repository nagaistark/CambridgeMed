import { ISafeInvite } from '@models/Invite_v3.model.ts';
import type { SafeUser, PublicUser } from '@models/User_v3.model.ts';
import type {
   PatientSummary,
   IPatientDocument,
   IPatientInitial,
} from '@models/Patient_v3.model.ts';
import { StrictIndexConfig } from '@utils/pathFinder_v3.ts';
import { ServerGeneratedFields } from '@ssot/serverGeneratedFields.ts';

/* Field projections defined once at module level. Using MongoDB-level projection means `passwordHash` never travels over the wire from MongoDB to the Node process. */
export const SAFE_USER_PROJECTION: Record<keyof SafeUser, 1> = {
   // Annotated with SafeUser, which excludes (doesn't list) `passwordHash`.
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
   _id: 1,
   createdAt: 1,
   updatedAt: 1,
} as const;

export const PUBLIC_USER_PROJECTION: Record<keyof PublicUser, 1> = {
   _id: 1,
   firstName: 1,
   lastName: 1,
   email: 1,
   role: 1,
   permissions: 1,
} as const;

export const SAFE_INVITE_PROJECTION: Record<keyof ISafeInvite, 1> = {
   email: 1,
   role: 1,
   canIssueInvites: 1,
   expiresAt: 1,
   usedAt: 1,
};

// ── Patient projections ──────────────────────────────────────────────────────────
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
   keyof IPatientInitial | keyof ServerGeneratedFields
>;

export const INTAKE_ONLY_PATIENT_PROJECTION: Record<ClinicalOnlyFields, 0> = {
   clinicalInfo: 0,
} as const;
