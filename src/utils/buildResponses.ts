import { PreviewInviteResponse, SafeInvite } from '@models/Invite.model.ts';
import {
   IPatientDocument,
   PatientCreateFullResponse,
   PatientCreateIntakeResponse,
   PatientGetFullResponse,
   PatientGetIntakeResponse,
   PatientSummary,
   PatientCursorListResponse,
} from '@models/Patient.model.ts';
import type {
   AuthUserResponse,
   AuthUserResponseLogout,
   IUserDocument,
   SafeUser,
} from '@models/User.model.ts';
import { encodeCursor } from '@utils/cursorPagination.ts';

// ── Auth operation responses (login / refresh / logout) ──────────────────────────
/* These return the minimal PublicUser shape (there is no need to send the full profile, history arrays, or counters on every token operation.

Function overloads: when called with a user argument, the return type is AuthUserResponse... */
export function buildAuthResponse(
   message: string,
   user: IUserDocument
): AuthUserResponse;

/* ...when called without one, the return type is AuthUserResponseLogout */
export function buildAuthResponse(message: string): AuthUserResponseLogout;

export function buildAuthResponse(
   message: string,
   user?: IUserDocument
): AuthUserResponse | AuthUserResponseLogout {
   if (user) {
      return {
         success: true,
         message,
         user: {
            _id: user._id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            role: user.role,
            permissions: user.permissions,
         },
      };
   }
   return {
      success: true,
      message,
   };
}

// ── Self-profile response (GET /api/auth/me) ─────────────────────────────────────
/* Distinct from buildAuthResponse because the /me endpoint is the one place where a user sees everything about themselves (except `passwordHash`).

The separation into a dedicated function (rather than a third overload) is intentional. The overload mechanism was designed around the user-present / user-absent distinction. A different *level of detail* for the same user is a semantically distinct concern and warrants a named function of its own. */
export type MeResponse = {
   success: true;
   message: string;
   user: SafeUser;
};

export function buildMeResponse(message: string, user: SafeUser): MeResponse {
   return { success: true, message, user };
}

// ── Invite preview response ──────────────────────────────────────────────────────
export function buildPreviewInviteResponse(
   inv: SafeInvite
): PreviewInviteResponse {
   return { success: true, inv };
}

// ── Patient responses ────────────────────────────────────────────────────────────
export function buildCreatePatientResponse(
   patient: IPatientDocument, // Plain object because the caller did `.toObject()`
   canReadClinical: boolean
): PatientCreateFullResponse | PatientCreateIntakeResponse {
   const message = 'Patient created successfully.';

   if (canReadClinical) {
      /* Full shape: clinicalInfo is already present on the patient parameter */
      return { success: true, message, patient };
   }

   /* TypeScript checks that every field of Omit<IPatientDocument, 'clinicalInfo'> is satisfied by this object literal — no destructuring required. */
   const intakePatient: Omit<IPatientDocument, 'clinicalInfo'> = {
      _id: patient._id,
      isActive: patient.isActive,
      primaryDoctorId: patient.primaryDoctorId,
      intakeInfo: patient.intakeInfo,
      createdAt: patient.createdAt,
      updatedAt: patient.updatedAt,
   };

   return { success: true, message, patient: intakePatient };
}

export function buildGetPatientResponse(
   patient: IPatientDocument,
   canReadClinical: boolean
): PatientGetFullResponse | PatientGetIntakeResponse {
   if (canReadClinical) {
      return { success: true, patient };
   }

   /* Explicit object construction rather than rest-spread destructuring. The type annotation on intakePatient forces TypeScript to verify that every field of Omit<IPatientDocument, 'clinicalInfo'> is present here. If a new top-level field is added to IPatientDocument, this assignment site fails to compile until it is included — drift is impossible. */
   const intakePatient: Omit<IPatientDocument, 'clinicalInfo'> = {
      _id: patient._id,
      isActive: patient.isActive,
      primaryDoctorId: patient.primaryDoctorId,
      intakeInfo: patient.intakeInfo,
      createdAt: patient.createdAt,
      updatedAt: patient.updatedAt,
   };

   return { success: true, patient: intakePatient };
}

export function buildCursorPatientsResponse(
   patients: PatientSummary[],
   limit: number
): PatientCursorListResponse {
   // Check if we retrieved that extra "+1" document
   const hasNextPage = patients.length > limit;

   if (hasNextPage) {
      patients.pop(); // Remove the extra document so we only return the exact limit
   }

   // Generate the bookmark based on the very last item in the list
   const nextCursor =
      hasNextPage && patients.length > 0
         ? encodeCursor(patients[patients.length - 1])
         : null;

   return {
      success: true,
      patients,
      pagination: { nextCursor, limit },
   };
}
