import type { ISessionDocument } from '@models/Session_v3.model.ts';
import type {
   ICreateInviteResponse,
   IInviteDocumentRead,
   IPreviewInviteResponse,
   ISafeInviteCreate,
} from '@models/Invite_v3.model.ts';
import type {
   IPatientDocument,
   PatientCreateFullResponse,
   PatientCreateIntakeResponse,
   PatientGetFullResponse,
   PatientGetIntakeResponse,
   PatientSummary,
   PatientCursorListResponse,
} from '@models/Patient_v3.model.ts';
import type {
   AuthUserResponse,
   AuthUserResponseLogout,
   ISafeUser,
   IPublicUser,
} from '@models/User_v3.model.ts';
import { encodeCursor } from '@utils/cursorPagination.ts';
import type { EmailChangeStatus } from '@ssot/email_change_status_constants.ts';

// ── Auth operation responses (login / refresh / logout) ──────────────────────────
/* Session-establishing responses (login, TOTP, refresh) must carry the email-change status; the overload makes forgetting it a compile error. Logout has no session afterwards, so it keeps the minimal shape. */
export function buildAuthResponse(
   message: string,
   user: IPublicUser,
   emailChange: EmailChangeStatus
): AuthUserResponse;

export function buildAuthResponse(message: string): AuthUserResponseLogout;

export function buildAuthResponse(
   message: string,
   user?: IPublicUser,
   emailChange?: EmailChangeStatus
): AuthUserResponse | AuthUserResponseLogout {
   if (user !== undefined && emailChange !== undefined) {
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
         emailChange,
      };
   }
   return { success: true, message };
}

export type MeResponse = {
   success: true;
   message: string;
   user: ISafeUser;
   emailChange: EmailChangeStatus;
};

export function buildMeResponse(
   message: string,
   user: ISafeUser,
   emailChange: EmailChangeStatus
): MeResponse {
   return { success: true, message, user, emailChange };
}

// ── Invite responses ─────────────────────────────────────────────────────────────
export function buildPreviewInviteResponse(
   inv: IPreviewInviteResponse['inv']
): IPreviewInviteResponse {
   return { success: true, inv };
}

export function buildCreateInviteResponse(
   inv: ISafeInviteCreate
): ICreateInviteResponse {
   return {
      success: true,
      message: 'Invite sent successfully.',
      inv,
   };
}

export function buildListInvitesResponse<
   T extends Pick<IInviteDocumentRead, '_id'>,
>(
   invites: readonly T[],
   hasNextPage: boolean,
   limit: number
): {
   success: true;
   invites: readonly T[];
   pagination: { nextCursor: string | null; limit: number };
} {
   const lastInvite = invites.at(-1);
   const nextCursor =
      hasNextPage && lastInvite !== undefined
         ? lastInvite._id.toHexString()
         : null;
   return { success: true, invites, pagination: { nextCursor, limit } };
}

// ── User responses ───────────────────────────────────────────────────────────────
export function buildGetUserResponse(user: ISafeUser): {
   success: true;
   user: ISafeUser;
};
export function buildGetUserResponse(user: IPublicUser): {
   success: true;
   user: IPublicUser;
};
export function buildGetUserResponse(user: ISafeUser | IPublicUser): {
   success: true;
   user: ISafeUser | IPublicUser;
} {
   return { success: true, user };
}

export function buildListUsersResponse<T extends Pick<IPublicUser, '_id'>>(
   users: readonly T[],
   hasNextPage: boolean,
   limit: number
): {
   success: true;
   users: readonly T[];
   pagination: { nextCursor: string | null; limit: number };
} {
   const last = users.at(-1);
   const nextCursor =
      hasNextPage && last !== undefined ? last._id.toHexString() : null;

   return { success: true, users, pagination: { nextCursor, limit } };
}

// ── Session responses ────────────────────────────────────────────────────────────
export function buildListSessionsResponse<
   T extends Pick<ISessionDocument, '_id'>,
>(
   sessions: readonly T[],
   hasNextPage: boolean,
   limit: number
): {
   success: true;
   sessions: readonly T[];
   pagination: { nextCursor: string | null; limit: number };
} {
   const last = sessions.at(-1);
   const nextCursor =
      hasNextPage && last !== undefined ? last._id.toHexString() : null;
   return { success: true, sessions, pagination: { nextCursor, limit } };
}

// ── Patient responses ────────────────────────────────────────────────────────────
export function buildCreatePatientResponse(
   patient: IPatientDocument,
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

   const trimmed = hasNextPage ? patients.slice(0, limit) : patients;

   // Generate the bookmark based on the very last item in the list

   const nextCursor =
      hasNextPage && trimmed.length > 0
         ? encodeCursor(trimmed[trimmed.length - 1])
         : null;

   return {
      success: true,
      patients,
      pagination: { nextCursor, limit },
   };
}
