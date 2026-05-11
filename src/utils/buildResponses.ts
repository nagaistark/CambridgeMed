import type {
   AuthUserResponse,
   AuthUserResponseLogout,
   IUserDocument,
   SafeUser,
} from '@models/User.model.ts';

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
            canIssueInvites: user.canIssueInvites,
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
