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
   return {
      success: true,
      message,
      ...(user && {
         user: {
            id: user._id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            role: user.role,
            canIssueInvites: user.canIssueInvites,
         },
      }),
   };
}

// ── Self-profile response (GET /api/auth/me) ─────────────────────────────────────
/* Distinct from buildAuthResponse because the /me endpoint is the one place where a user is entitled to see everything about themselves. The only thing withheld is `passwordHash`. 

The separation into a dedicated function (rather than a third overload) is intentional. The overload mechanism was designed around the user-present / user-absent distinction. A different *level of detail* for the same user is a semantically distinct concern and warrants a named function of its own. */
export type MeResponse = {
   success: true;
   message: string;
   user: SafeUser;
};

export function buildMeResponse(
   message: string,
   user: IUserDocument
): MeResponse {
   /* Destructure passwordHash out and collect everything else. TypeScript correctly infers the remainder as Omit<IUserDocument, 'passwordHash'>, which is exactly SafeUser — no cast needed. The `_` prefix signals to both the reader and the compiler that the variable is intentionally discarded. */
   const { passwordHash: _passwordHash, ...safeUser } = user;
   return { success: true, message, user: safeUser };
}
