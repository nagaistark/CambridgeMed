import {
   AuthUserResponse,
   AuthUserResponseLogout,
   IUserDocument,
} from '@models/User.model.ts';

/* Function overloads:
   when called with a user argument, the return type is AuthUserResponse*/
export function buildAuthResponse(
   message: string,
   user: IUserDocument
): AuthUserResponse;

/* when called without one, the return type is AuthUserResponseLogout */
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
