import { allowedRoles, type UserRole } from '@ssot/user_roles_constants.ts';
import type { StrictMongoFilter } from './pathFinder_v3.ts';
import type { IUserDocument } from '@models/User_v3.model.ts';
import type { EmptyOr } from './helperTypes.ts';

/* Superadmin: everyone, including deactivated users and themselves. Everyone else: active, assignable-role users only. The allow-list (`allowedRoles`) fails closed, because a role added later stays hidden until someone decides otherwise. Single ternary on purpose, so TypeScript infers a normalized union instead of reducing it to `{}`. */

const staffVisibilityFilter = {
   isActive: true,
   role: { $in: allowedRoles },
} satisfies StrictMongoFilter<IUserDocument>;

export type UserVisibilityFilter = EmptyOr<typeof staffVisibilityFilter>;

export function buildUserVisibilityFilter(
   viewerRole: UserRole
): UserVisibilityFilter {
   return viewerRole === 'superadmin' ? {} : staffVisibilityFilter;
}
