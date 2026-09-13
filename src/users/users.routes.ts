import { Router } from 'express';
import { authenticate } from '@middleware/authenticate.ts';
import { validateBody } from '@middleware/validateBody.ts';
import { validateParams } from '@middleware/validateParams.ts';
import { requireValidRawToken } from '@middleware/requireValidRawToken.ts';
import {
   emailChangeInitiateRateLimiter,
   emailTokenRateLimiter,
   nameChangeRateLimiter,
   passwordChangeRateLimiter,
   userAdminToggleRateLimiter,
} from '@utils/rateLimiters.ts';
import { MongoIdParamsSchema } from '@utils/effectSchemaReusables.ts';
import {
   ChangeNameSchema,
   ChangePasswordSchema,
   InitiateEmailChangeSchema,
   SetCanIssueInvitesSchema,
   SetIsActiveSchema,
} from './User_v3.schemas.ts';
import { changePasswordController } from './changePassword.controller.ts';
import { changeNameController } from './changeName.controller.ts';
import { initiateEmailChangeController } from './initiateEmailChange.controller.ts';
import { confirmEmailChangeController } from './confirmEmailChange.controller.ts';
import { cancelEmailChangeController } from './cancelEmailChange.controller.ts';
import { listUsersController } from './listUsers.controller.ts';
import { getUserController } from './getUser.controller.ts';
import { toggleCanIssueInvitesController } from './toggleCanIssueInvites.controller.ts';
import { toggleIsActiveController } from './toggleIsActive.controller.ts';

const usersRouter = Router();

// ── 1. SELF-MUTATION SUB-ROUTER (/me/*) ──────────────────────────────────────────
const meRouter = Router();
meRouter.use(authenticate);

meRouter.patch(
   '/password',
   passwordChangeRateLimiter,
   validateBody(ChangePasswordSchema),
   changePasswordController
);

meRouter.patch(
   '/name',
   nameChangeRateLimiter,
   validateBody(ChangeNameSchema),
   changeNameController
);

meRouter.post(
   '/email',
   emailChangeInitiateRateLimiter,
   validateBody(InitiateEmailChangeSchema),
   initiateEmailChangeController
);

// ── 2. EMAIL TOKEN SUB-ROUTER (/email/*) ─────────────────────────────────────────
const emailRouter = Router();

emailRouter.get(
   '/confirm/:token',
   emailTokenRateLimiter,
   requireValidRawToken('This confirmation link is invalid or has expired.'),
   confirmEmailChangeController
);

emailRouter.get(
   '/cancel/:token',
   emailTokenRateLimiter,
   requireValidRawToken('This cancellation link is invalid or has expired.'),
   cancelEmailChangeController
);

// ── 3. USER MANAGEMENT & DYNAMIC ROUTES (/*) ─────────────────────────────────────
const userAdminRouter = Router();
userAdminRouter.use(authenticate);

userAdminRouter.get('/', listUsersController);

userAdminRouter.get(
   '/:id',
   validateParams(MongoIdParamsSchema),
   getUserController
);

userAdminRouter.patch(
   '/:id/can-issue-invites',
   userAdminToggleRateLimiter,
   validateParams(MongoIdParamsSchema),
   validateBody(SetCanIssueInvitesSchema),
   toggleCanIssueInvitesController
);
userAdminRouter.patch(
   '/:id/is-active',
   userAdminToggleRateLimiter,
   validateParams(MongoIdParamsSchema),
   validateBody(SetIsActiveSchema),
   toggleIsActiveController
);

// ── MOUNT SUB-ROUTERS ON MAIN ROUTER ─────────────────────────────────────────────
/* Express matches prefixes first: requests starting with /me or /email enter their respective sub-router directly and can never hit dynamic :id handlers. */
usersRouter.use('/me', meRouter);
usersRouter.use('/email', emailRouter);
usersRouter.use('/', userAdminRouter);

export default usersRouter;
