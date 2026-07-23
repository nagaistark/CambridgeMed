import { Router } from 'express';
import { authenticate } from '@middleware/authenticate.ts';
import { validateBody } from '@middleware/validateBody.ts';
import {
   passwordChangeRateLimiter,
   nameChangeRateLimiter,
   emailChangeInitiateRateLimiter,
   emailTokenRateLimiter,
} from '@utils/rateLimiters.ts';
import {
   ChangePasswordSchema,
   ChangeNameSchema,
   InitiateEmailChangeSchema,
   SetCanIssueInvitesSchema,
   SetIsActiveSchema,
} from '@users/User_v3.schemas.ts';
import { listUsersController } from '@users/listUsers.controller.ts';
import { changePasswordController } from '@users/changePassword.controller.ts';
import { changeNameController } from '@users/changeName.controller.ts';
import { initiateEmailChangeController } from '@users/initiateEmailChange.controller.ts';
import { confirmEmailChangeController } from '@users/confirmEmailChange.controller.ts';
import { cancelEmailChangeController } from '@users/cancelEmailChange.controller.ts';
import { getUserController } from '@users/getUser.controller.ts';
import { toggleCanIssueInvitesController } from '@users/toggleCanIssueInvites.controller.ts';
import { toggleIsActiveController } from '@users/toggleIsActive.controller.ts';
import { validateParams } from '@middleware/validateParams.ts';
import { MongoIdParamsSchema } from '@utils/effectSchemaReusables.ts';
import { requireValidRawToken } from '@middleware/requireValidRawToken.ts';

const usersRouter = Router();

/* ROUTE REGISTRATION ORDER IS LOAD-BEARING.

   Express matches routes in declaration order. Static path segments must be registered before dynamic (:id, :token) segments at the same nesting level, or a static path will be swallowed as a parameter value.

   For example, if `/:id` were registered before `/email/confirm/:token`, a request to `/email/confirm/abc` would match `/:id` with id = 'email' and never reach the confirm handler.

   The ordering rule: all /me/* and /email/* routes come before /:id routes. */

// ── User listing ─────────────────────────────────────────────────────────────────
/* Superadmin: full SafeUser[]. Others: PublicUser[]. */
usersRouter.get('/', authenticate, listUsersController);

// ── Self-mutation routes (/me/*) ─────────────────────────────────────────────────
/* All require authentication. Rate limiters are the inner guards on sensitive writes. */

usersRouter.patch(
   '/me/password',
   authenticate,
   passwordChangeRateLimiter,
   validateBody(ChangePasswordSchema),
   changePasswordController
);

usersRouter.patch(
   '/me/name',
   authenticate,
   nameChangeRateLimiter,
   validateBody(ChangeNameSchema),
   changeNameController
);

usersRouter.post(
   '/me/email',
   authenticate,
   emailChangeInitiateRateLimiter,
   validateBody(InitiateEmailChangeSchema),
   initiateEmailChangeController
);

// ── Email change token routes (/email/*) ─────────────────────────────────────────
/* Public: no authenticate middleware. The raw token in the URL is the sole credential. The user clicking a link from their email client will not have an active session. Registered as GET because links in emails are followed via browser navigation, which is always GET. The mutations triggered are protected by the token itself, not by the HTTP verb. */
usersRouter.get(
   '/email/confirm/:token',
   emailTokenRateLimiter,
   requireValidRawToken,
   confirmEmailChangeController
);

usersRouter.get(
   '/email/cancel/:token',
   emailTokenRateLimiter,
   requireValidRawToken,
   cancelEmailChangeController
);

// ── Per-user admin routes (/:id/*) ───────────────────────────────────────────────
/* These must come last. Dynamic segments eat any path that wasn't matched above. All require authentication. Authorisation (superadmin vs inviter) is enforced inside each controller because it requires a database lookup of the target user — middleware cannot perform this check without duplicating the fetch. */

usersRouter.get(
   '/:id',
   authenticate,
   validateParams(MongoIdParamsSchema),
   getUserController
);

usersRouter.patch(
   '/:id/can-issue-invites',
   authenticate,
   validateParams(MongoIdParamsSchema),
   validateBody(SetCanIssueInvitesSchema),
   toggleCanIssueInvitesController
);

usersRouter.patch(
   '/:id/is-active',
   authenticate,
   validateParams(MongoIdParamsSchema),
   validateBody(SetIsActiveSchema),
   toggleIsActiveController
);

export default usersRouter;
