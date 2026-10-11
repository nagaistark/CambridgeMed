import { Router } from 'express';
import { authenticate } from '@middleware/authenticate.ts';
import { requirePermissions } from '@middleware/requirePermission.ts';
import { validateBody } from '@middleware/validateBody.ts';
import { InviteInputSchema } from '@models/Invite_v3.model.ts';
import { UserInputSchema } from '@models/User_v3.model.ts';
import { createInviteController } from '@invites/createInvite.controller.ts';
import { revokeInviteController } from '@invites/revokeInvite.controller.ts';
import { previewInviteController } from '@invites/previewInvite.controller.ts';
import { listInvitesController } from '@invites/listInvites.controller.ts';
import { acceptInviteController } from '@invites/acceptInvite.controller.ts';
import { validateParams } from '@middleware/validateParams.ts';
import { validateQuery } from '@middleware/validateQuery.ts';
import {
   MongoIdParamsSchema,
   ObjectIdCursorPaginationSchema,
} from '@utils/effectSchemaReusables.ts';
import { requireValidRawToken } from '@middleware/requireValidRawToken.ts';
import {
   inviteAcceptRateLimiter,
   inviteCreateRateLimiter,
   invitePreviewRateLimiter,
} from '@utils/rateLimiters.ts';

const inviteRouter = Router();

// Protected: must be authenticated AND hold the ISSUE_INVITES permission.
inviteRouter.post(
   '/',
   authenticate,
   requirePermissions('ISSUE_INVITES'),
   inviteCreateRateLimiter,
   validateBody(InviteInputSchema),
   createInviteController
);

// Protected: ownership check inside the controller.
inviteRouter.delete(
   '/:id',
   authenticate,
   requirePermissions('ISSUE_INVITES'),
   validateParams(MongoIdParamsSchema),
   revokeInviteController
);

// Protected: list of the invites issued by a particular User OR list of all the invites issued by every User (only visible to superadmin). Visibility is enforced by the ownership predicate inside the controller, not by the `requirePermissions('ISSUE_INVITES')` permission gate. Demoted doctors retain the ability to list the invites they issued before the demotion. The superadmin sees every invite.
inviteRouter.get(
   '/',
   authenticate,
   validateQuery(ObjectIdCursorPaginationSchema),
   listInvitesController
);

// Public: the invitee has no session yet — authenticate must not appear here.
inviteRouter.get(
   '/:token/preview',
   invitePreviewRateLimiter,
   requireValidRawToken('This invite link is invalid or has expired.'),
   previewInviteController
);

// Public: the registering user has no session. validateBody runs the full UserInputSchema (firstName, lastName, email, password). The raw token arrives as a path parameter, not in the body.
inviteRouter.post(
   '/:token/accept',
   inviteAcceptRateLimiter,
   requireValidRawToken('This invite link is invalid or has expired.'),
   validateBody(UserInputSchema),
   acceptInviteController
);

export default inviteRouter;
