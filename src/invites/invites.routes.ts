import { Router } from 'express';
import { authenticate } from '@middleware/authenticate.ts';
import { requirePermissions } from '@middleware/requirePermission.ts';
import { validateBody } from '@middleware/validateBody.ts';
import { InviteCreateSchema } from '@invites/Invite_v3.schemas.ts';
import { UserInputSchema } from '@models/User_v3.model.ts';
import { createInviteController } from '@invites/createInvite.controller.ts';
import { revokeInviteController } from '@invites/revokeInvite.controller.ts';
import { previewInviteController } from '@invites/previewInvite.controller.ts';
import { listInvitesController } from '@invites/listInvites.controller.ts';
import { acceptInviteController } from '@invites/acceptInvite.controller.ts';

const inviteRouter = Router();

// Protected: must be authenticated AND hold the ISSUE_INVITES permission.
inviteRouter.post(
   '/',
   authenticate,
   requirePermissions('ISSUE_INVITES'),
   validateBody(InviteCreateSchema),
   createInviteController
);

// Protected: same gate, with an additional ownership check inside the controller.
inviteRouter.delete(
   '/:id',
   authenticate,
   requirePermissions('ISSUE_INVITES'),
   revokeInviteController
);

// Protected: list of the invites issued by a particular User OR list of all the invites issued by every User (only visible to superadmin)
inviteRouter.get(
   '/',
   authenticate,
   requirePermissions('ISSUE_INVITES'),
   listInvitesController
);

// Public: the invitee has no session yet — authenticate must not appear here.
inviteRouter.get('/:token/preview', previewInviteController);

// Public: the registering user has no session. validateBody runs the full UserRegistrationSchema (firstName, lastName, email, password). The raw token arrives as a path parameter, not in the body.
inviteRouter.post(
   '/:token/accept',
   validateBody(UserInputSchema),
   acceptInviteController
);

export default inviteRouter;
