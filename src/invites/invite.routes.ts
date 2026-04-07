import { Router } from 'express';
import { authenticate } from '@middleware/authenticate.ts';
import { requirePermission } from '@middleware/require.permission.ts';
import { validateBody } from '@middleware/validateBody.ts';
import { InviteCreateSchema } from '@models/Invite.model.ts';
import { createInviteController } from '@invites/createInvite.controller.ts';
import { revokeInviteController } from '@invites/revokeInvite.controller.ts';
import { previewInviteController } from '@invites/previewInvite.controller.ts';

const inviteRouter = Router();

// Protected: must be authenticated AND hold the canIssueInvites permission.
inviteRouter.post(
   '/',
   authenticate,
   requirePermission('canIssueInvites'),
   validateBody(InviteCreateSchema),
   createInviteController
);

// Protected: same gate, with an additional ownership check inside the controller.
inviteRouter.post(
   '/:id',
   authenticate,
   requirePermission('canIssueInvites'),
   revokeInviteController
);

// Public: the invitee has no session yet — authenticate must not appear here.
inviteRouter.get('/:token/preview', previewInviteController);

export default inviteRouter;
