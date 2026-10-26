import { Router } from 'express';
import { authenticate } from '@middleware/authenticate.ts';
import { listSessionsController } from '@sessions/listSessions.controller.ts';
import { killSessionController } from '@sessions/killSession.controller.ts';
import { requireLiveSession } from '@middleware/requireLiveSession.ts';
import { validateQuery } from '@middleware/validateQuery.ts';
import {
   MongoIdParamsSchema,
   ObjectIdCursorPaginationSchema,
} from '@utils/effectSchemaReusables.ts';
import { validateParams } from '@middleware/validateParams.ts';
import { sessionKillRateLimiter } from '@utils/rateLimiters.ts';

const sessionsRouter = Router();

// Protected: every role lists ITS OWN sessions; the superadmin lists everyone's. Scope is enforced by the filter inside the controller.
sessionsRouter.get(
   '/',
   authenticate,
   requireLiveSession,
   validateQuery(ObjectIdCursorPaginationSchema),
   listSessionsController
);

// Protected: ownership and recency are enforced atomically in the controller's delete filter.
sessionsRouter.delete(
   '/:id',
   authenticate,
   requireLiveSession,
   sessionKillRateLimiter,
   validateParams(MongoIdParamsSchema),
   killSessionController
);

export default sessionsRouter;
