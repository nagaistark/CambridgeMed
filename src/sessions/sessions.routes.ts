import { Router } from 'express';
import { authenticate } from '@middleware/authenticate.ts';
import { listSessionsController } from '@sessions/listSessions.controller.ts';
import { killSessionController } from '@sessions/killSession.controller.ts';

const sessionsRouter = Router();

sessionsRouter.get('/', authenticate, listSessionsController);
sessionsRouter.delete('/:id', authenticate, killSessionController);

export default sessionsRouter;
