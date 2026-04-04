import { Router } from 'express';
import { validateBody } from '@middleware/validateBody.ts';
import { authenticate } from '@middleware/authenticate.ts';
import { LoginSchema } from '@auth/login.schema.ts';
import { loginController } from '@auth/login.controller.ts';
import { logoutController } from '@auth/logout.controller.ts';
import { meController } from '@auth/me.controller.ts';
import { refreshController } from '@auth/refresh.controller.ts';

const authRouter = Router();

authRouter.post('/login', validateBody(LoginSchema), loginController);
authRouter.post('/logout', logoutController);
authRouter.post('/refresh', refreshController);

/* authenticate runs first: verifies the access token signature, expiry, and audience claim, then populates `res.locals.authenticatedUser`. If it rejects, `meController` never runs. */
authRouter.get('/me', authenticate, meController);

export default authRouter;
