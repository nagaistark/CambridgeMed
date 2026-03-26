import { Router } from 'express';
import { validateBody } from '@middleware/validateBody.ts';
import { LoginSchema } from '@auth/auth.validator.ts';
import { loginController } from '@auth/login.controller.ts';
import { logoutController } from '@auth/logout.controller.ts';

const authRouter = Router();

authRouter.post('/login', validateBody(LoginSchema), loginController);
authRouter.post('/logout', logoutController);

export default authRouter;
