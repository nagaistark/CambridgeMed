import { Router } from 'express';
import { validateBody } from '@middleware/validateBody.ts';
import { authenticate } from '@middleware/authenticate.ts';
import { LoginSchema } from '@auth/login.schema.ts';
import { ForgotPasswordSchema } from '@auth/forgotPassword.schema.ts';
import { ResetPasswordSchema } from '@auth/resetPassword.schema.ts';
import { loginController } from '@auth/login.controller.ts';
import { logoutController } from '@auth/logout.controller.ts';
import { meController } from '@auth/me.controller.ts';
import { refreshController } from '@auth/refresh.controller.ts';
import { forgotPasswordController } from '@auth/forgotPassword.controller.ts';
import { resetPasswordController } from '@auth/resetPassword.controller.ts';
import {
   forgotPasswordRateLimiter,
   resetPasswordRateLimiter,
} from '@utils/rateLimiters.ts';

const authRouter = Router();

authRouter.post('/login', validateBody(LoginSchema), loginController);
authRouter.post('/logout', logoutController);
authRouter.post('/refresh', refreshController);
authRouter.get('/me', authenticate, meController);

// ── Password recovery (unauthenticated) ──────────────────────────────────────────
/* Both routes are public. The user has no session — that's the whole point. The rate limiter on forgot-password is the primary abuse-prevention mechanism since the route is both public and triggers an outbound email. */
authRouter.post(
   '/forgot-password',
   forgotPasswordRateLimiter,
   validateBody(ForgotPasswordSchema),
   forgotPasswordController
);

authRouter.post(
   '/reset-password/:token',
   resetPasswordRateLimiter,
   validateBody(ResetPasswordSchema),
   resetPasswordController
);

export default authRouter;
