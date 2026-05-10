import { Router } from 'express';
import { validateBody } from '@middleware/validateBody.ts';
import { authenticate } from '@middleware/authenticate.ts';
import { authenticateTotp } from '@middleware/authenticateTotp.ts';
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
import { enrollTotpController } from '@auth/enrollTotp.controller.ts';
import { confirmTotpEnrollmentController } from '@auth/confirmTotpEnrollment.controller.ts';
import { disableTotpController } from '@auth/disableTotp.controller.ts';
import { verifyTotpController } from '@auth/verifyTotp.controller.ts';
import { recoverTotpController } from '@auth/recoverTotp.controller.ts';
import {
   TotpCodeSchema,
   DisableTotpSchema,
   RecoveryCodeSchema,
} from '@auth/totp.schemas.ts';

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

// ── TOTP (authenticated user managing their own 2FA) ─────────────────────────────
authRouter.post(`/totp/enroll`, authenticate, enrollTotpController);

authRouter.post(
   '/totp/enroll/confirm',
   authenticate,
   validateBody(TotpCodeSchema),
   confirmTotpEnrollmentController
);

authRouter.delete(
   '/totp',
   authenticate,
   validateBody(DisableTotpSchema),
   disableTotpController
);

// ── TOTP (mid-login, challenge token only — no session yet) ──────────────────────
authRouter.post(
   '/totp/verify',
   authenticateTotp,
   validateBody(TotpCodeSchema),
   verifyTotpController
);

authRouter.post(
   '/totp/recover',
   authenticateTotp,
   validateBody(RecoveryCodeSchema),
   recoverTotpController
);

export default authRouter;
