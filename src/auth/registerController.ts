import { Request, Response, NextFunction } from 'express';
import argon2 from 'argon2';
import { SignJWT } from 'jose';
import { importPKCS8 } from 'jose';
import { UserModel } from '@models/User.model.ts';
import { IUserInitial } from '@validators/user.validator.ts';
import { myEnv, staffWhiteList } from '@/validateConfig.ts';
import { sendVerificationEmail } from '@utils/emailService.ts';
import { createErrorResponse } from '@/errorHandlers.ts';
import {
   VERIFICATION_TOKEN_EXPIRY,
   EMAIL_VERIFICATION_AUDIENCE,
} from '@/_SSOT/email_verification_constants.ts';

export async function registerController(
   _req: Request,
   res: Response,
   next: NextFunction
): Promise<void> {
   try {
      /* By the time we're here, validateBody middleware has already run. The cast is safe — validateBody guarantees this shape via the schema. */
      const { username, email, password } = res.locals[
         'validatedBody'
      ] as IUserInitial;

      // ── 1. Whitelist check ──────────────────────────────────────────────
      /* We do this before touching the database or hashing the password. Fail fast, and don't waste compute on requests we'll reject anyway. Do NOT pass it to `next()`. The `next(err)` pattern is for unexpected errors that need to bubble up through the error handler pipeline. A whitelist rejection is not unexpected, it's deliberate. */
      const role = staffWhiteList.get(email);
      if (role === undefined) {
         return void res
            .status(403)
            .json(
               createErrorResponse(
                  'FORBIDDEN',
                  'This email address is not authorised to register.',
                  undefined,
                  res.locals['requestId'] as string | undefined
               )
            );
      }

      // ── 2. Password hashing ─────────────────────────────────────────────
      /* argon2.hash uses argon2id by default — the recommended variant, combining resistance to both side-channel and GPU brute-force attacks. The default memory/time/parallelism parameters are sane for most servers; tune them if you benchmark and find they're too slow or too fast. */
      const passwordHash = await argon2.hash(password);

      // ── 3. Create the user document ─────────────────────────────────────
      /* We let UserModel.create() throw on a duplicate email (MongoDB 11000). `handleMongooseError` already handles that case and returns CONFLICT. No need for a pre-check here — that would be a TOCTOU race condition. */
      const user = await UserModel.create({
         username,
         email,
         passwordHash,
         role,
         // `isVerified` and `isActive` both default to false/true in the schema. We omit them here to let the schema defaults apply.
      });

      // ── 4. Generate verification JWT ────────────────────────────────────
      /* We reuse the same RS256 key pair as access tokens, but stamp the token with a `purpose` claim so the verification endpoint can reject a token that wasn't specifically minted for this flow (e.g. a stolen access token). */
      const privateKey = await importPKCS8(myEnv.jwt.privateKey, 'RS256');

      const verificationToken = await new SignJWT({})
         .setProtectedHeader({ alg: 'RS256' })
         .setSubject(user._id.toString())
         .setAudience(EMAIL_VERIFICATION_AUDIENCE)
         .setIssuedAt()
         .setExpirationTime(VERIFICATION_TOKEN_EXPIRY)
         .sign(privateKey);

      // ── 5. Send verification email ──────────────────────────────────────
      /* If this throws (Resend infrastructure failure), the catch block below passes it to next(), where handleCatchAll will log it and return 500. The user document was already created — they can request a resend later. That resend flow is out of scope for now but worth noting. */
      await sendVerificationEmail({
         toEmail: email,
         username,
         token: verificationToken,
      });

      // ── 6. Respond ──────────────────────────────────────────────────────
      /* 201 Created. We never confirm whether the email was already registered — always the same neutral message regardless. Email enumeration protection. */
      return void res.status(201).json({
         success: true,
         message: `Registration successful. Please check your email to verify your account.`,
      });
   } catch (err) {
      // Hand off to the error handler pipeline. `handleMongooseError` catches the 11000 duplicate; handleCatchAll catches everything else.
      next(err);
   }
}
