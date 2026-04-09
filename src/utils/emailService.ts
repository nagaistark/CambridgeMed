import { myEnv } from 'validateConfig.ts';
import { Resend } from 'resend';
import { HUMANIZED_EXPIRY } from '@ssot/email_verification_constants.ts';

const resend = new Resend(myEnv.resend.apiKey);
const APP_BASE_URL = myEnv.cors.origins.at(0);

interface SendVerificationEmailOptions {
   toEmail: string;
   username: string;
   token: string; // The signed JWT, not a plaintext secret.
}

export async function sendVerificationEmail({
   toEmail,
   username,
   token,
}: SendVerificationEmailOptions): Promise<void> {
   const verificationUrl = `${APP_BASE_URL}/auth/verify-email?token=${token}`;

   const { error } = await resend.emails.send({
      from: 'Cambridge Med <onboarding@resend.dev>',
      to: [toEmail],
      subject: 'Verify your Cambridge Med account',
      html: `
         <p>Hi ${username},</p>
         <p>Please verify your email address by clicking the link below.
            This link expires in ${HUMANIZED_EXPIRY}.</p>
         <p><a href="${verificationUrl}">Verify my account</a></p>
         <p>If you did not create an account, you can safely ignore this email.</p>
      `,
   });

   /* We throw here so the controller can catch it and handle it explicitly. Resend errors are infrastructure failures, not client mistakes — the user created a valid account, the email just didn't send. The controller decides what to do about that (log it, still return 201, etc.). */
   if (error) {
      throw new Error(
         `Resend failed to send verification email: ${error.message}`
      );
   }
}
