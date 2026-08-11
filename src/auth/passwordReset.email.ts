import { Resend } from 'resend';
import { myEnv } from '../validateConfig.ts';
import { Redacted } from 'effect';
import { TIME_ZONE, LOCALE } from '@ssot/date_time_constants.ts';
import type { IPasswordResetDocument } from '@models/PasswordReset_v3.model.ts';
import type { IUserDocument } from '@models/User_v3.model.ts';
import { escapeHtml } from '@utils/escapeHTML.ts';

export type IPasswordResetEmailParams = Pick<
   IUserDocument,
   'firstName' | 'email'
> &
   Pick<IPasswordResetDocument, 'expiresAt'> & {
      resetUrl: string;
   };

const resend = new Resend(Redacted.value(myEnv.resend.apiKey));

export async function sendPasswordResetEmail(
   params: IPasswordResetEmailParams
): Promise<void> {
   const { firstName, email, resetUrl, expiresAt } = params;

   /* toLocaleString includes both date AND time — critical for a 30-minute window. toLocaleDateString would only show the day, which is useless here. */
   const expiryFormatted = expiresAt.toLocaleString(LOCALE, {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      timeZone: TIME_ZONE,
   });

   const { error } = await resend.emails.send({
      from: myEnv.resend.from,
      to: email,
      subject: `Reset your CambridgeMed password`,
      text: [
         `Hi ${escapeHtml(firstName)},`,
         ``,
         `We received a request to reset the password for your CambridgeMed account.`,
         ``,
         `Click the link below to choose a new password:`,
         resetUrl,
         ``,
         `This link expires at ${expiryFormatted}.`,
         ``,
         `If you did not request a password reset, you can safely ignore this email. Your password will not change.`,
      ].join('\n'),
      html: `<!DOCTYPE html>
         <html lang="en">
            <body style="font-family:sans-serif;max-width:580px;margin:0 auto;padding:32px 24px;color:#111827;">
               <h2 style="margin:0 0 16px;">Reset your password</h2>
               <p style="margin:0 0 12px;">Hi <strong>${firstName}</strong>,</p>
               <p style="margin:0 0 12px;">
                  We received a request to reset the password for your CambridgeMed account.
               </p>
               <p style="margin:0 0 12px;">Click the button below to choose a new password:</p>
               <p style="margin:24px 0;">
                  <a href="${resetUrl}"
                     style="background:#2563eb;color:#ffffff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;display:inline-block;">
                     Reset Password
                  </a>
               </p>
               <p style="color:#6b7280;font-size:13px;margin:0 0 8px;">
                  This link expires at <strong>${expiryFormatted}</strong>.
               </p>
               <p style="color:#6b7280;font-size:13px;margin:0;">
                  If you did not request a password reset, you can safely ignore this email. Your password will not change.
               </p>
            </body>
         </html>`,
   });

   if (error) {
      throw new Error(`Password reset email failed to send: ${error.message}`);
   }
}
