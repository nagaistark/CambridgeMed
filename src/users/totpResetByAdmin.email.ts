import { TIME_ZONE, LOCALE } from '@ssot/date_time_constants.ts';
import type { IUserDocument } from '@models/User_v3.model.ts';
import { escapeHtml } from '@utils/escapeHTML.ts';
import type { ExpandType } from '@utils/helperTypes.ts';
import { sendEmail } from '@services/email.service.ts';

export type ITotpResetByAdminEmailParams = ExpandType<
   Pick<IUserDocument, 'firstName' | 'email'>
>;

/* Goes to the address ON FILE, so the real owner learns about it even if somebody else asked for the reset. */
export async function sendTotpResetByAdminEmail(
   params: ITotpResetByAdminEmailParams
): Promise<void> {
   const { firstName, email } = params;

   const resetAt = new Date().toLocaleString(LOCALE, {
      dateStyle: 'full',
      timeStyle: 'short',
      timeZone: TIME_ZONE,
   });

   const text = `Hi ${firstName}.\n\nAn administrator reset two-factor authentication on your CambridgeMed account on ${resetAt}. All your devices have been signed out.\n\nBefore you can log in again, use "Forgot password" to choose a new password. You can then enable two-factor authentication again from your security settings.\n\nIf you did not ask for this, contact an administrator immediately.`;

   const html = `<!DOCTYPE html>
      <html lang="en">
         <body style="font-family:sans-serif;max-width:580px;margin:0 auto;padding:32px 24px;color:#111827;">
            <h2 style="margin:0 0 16px;">Two-factor authentication was reset</h2>
            <p style="margin:0 0 12px;">Hi <strong>${escapeHtml(firstName)}</strong>,</p>
            <p style="margin:0 0 12px;">
               An administrator reset two-factor authentication on your CambridgeMed account on <strong>${resetAt}</strong>. All your devices have been signed out.
            </p>
            <p style="margin:0 0 12px;">
               Before you can log in again, use "Forgot password" to choose a new password. You can then enable two-factor authentication again from your security settings.
            </p>
            <p style="color:#6b7280;font-size:13px;margin:0;">
               If you did not ask for this, contact an administrator immediately.
            </p>
         </body>
      </html>`;

   await sendEmail({
      to: email,
      subject: `Two-factor authentication was reset on your CambridgeMed account`,
      text,
      html,
      label: 'totp-reset-by-admin',
   });
}
