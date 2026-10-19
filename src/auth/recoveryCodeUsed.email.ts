import { TIME_ZONE, LOCALE } from '@ssot/date_time_constants.ts';
import type { IUserDocument } from '@models/User_v3.model.ts';
import { escapeHtml } from '@utils/escapeHTML.ts';
import type { ExpandType } from '@utils/helperTypes.ts';
import { sendEmail } from '@services/email.service.ts';

export type IRecoveryCodeUsedEmailParams = ExpandType<
   Pick<IUserDocument, 'firstName' | 'email'> & {
      readonly remainingRecoveryCodes: number;
   }
>;

/* A recovery code is the "break glass" credential. Using one should never be silent. */
export async function sendRecoveryCodeUsedEmail(
   params: IRecoveryCodeUsedEmailParams
): Promise<void> {
   const { firstName, email, remainingRecoveryCodes } = params;

   const usedAt = new Date().toLocaleString(LOCALE, {
      dateStyle: 'full',
      timeStyle: 'short',
      timeZone: TIME_ZONE,
   });

   const text = `Hi ${firstName}.\n\nA recovery code was used to sign in to your CambridgeMed account on ${usedAt}. You have ${remainingRecoveryCodes} recovery code(s) remaining.\n\nIf this was you, no action is needed. If it was NOT you, use "Forgot password" to reset your password right away and contact an administrator.`;

   const html = `<!DOCTYPE html>
      <html lang="en">
         <body style="font-family:sans-serif;max-width:580px;margin:0 auto;padding:32px 24px;color:#111827;">
            <h2 style="margin:0 0 16px;">A recovery code was used on your account</h2>
            <p style="margin:0 0 12px;">Hi <strong>${escapeHtml(firstName)}</strong>,</p>
            <p style="margin:0 0 12px;">
               A recovery code was used to sign in to your CambridgeMed account on <strong>${usedAt}</strong>.
               You have <strong>${remainingRecoveryCodes}</strong> recovery code(s) remaining.
            </p>
            <p style="color:#6b7280;font-size:13px;margin:0;">
               If this was you, no action is needed. If it was NOT you, use "Forgot password" to reset your password right away and contact an administrator.
            </p>
         </body>
      </html>`;

   await sendEmail({
      to: email,
      subject: `A recovery code was used on your CambridgeMed account`,
      text,
      html,
      label: 'recovery-code-used',
   });
}
