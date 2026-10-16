import { TIME_ZONE, LOCALE } from '@ssot/date_time_constants.ts';
import type { IEmailChangeDocumentCreate } from '@models/EmailChange_v3.model.ts';
import type { IUserDocument } from '@models/User_v3.model.ts';
import { escapeHtml } from '@utils/escapeHTML.ts';
import type { ExpandType } from '@utils/helperTypes.ts';
import { sendEmail } from '@services/email.service.ts';

export type IEmailChangeEmailParams = ExpandType<
   Pick<
      IEmailChangeDocumentCreate,
      'oldEmail' | 'newEmail' | 'confirmExpiresAt' | 'cancelExpiresAt'
   > &
      Pick<IUserDocument, 'firstName'> & {
         readonly confirmUrl: string;
         readonly cancelUrl: string;
      }
>;

function formatExpiry(date: Date): string {
   return date.toLocaleString(LOCALE, {
      dateStyle: 'full',
      timeStyle: 'short',
      timeZone: TIME_ZONE,
   });
}

/* Sends two emails as a single logical operation. Both must succeed. If either fails, the error propagates to the caller, which is responsible for rolling back the EmailChange document. */
export async function sendEmailChangeEmails(
   params: IEmailChangeEmailParams
): Promise<void> {
   const {
      firstName,
      oldEmail,
      newEmail,
      confirmUrl,
      cancelUrl,
      confirmExpiresAt,
      cancelExpiresAt,
   } = params;

   const confirmExpiryFormatted = formatExpiry(confirmExpiresAt);
   const cancelExpiryFormatted = formatExpiry(cancelExpiresAt);

   const confirmTemplate = `Hi ${firstName}.\n\nYou requested to change your CambridgeMed email address to ${newEmail}. Click the link below to confirm this change:\n\n${confirmUrl}\n\nThis link expires on ${confirmExpiryFormatted}. If you did not request this change, you can safely ignore this email. A separate cancellation link has been sent to your current address.`;

   const cancelTemplate = `Hi ${firstName}.\n\nA request has been made to change the email address on your CambridgeMed account to ${newEmail}. If this was you, no action is needed here — confirm the change from the email sent to your new address. If this was NOT you, or if you changed your mind, click the link below to cancel the request:\n\n${cancelUrl}\n\nThis cancellation link works even after the change has been confirmed, giving you a window to revert it if needed. The cancellation link expires on ${cancelExpiryFormatted}`;

   // ── Email 1: confirmation → new address ────────────────────────────────────
   /* This link finalises the change. It is sent to the *new* address to prove the user controls it before the switch takes effect. */
   await sendEmail({
      to: newEmail,
      subject: `Confirm your new email address for CambridgeMed`,
      text: confirmTemplate,
      html: `<!DOCTYPE html>
         <html lang="en">
            <body style="font-family:sans-serif;max-width:580px;margin:0 auto;padding:32px 24px;color:#111827;">
               <h2 style="margin:0 0 16px;">Confirm your new email address</h2>
               <p style="margin:0 0 12px;">Hi <strong>${escapeHtml(firstName)}</strong>,</p>
               <p style="margin:0 0 12px;">
                  You requested to change your CambridgeMed email address to <strong>${escapeHtml(newEmail)}</strong>.
               </p>
               <p style="margin:0 0 12px;">
                  Click the link below to confirm this change:
               </p>
               <p style="margin:24px 0;">
                  <a href="${escapeHtml(confirmUrl)}"
                     style="background:#2563eb;color:#ffffff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;display:inline-block;">
                     Confirm Email Change
                  </a>
               </p>
               <p style="color:#6b7280;font-size:13px;margin:0 0 8px;">
                  This link expires on <strong>${confirmExpiryFormatted}</strong>.
               </p>
               <p style="color:#6b7280;font-size:13px;margin:0;">
                  If you did not request this change, you can safely ignore this email. A separate cancellation link has been sent to your current address.
               </p>
            </body>
         </html>`,
      label: 'email-change-confirm',
   });

   // ── Email 2: cancellation → old address ────────────────────────────────────
   /* This link gives the account owner the ability to abort the change — both before it is confirmed (user made a typo) and after (account hijack scenario). It is the stronger of the two: a cancellation after confirmation reverts the email back to this address and kills all active sessions. */
   await sendEmail({
      to: oldEmail,
      subject: `Email change requested for your CambridgeMed account`,
      text: cancelTemplate,
      html: `<!DOCTYPE html>
         <html lang="en">
            <body style="font-family:sans-serif;max-width:580px;margin:0 auto;padding:32px 24px;color:#111827;">
               <h2 style="margin:0 0 16px;">Email change requested on your account</h2>
               <p style="margin:0 0 12px;">Hi <strong>${escapeHtml(firstName)}</strong>,</p>
               <p style="margin:0 0 12px;">
                  A request has been made to change the email address on your CambridgeMed account to <strong>${escapeHtml(newEmail)}</strong>.
               </p>
               <p style="margin:0 0 12px;">
                  If this was you, no action is needed here — confirm the change from the email sent to your new address. If this was NOT you, or if you changed your mind, click the link below to cancel the request:
               </p>
               <p style="margin:24px 0;">
                  <a href="${escapeHtml(cancelUrl)}"
                     style="background:#dc2626;color:#ffffff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;display:inline-block;">
                     Cancel Email Change
                  </a>
               </p>
               <p style="color:#6b7280;font-size:13px;margin:0 0 8px;">
                  This cancellation link works even after the change has been confirmed, giving you a window to revert it if needed.
               </p>
               <p style="color:#6b7280;font-size:13px;margin:0;">
                  The cancellation link expires on <strong>${cancelExpiryFormatted}</strong>.
               </p>
            </body>
         </html>`,
      label: 'email-change-cancel',
   });
}
