import type { AllowedUserRole } from '@ssot/user_roles_constants.ts';
import { TIME_ZONE, LOCALE } from '@ssot/date_time_constants.ts';
import { escapeHtml } from '@utils/escapeHTML.ts';
import { sendEmail } from '@services/email.service.ts';

export type IInviteEmailParams = {
   to: string;
   issuerFirstName: string;
   issuerLastName: string;
   role: AllowedUserRole;
   canIssueInvites: boolean;
   registrationUrl: string;
   expiresAt: Date;
};

export async function sendInviteEmail(
   params: IInviteEmailParams
): Promise<void> {
   const {
      to,
      issuerFirstName,
      issuerLastName,
      role,
      canIssueInvites,
      registrationUrl,
      expiresAt,
   } = params;

   const issuerFullNameHtml = `${escapeHtml(issuerFirstName)} ${escapeHtml(issuerLastName)}`;
   const issuerFullNameText = `${issuerFirstName} ${issuerLastName}`;
   const roleLabel = role.charAt(0).toUpperCase() + role.slice(1);

   const expiryFormatted = expiresAt.toLocaleString(LOCALE, {
      dateStyle: 'full',
      timeStyle: 'short',
      timeZone: TIME_ZONE,
   });

   type Template = {
      intro: string;
      privilege: string;
      link: string;
      exp: string;
      otherwise: string;
   };

   const template: Template = {
      intro: 'has invited you to join CambridgeMed as a',
      privilege:
         'You will also have the ability to invite other staff members to the platform',
      link: 'Click the link below to complete your registration:',
      exp: 'This invitation expires on',
      otherwise:
         'If you were not expecting this invitation, you can safely ignore this email',
   };

   function renderMessage(): {
      text: string;
      html: string;
   } {
      const text = [
         `${issuerFullNameText} ${template.intro} ${roleLabel}.`,
         ...(canIssueInvites ? [`${template.privilege}.`] : []),
         '',
         template.link,
         registrationUrl,
         '',
         `${template.exp} ${expiryFormatted}.`,
         '',
         `${template.otherwise}.`,
      ].join('\n');

      const html = `<!DOCTYPE html>
      <html lang="en">
         <body style="font-family:sans-serif;max-width:580px;margin:0 auto;padding:32px 24px;color:#111827;">
            <h2 style="margin:0 0 16px;">You have been invited to CambridgeMed</h2>
            <p style="margin:0 0 12px;">
               <strong>${escapeHtml(issuerFullNameHtml)}</strong> ${template.intro} <strong>${roleLabel}</strong>.
            </p>
            ${canIssueInvites ? `<p style="margin:0 0 12px;">${template.privilege}.</p>` : ''}
            <p style="margin:24px 0;">
               <a href="${escapeHtml(registrationUrl)}" style="background:#2563eb; color:#ffffff; padding:12px 24px;border-radius:6px; text-decoration:none; font-weight:600;display:inline-block;">Complete Registration</a>
            </p>
            <p style="color:#6b7280;font-size:13px;margin:0 0 8px;">
               ${template.exp} <strong>${expiryFormatted}</strong>.
            </p>
            <p style="color:#6b7280;font-size:13px;margin:0;">
               ${template.otherwise}.
            </p>
         </body>
      </html>`;
      return { text, html };
   }

   const { text, html } = renderMessage();

   await sendEmail({
      to,
      subject: `You've been invited to join CambridgeMed`,
      text,
      html,
      label: 'invite',
   });
}
