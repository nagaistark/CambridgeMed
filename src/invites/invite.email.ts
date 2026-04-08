import { Resend } from 'resend';
import { myEnv } from 'validateConfig.ts';
import type { AllowedUserRole } from '@ssot/user_roles_constants.ts';
import { TIME_ZONE, LOCALE } from '@ssot/date_time_constants.ts';

/* Instantiated once at module load. Resend is stateless between calls, so a single shared instance is correct and efficient. */
const resend = new Resend(myEnv.resend.apiKey);

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

   const issuerFullName = `${issuerFirstName} ${issuerLastName}`;
   const roleLabel = role.charAt(0).toUpperCase() + role.slice(1);

   const expiryFormatted = expiresAt.toLocaleDateString(LOCALE, {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      timeZone: TIME_ZONE,
   });

   const privilegeLine = canIssueInvites
      ? 'You will also have the ability to invite other staff members to the platform.'
      : '';

   const textBody = [
      `${issuerFullName} has invited you to join CambridgeMed as a ${roleLabel}.`,
      privilegeLine,
      '',
      'Click the link below to complete your registration:',
      registrationUrl,
      '',
      `This invitation expires on ${expiryFormatted}.`,
      '',
      'If you were not expecting this invitation, you can safely ignore this email.',
   ]
      .filter(line => line !== undefined && !(line === '' && !privilegeLine))
      .join('\n');

   const htmlBody = `<!DOCTYPE html>
      <html lang="en">
         <body style="font-family:sans-serif;max-width:580px;margin:0 auto;padding:32px 24px;color:#111827;">
            <h2 style="margin:0 0 16px;">You have been invited to CambridgeMed</h2>
            <p style="margin:0 0 12px;">
               <strong>${issuerFullName}</strong> has invited you to join CambridgeMed as a <strong>${roleLabel}</strong>.
            </p>
            ${canIssueInvites ? `<p style="margin:0 0 12px;">You will also have the ability to invite other staff members to the platform.</p>` : ''}
            <p style="margin:24px 0;">
               <a href="${registrationUrl}"
                  style="background:#2563eb; color:#ffffff; padding:12px 24px;border-radius:6px; text-decoration:none; font-weight:600;display:inline-block;">
               Complete Registration
               </a>
            </p>
            <p style="color:#6b7280;font-size:13px;margin:0 0 8px;">
               This invitation expires on <strong>${expiryFormatted}</strong>.
            </p>
            <p style="color:#6b7280;font-size:13px;margin:0;">
               If you were not expecting this invitation, you can safely ignore this email.
            </p>
         </body>
      </html>`;

   const { error } = await resend.emails.send({
      from: myEnv.resend.from, // <onboarding@resend.dev> — default sender address until I verify my own domain (which I don't have yet).
      to,
      subject: `You've been invited to join CambridgeMed`,
      text: textBody,
      html: htmlBody,
   });

   // Normalise Resend's error-as-value into a thrown Error.
   if (error) {
      throw new Error(`Invite email delivery failed: ${error.message}`);
   }
}
