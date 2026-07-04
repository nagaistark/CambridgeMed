import { myEnv } from 'validateConfig.ts';
import { Resend } from 'resend';
import { Redacted } from 'effect';
import { TIME_ZONE, LOCALE } from '@ssot/date_time_constants.ts';
import { IEmailChangeDefinition } from '@models/EmailChange.model.ts';
import { IUserDefinition } from '@models/User.model.ts';

export type IEmailChangeEmailParams = Pick<
   IEmailChangeDefinition,
   'oldEmail' | 'newEmail' | 'expiresAt'
> &
   Pick<IUserDefinition, 'firstName'> & {
      confirmUrl: string;
      cancelUrl: string;
   };

const resend = new Resend(Redacted.value(myEnv.resend.apiKey));

/* Sends two emails as a single logical operation. Both must succeed. If either fails, the error propagates to the caller, which is responsible for rolling back the EmailChange document. */
export async function sendEmailChangeEmails(
   params: IEmailChangeEmailParams
): Promise<void> {
   const { firstName, oldEmail, newEmail, confirmUrl, cancelUrl, expiresAt } =
      params;

   const expiryFormatted = expiresAt.toLocaleDateString(LOCALE, {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      timeZone: TIME_ZONE,
   });

   type confirmTemplate = {
      greeting: string;
      intro: string;
      link: string;
      exp: string;
      otherwise: string;
   };

   const confirmTemplate: confirmTemplate = {
      greeting: 'Hi',
      intro: 'You requested to change your CambridgeMed email address to',
      link: 'Click the link below to confirm this change:',
      exp: 'This link expires on',
      otherwise:
         'If you did not request this change, you can safely ignore this email. A separate cancellation link has been sent to your current address',
   };

   type CancelTemplate = {
      greeting: string;
      message: string;
      instruction: string;
      clarification: string;
      exp: string;
   };

   const cancelTemplate: CancelTemplate = {
      greeting: 'Hi',
      message:
         'A request has been made to change the email address on your CambridgeMed account to',
      instruction:
         'If this was you, no action is needed here — confirm the change from the email sent to your new address. If this was NOT you, or if you changed your mind, click the link below to cancel the request',
      clarification:
         'This cancellation link works even after the change has been confirmed, giving you a window to revert it if needed',
      exp: 'The cancellation link expires on',
   };

   // ── Email 1: confirmation → new address ────────────────────────────────────
   /* This link finalises the change. It is sent to the *new* address to prove the user controls it before the switch takes effect. */
   const { error: confirmError } = await resend.emails.send({
      from: myEnv.resend.from,
      to: newEmail,
      subject: `Confirm your new email address for CambridgeMed`,
      text: [
         `${confirmTemplate.greeting} ${firstName},`,
         ``,
         `${confirmTemplate.intro} ${newEmail}.`,
         ``,
         `${confirmTemplate.link}`,
         confirmUrl,
         ``,
         `${confirmTemplate.exp} ${expiryFormatted}.`,
         ``,
         `${confirmTemplate.otherwise}`,
      ].join('\n'),
      html: `<!DOCTYPE html>
         <html lang="en">
            <body style="font-family:sans-serif;max-width:580px;margin:0 auto;padding:32px 24px;color:#111827;">
               <h2 style="margin:0 0 16px;">Confirm your new email address</h2>
               <p style="margin:0 0 12px;">${confirmTemplate.greeting} <strong>${firstName}</strong>,</p>
               <p style="margin:0 0 12px;">
                  ${confirmTemplate.intro} <strong>${newEmail}</strong>.
               </p>
               <p style="margin:0 0 12px;">
                  ${confirmTemplate.link}
               </p>
               <p style="margin:24px 0;">
                  <a href="${confirmUrl}"
                     style="background:#2563eb;color:#ffffff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;display:inline-block;">
                     Confirm Email Change
                  </a>
               </p>
               <p style="color:#6b7280;font-size:13px;margin:0 0 8px;">
                  ${confirmTemplate.exp} <strong>${expiryFormatted}</strong>.
               </p>
               <p style="color:#6b7280;font-size:13px;margin:0;">
                  ${confirmTemplate.otherwise}
               </p>
            </body>
         </html>`,
   });

   if (confirmError) {
      throw new Error(
         `Email change confirmation email failed to send: ${confirmError.message}`
      );
   }

   // ── Email 2: cancellation → old address ────────────────────────────────────
   /* This link gives the account owner the ability to abort the change — both before it is confirmed (user made a typo) and after (account hijack scenario). It is the stronger of the two: a cancellation after confirmation reverts the email back to this address and kills all active sessions. */
   const { error: cancelError } = await resend.emails.send({
      from: myEnv.resend.from,
      to: oldEmail,
      subject: `Email change requested for your CambridgeMed account`,
      text: [
         `${cancelTemplate.greeting} ${firstName},`,
         ``,
         `${cancelTemplate.message} ${newEmail}.`,
         ``,
         `${cancelTemplate.instruction}:`,
         cancelUrl,
         ``,
         `${cancelTemplate.clarification}.`,
         ``,
         `${cancelTemplate.exp} ${expiryFormatted}.`,
      ].join('\n'),
      html: `<!DOCTYPE html>
         <html lang="en">
            <body style="font-family:sans-serif;max-width:580px;margin:0 auto;padding:32px 24px;color:#111827;">
               <h2 style="margin:0 0 16px;">Email change requested on your account</h2>
               <p style="margin:0 0 12px;">${cancelTemplate.greeting} <strong>${firstName}</strong>,</p>
               <p style="margin:0 0 12px;">
                  ${cancelTemplate.message} <strong>${newEmail}</strong>.
               </p>
               <p style="margin:0 0 12px;">
                  ${cancelTemplate.instruction}:
               </p>
               <p style="margin:24px 0;">
                  <a href="${cancelUrl}"
                     style="background:#dc2626;color:#ffffff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;display:inline-block;">
                     Cancel Email Change
                  </a>
               </p>
               <p style="color:#6b7280;font-size:13px;margin:0 0 8px;">
                  ${cancelTemplate.clarification}.
               </p>
               <p style="color:#6b7280;font-size:13px;margin:0;">
                  ${cancelTemplate.exp} <strong>${expiryFormatted}</strong>.
               </p>
            </body>
         </html>`,
   });

   if (cancelError) {
      throw new Error(
         `Email change cancellation email failed to send: ${cancelError.message}`
      );
   }
}
