import logger from '../logger.ts';
import { myEnv } from '../validateConfig.ts';
import { Redacted } from 'effect';
import { Resend } from 'resend';

/* Instantiated once. The constructor does no network I/O, and the key was already validated by validateConfig at import time, so eager creation is safe. Deliberately NOT exported: callers get `sendEmail`, never the raw SDK client. */
const resend = new Resend(Redacted.value(myEnv.resend.apiKey));

/* Matches AppErrorShape in errorHandlers.ts, so handleEffectFailure turns it into a 503 automatically. The message is CLIENT-FACING (AppErrors are sent verbatim), so provider details stay out of it. */
export class EmailDeliveryError extends Error {
   readonly _tag = 'EmailDeliveryError';
   readonly status = 503;
   readonly code = 'SERVICE_UNAVAILABLE';

   constructor(cause: unknown) {
      super(`We could not send the email. Please try again shortly.`, {
         cause,
      });
      this.name = 'EmailDeliveryError';
   }
}

/* Both `text` and `html` are required on purpose: multipart/alternative improves deliverability and keeps non-HTML clients working. */
export type TransactionalEmail = {
   readonly to: string;
   readonly subject: string;
   readonly text: string;
   readonly html: string;
   /* Short tag for logs, e.g. 'invite' or 'password-reset'. */
   readonly label: string;
};

export async function sendEmail(email: TransactionalEmail): Promise<void> {
   const { label, ...content } = email;

   const { error } = await resend.emails.send({
      from: myEnv.resend.from, // <onboarding@resend.dev> — default sender address until I verify my own domain (which I don't have yet).
      ...content,
   });

   if (error) {
      /* The provider detail goes to the logs, never to the client. */
      logger.error(`Email delivery failed (${label}): ${error.message}`);
      throw new EmailDeliveryError(error);
   }
}
