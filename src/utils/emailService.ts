import { Request, Response } from 'express';
import { myEnv } from '@/validateConfig.ts';
import { Resend } from 'resend';

const resend = new Resend(myEnv.apiKeys.resend);

export const sendVerificationEmail = async (_req: Request, res: Response) => {
   const { data, error } = await resend.emails.send({
      from: 'Acme <onboarding@resend.dev>',
      to: ['jascha.stark+resend@gmail.com'],
      subject: 'Verification required.',
      html: '<strong>Verification token...</strong>',
   });

   if (error) {
      return res.status(400).json({ error });
   }

   res.status(200).json({ data });
};
