import supertest from 'supertest';
import app from 'app.ts';
import type { LoginBody } from '@auth/login.schema.ts';

export async function loginAs(
   credentials: LoginBody
): Promise<supertest.Agent> {
   const agent = supertest.agent(app);

   const res = await agent
      .post('/api/auth/login')
      .send({ email: credentials.email, password: credentials.password });

   if (res.status !== 200) {
      throw new Error(
         `loginAs failed for ${credentials.email}: HTTP ${res.status} — ${JSON.stringify(res.body)}`
      );
   }

   return agent;
}
