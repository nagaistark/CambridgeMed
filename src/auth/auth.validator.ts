/* It's intentional that login has NO password complexity rules. We are verifying against an existing Argon2 hash, not enforcing creation constraints. maxLength matches the registration ceiling so an over-long payload is rejected early before we even touch the database. */

import {
   email,
   InferOutput,
   maxLength,
   minLength,
   nonEmpty,
   pipe,
   strictObject,
   string,
   transform,
} from 'valibot';

export const LoginSchema = strictObject({
   email: pipe(
      string(`Must be a string.`),
      nonEmpty(`Please enter your email.`),
      email(`Incorrectly formatted email.`),
      maxLength(64, `Your email is too long.`),
      transform(str => str.toLowerCase())
   ),
   password: pipe(
      string(`Must be a string.`),
      nonEmpty(`Please enter your password.`),
      minLength(1, `Password cannot be empty.`),
      maxLength(128, `Password is too long.`)
   ),
});

export type LoginBody = InferOutput<typeof LoginSchema>;
