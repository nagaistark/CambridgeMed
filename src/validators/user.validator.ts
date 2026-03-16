import {
   email,
   InferOutput,
   maxLength,
   minLength,
   nonEmpty,
   pipe,
   regex,
   strictObject,
   string,
   transform,
} from 'valibot';

export const RegisterRequestSchema = strictObject({
   username: pipe(
      string(`Must be a string`),
      minLength(3, `Username must be at least 3 characters`),
      maxLength(32, `Username is too long`),
      regex(
         /^[a-zA-Z0-9_]+$/,
         `Username can only contain letters, numbers, and underscores`
      ),
      transform(str => {
         return str.toLowerCase();
      })
   ),
   email: pipe(
      string(`Must be a string`),
      nonEmpty(`Please enter your email`),
      email(`Incorrectly formatted email`),
      maxLength(64, `Your email is too long`),
      transform(str => {
         return str.toLowerCase();
      })
   ),
   password: pipe(
      string(`Must be a string`),
      minLength(8, `Password must be at least 8 characters`),
      maxLength(128, `Password is too long.`),
      regex(/[A-Z]/, `Password must contain at least one uppercase letter`),
      regex(/[a-z]/, `Password must contain at least one lowercase letter`),
      regex(/[0-9]/, `Password must contain at least one number`)
   ),
});

export type IUserInitial = InferOutput<typeof RegisterRequestSchema>;
