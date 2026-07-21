import { PatientSummary } from '@models/Patient_v3.model.ts';
import { Either, Schema } from 'effect';
import { ObjectId } from 'mongodb';
import { nameString, stringToObjectId } from './effectSchemaReusables.ts';

type PatientCursorData = readonly [
   lastName: string,
   firstName: string,
   id: ObjectId,
];

export function encodeCursor(patient: PatientSummary): string {
   const cursorData: PatientCursorData = [
      patient.intakeInfo.demographics.lastName,
      patient.intakeInfo.demographics.firstName,
      patient._id,
   ];
   // Convert the array to a JSON string, then encode it as Base64 so the frontend just sees a random string
   return Buffer.from(JSON.stringify(cursorData)).toString('base64url');
}

const PatientCursorSchema = Schema.Tuple(
   nameString,
   nameString,
   stringToObjectId
);

export function decodeCursor(cursorString: string): PatientCursorData | null {
   try {
      const decoded = Buffer.from(cursorString, 'base64url').toString('utf-8');
      const parsed: unknown = JSON.parse(decoded);
      const result = Schema.decodeUnknownEither(PatientCursorSchema)(parsed);
      return Either.isRight(result) ? result.right : null;
   } catch {
      return null; // If decoding fails, treat it as a bad request or start from the beginning
   }
}
