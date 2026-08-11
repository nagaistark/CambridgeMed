import type { Request, NextFunction } from 'express';
import { generateSecret, generateURI } from 'otplib';
import QRCode from 'qrcode';
import { getUserCollection, IUserDocument } from '@models/User_v3.model.ts';
import { encryptTotpSecret } from '@utils/totpCrypto.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import { AuthenticatedResponse } from '@utils/customTypedResponses.ts';
import { TOTP_ISSUER, TOTP_SECRET_BYTES } from '@ssot/totp_constants.ts';
import { ObjectId } from 'mongodb';
import { StrictMongoFilter, StrictUpdate } from '@utils/pathFinder_v3.ts';

export async function enrollTotpController(
   _req: Request,
   res: AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub } = res.locals.authenticatedUser;

      const userCollection = getUserCollection();
      const user = await userCollection.findOne({
         _id: new ObjectId(sub),
      } satisfies StrictMongoFilter<IUserDocument>);

      if (!user) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `Account not found.`, requestId)
            );
      }

      if (user.isTotpEnabled) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  `Two-factor authentication is already enabled. Disable it first to re-enroll.`,
                  requestId
               )
            );
      }

      // ── Generate and persist the new secret ────────────────────────────────────
      /* If the user previously started enrollment without confirming, we simply overwrite the old pending secret. Since isTotpEnabled is still false, the previous secret was never "live" — overwriting is safe. */
      const rawSecret = generateSecret({ length: TOTP_SECRET_BYTES });
      const encryptedSecret = encryptTotpSecret(rawSecret);

      await userCollection.updateOne(
         { _id: user._id } satisfies StrictMongoFilter<IUserDocument>,
         {
            $set: { totpSecret: encryptedSecret },
         } satisfies StrictUpdate<IUserDocument>
      );

      // ── Build the QR code ─────────────────────────────────────────────────────
      /* generateURI produces the otpauth://totp/... string that every authenticator app understands. `label` is the account name shown inside the app; `issuer` is the app/service name shown above it. */
      const otpauthUri = generateURI({
         secret: rawSecret,
         issuer: TOTP_ISSUER,
         label: user.email,
      });

      /* toDataURL produces a base64-encoded PNG the frontend can drop directly into an <img src="..."> tag — no extra processing needed. */
      const qrCodeDataUrl = await QRCode.toDataURL(otpauthUri);

      return void res.status(200).json({
         success: true,
         message: `Scan the QR code with your authenticator app, then confirm with a 6-digit code.`,
         qrCode: qrCodeDataUrl,
         manualEntryKey: rawSecret, // For users who cannot scan a QR code
      });
   } catch (err) {
      next(err);
   }
}
