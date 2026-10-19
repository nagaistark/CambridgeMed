import type { Request, NextFunction } from 'express';
import { Either, Schema } from 'effect';
import { generateSecret, generateURI } from 'otplib';
import QRCode from 'qrcode';
import { ObjectId } from 'mongodb';
import {
   getUserCollection,
   UserTotpManagementValidator,
   type IUserDocument,
   type IUserTotpManagement,
} from '@models/User_v3.model.ts';
import { encryptTotpSecret } from '@utils/totpCrypto.ts';
import { verifyPassword } from '@utils/hashAndVerify.ts';
import { createErrorResponse } from '../errorHandlers.ts';
import type {
   AuthenticatedResponse,
   ResponseWithValidatedBody,
} from '@utils/customTypedResponses.ts';
import type { TotpEnrollBody } from '@auth/totp.schemas.ts';
import { TOTP_ISSUER, TOTP_SECRET_BYTES } from '@ssot/totp_constants.ts';
import { USER_TOTP_MANAGEMENT_PROJECTION } from '@ssot/user_mongodb_query_projection_constants.ts';
import type {
   StrictFindOneOptions,
   StrictMongoFilter,
   StrictUpdate,
} from '@utils/pathFinder_v3.ts';

export async function enrollTotpController(
   _req: Request,
   res: ResponseWithValidatedBody<TotpEnrollBody> & AuthenticatedResponse,
   next: NextFunction
): Promise<void> {
   try {
      const requestId = res.locals.requestId;
      const { sub } = res.locals.authenticatedUser;
      const { currentPassword } = res.locals.validatedBody;

      const userCollection = getUserCollection();
      const userRaw = await userCollection.findOne<IUserTotpManagement>(
         { _id: new ObjectId(sub) } satisfies StrictMongoFilter<IUserDocument>,
         {
            projection: USER_TOTP_MANAGEMENT_PROJECTION,
         } satisfies StrictFindOneOptions<IUserTotpManagement>
      );

      if (userRaw === null) {
         return void res
            .status(404)
            .json(
               createErrorResponse('NOT_FOUND', `Account not found.`, requestId)
            );
      }

      const decodedUser = Schema.decodeUnknownEither(
         UserTotpManagementValidator
      )(userRaw);
      if (Either.isLeft(decodedUser)) {
         throw new Error(
            `Stored user failed validation during TOTP enrollment.`,
            { cause: decodedUser.left }
         );
      }
      const user = decodedUser.right;

      /* Step-up: a hijacked session alone must not be able to plant an authenticator. Checked before every other guard so they cannot become a probing oracle. */
      const isPasswordValid = await verifyPassword(
         user.passwordHash,
         currentPassword
      );
      if (!isPasswordValid) {
         return void res
            .status(401)
            .json(
               createErrorResponse(
                  'UNAUTHORIZED',
                  `Current password is incorrect.`,
                  requestId
               )
            );
      }

      if (!user.isActive) {
         return void res
            .status(403)
            .json(
               createErrorResponse(
                  'FORBIDDEN',
                  `This account has been deactivated. Please contact an administrator.`,
                  requestId
               )
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

      // ── Generate and persist the PENDING secret ────────────────────────────────
      /* A previous unconfirmed enrollment is simply overwritten: it was never live. The filter pins `isTotpEnabled: false`, so a confirm that lands between our read and this write cannot have its live secret clobbered. */
      const rawSecret = generateSecret({ length: TOTP_SECRET_BYTES });
      const encryptedSecret = encryptTotpSecret(rawSecret);

      const stored = await userCollection.updateOne(
         {
            _id: user._id,
            isTotpEnabled: false,
         } satisfies StrictMongoFilter<IUserDocument>,
         {
            $set: { totpPendingSecret: encryptedSecret },
         } satisfies StrictUpdate<IUserDocument>
      );

      if (stored.matchedCount === 0) {
         return void res
            .status(409)
            .json(
               createErrorResponse(
                  'CONFLICT',
                  `Two-factor authentication state changed. Please try again.`,
                  requestId
               )
            );
      }

      const otpauthUri = generateURI({
         secret: rawSecret,
         issuer: TOTP_ISSUER,
         label: user.email,
      });
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
