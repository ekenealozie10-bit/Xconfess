import { IsOptional, IsString, MinLength, MaxLength, ValidateIf } from 'class-validator';

/**
 * Payload for {@link AuthController.stepUp}. Exactly one of `password`,
 * `totpToken`, or `webAuthnAssertion` should be supplied to re-prove control of the account.
 * Password and TOTP are legacy fallbacks; passkey assertion is the preferred,
 * phishing-resistant mechanism.
 */
export class StepUpDto {
  @IsOptional()
  @IsString( { message: 'Password must be a string' })
  @MinLength(1, { message: 'Password must not be empty' })
  password?: string;

  @IsOptional()
  @IsString({ message: 'TOTP token must be a string' })
  @MinLength(6, { message: 'TOTP token must be 6 digits' })
  @MaxLength(10, { message: 'TOTP token is too long' })
  totpToken?: string;

  /**
   * Base64url-encoded WebAuthn assertion response (PublicKeyCredential.json).
   * Verified against the stored challenge, origin, and RP id by the WebAuthn service.
   */
  @IsOptional()
  @IsString({ message: 'WebAuthn assertion must be a string' })
  @MinLength(1, { message: 'WebAuthn assertion must not be empty' })
  webAuthnAssertion?: string;

  /**
   * Opaque challenge identifier issued by the server for this step-up attempt.
   * Required when `webAuthnAssertion` is present so replayed assertions can be rejected.
   */
  @IsOptional()
  @IsString( { message: 'WebAuthn challenge id must be a string' })
  @MinLength(1, { message: 'WebAuthn challenge id must not be empty' })
  webAuthnChallengeId?: string;
}
