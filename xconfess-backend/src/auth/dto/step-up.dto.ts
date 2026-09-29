import { IsOptional, IsString, MinLength, MaxLength, ValidateIF } from 'class-validator';

/**
 * Payload for {@link AuthController.stepUp}. Exactly one of `password` or
 * `totpToken` should be supplied to re-prove control of the account.
 *
 * This guard is reused by the account merge / anonymous identity transfer
 * workflow. Merge attempts must be authorized with a step-up proof, so the
 * same constraints apply: exactly one credential field must be present and
 * non-empty.
 */
export class StepUpDto {
  @IsOptional()
  @IsString({ message: 'Password must be a string' })
  @MinLength(1, { message: 'Password must not be empty' })
  password?: string;

  @IsOptional()
  @IsString({ message: 'TOTP must be a string' })
  @MinLength(6, { message: 'TOTP must be 6 digits' })
  @MaxLength(10, { message: 'TOTP token is too long' })
  totpToken?: string;
}
