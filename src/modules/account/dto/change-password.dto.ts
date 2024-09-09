import { IsNotEmpty, IsString, MinLength } from 'class-validator';

export class ChangePasswordDto {
  @IsNotEmpty()
  @IsString()
  id: string;

  @IsNotEmpty()
  @IsString()
  oldPassword: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(8)
  newPassword: string;
}
