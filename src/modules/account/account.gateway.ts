import { Controller, UseFilters } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { AccountService } from './account.service';
import {
  SendOtpDto,
  VerifyOtpDto,
  LoginDto,
  RegisterDto,
  ForgotPasswordDto,
  ResetPasswordDto,
} from './dto';
import { ExceptionFilter } from 'src/filters/rpc-exception.filter';
import { ChangePasswordDto } from './dto/change-password.dto';

@Controller()
@UseFilters(new ExceptionFilter())
export class AccountGateway {
  constructor(private readonly accountService: AccountService) {}

  // ´decode-token
  @MessagePattern({ cmd: 'decode-token' })
  decodeToken(@Payload() data: { token: string; tokenType: any }) {
    const { token, tokenType } = data;
    if (!token) {
      return { error: 'Token is required', status: 400 };
    }
    return this.accountService.decodeToken(token, tokenType);
  }

  // Refresh token
  @MessagePattern({ cmd: 'refresh-token' })
  refreshToken(@Payload() data: { refresh_token: string }) {
    const { refresh_token } = data;
    if (!refresh_token) {
      return { error: 'Refresh token is required', status: 400 };
    }
    return this.accountService.refreshToken(refresh_token);
  }

  //register
  @MessagePattern({ cmd: 'register' })
  register(@Payload() registerDto: RegisterDto) {
    try {
      return this.accountService.register(registerDto);
    } catch (error) {
      console.log('error', error);
      return { error: error.message, status: error.status };
    }
  }

  // Confirm account
  @MessagePattern({ cmd: 'confirm-account' })
  confirmAccount(@Payload() data: { user: any; otp: string }) {
    const { otp, user } = data;
    if (!otp) {
      return { error: 'OTP is required', status: 400 };
    }
    return this.accountService.confirmAccount(user.id, otp);
  }

  //login
  @MessagePattern({ cmd: 'login' })
  login(@Payload() loginDto: LoginDto) {
    try {
      return this.accountService.login(loginDto);
    } catch (error) {
      console.log('error', error);
      return { error: error.message, status: error.status };
    }
  }

  //logout
  @MessagePattern({ cmd: 'logout' })
  logout(@Payload() data: { token: string }) {
    const { token } = data;
    return this.accountService.logout(token);
  }

  //change username
  @MessagePattern({ cmd: 'change-username' })
  changeUsername(@Payload() data: { id: string; username: string }) {
    const { id, username } = data;
    return this.accountService.changeUsername(id, username);
  }

  //change email
  @MessagePattern({ cmd: 'change-email' })
  changeEmail(@Payload() data: { id: string; email: string }) {
    const { id, email } = data;
    return this.accountService.changeEmail(id, email);
  }

  //change phone
  @MessagePattern({ cmd: 'change-phone' })
  changePhone(@Payload() data: { id: string; phone: string }) {
    const { id, phone } = data;
    return this.accountService.changePhone(id, phone);
  }

  //confirm change email
  @MessagePattern({ cmd: 'confirm-change-email' })
  confirmChangeEmail(@Payload() data: { id: string; otp: string }) {
    const { id, otp } = data;
    return this.accountService.confirmChangeEmail(id, otp);
  }

  //confirm change phone
  @MessagePattern({ cmd: 'confirm-change-phone' })
  confirmChangePhone(@Payload() data: { id: string; otp: string }) {
    const { id, otp } = data;
    return this.accountService.confirmChangePhone(id, otp);
  }

  //forgot password
  @MessagePattern({ cmd: 'forgot-password' })
  forgotPassword(@Payload() forgotPasswordDto: ForgotPasswordDto) {
    const { credential } = forgotPasswordDto;
    return this.accountService.forgotPassword(credential);
  }

  //reset password
  @MessagePattern({ cmd: 'reset-password' })
  resetPassword(@Payload() resetPasswordDto: ResetPasswordDto) {
    const { id, password } = resetPasswordDto;
    return this.accountService.resetPassword(id, password);
  }

  //change password
  @MessagePattern({ cmd: 'change-password' })
  changePassword(@Payload() changePasswordDto: ChangePasswordDto) {
    const { id, oldPassword, newPassword } = changePasswordDto;
    return this.accountService.changePassword(id, oldPassword, newPassword);
  }

  @MessagePattern({ cmd: 'send-otp' })
  verifyPhoneNumber(@Payload() sendOtpDto: SendOtpDto) {
    const { credential } = sendOtpDto;
    return this.accountService.sendOtp(credential, false);
  }

  @MessagePattern({ cmd: 'verify-otp' })
  verifyOtp(@Payload() verifyOtpDto: VerifyOtpDto) {
    const { credential, otp, device } = verifyOtpDto;
    return this.accountService.verifyOtp(credential, otp, device);
  }

  @MessagePattern({ cmd: 'get-profile' })
  getProfile(@Payload() body: { id: string }) {
    const { id } = body;
    return this.accountService.getProfile(id);
  }

  @MessagePattern({ cmd: 'complete-profile' })
  completeProfile(@Payload() data: { user: any; completeProfileDto: any }) {
    const { user, completeProfileDto } = data;
    console.log('user', user);
    if (!user) {
      return { error: 'User is required', status: 400 };
    }
    return this.accountService.completeProfile(user._id, completeProfileDto);
  }

  @MessagePattern({ cmd: 'check-username' })
  async checkUsername(@Payload() checkUsernameDto: { username: string }) {
    const exist = !(await this.accountService.isUsernameUnique(
      checkUsernameDto.username,
    ));
    return { exist };
    // return this.accountService.create(createAccountDto);
  }

  @MessagePattern({ cmd: 'check-email' })
  async checkEmail(@Payload() checkEmailDto: { email: string }) {
    const exist = !(await this.accountService.isEmailUnique(
      checkEmailDto.email,
    ));
    return { exist };
    // return this.accountService.create(createAccountDto);
  }

  @MessagePattern({ cmd: 'check-phone' })
  async checkPhone(@Payload() checkPhoneDto: { phone: string }) {
    const exist = !(await this.accountService.isPhoneUnique(
      checkPhoneDto.phone,
    ));
    return { exist };
  }

  @MessagePattern({ cmd: 'delete-account' })
  deleteAccount(@Payload() payload: any) {
    return this.accountService.delete(payload.id, payload.password);
  }

  @MessagePattern({ cmd: 'confirm-delete-account' })
  confirmDeleteAccount(@Payload() payload: any) {
    return this.accountService.confirmDelete(payload.id, payload.otp);
  }
}
