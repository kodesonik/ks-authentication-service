import { Controller, Get, Post, Body, Patch, Request } from '@nestjs/common';
import { AccountService } from './account.service';
import { CreateAccountDto } from './dto/create-account.dto';
import { ApiBody, ApiHeader, ApiParam, ApiTags } from '@nestjs/swagger';
import { SendOtpDto } from './dto/send-otp.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { Public } from '../../decorators/public.decorator';

@Controller('account')
export class AccountController {
  constructor(private readonly accountService: AccountService) {}

  @ApiTags('Verify email or phone number')
  @ApiBody({
    description: 'Email or phone number to verify',
    schema: {
      type: 'object',
      properties: {
        credential: {
          type: 'string',
          description: 'Email or phone number',
        },
      },
    },
  })
  @Public()
  @Post('send-otp')
  verifyPhoneNumber(@Body() sendOtpDto: SendOtpDto) {
    const { credential } = sendOtpDto;
    return this.accountService.sendOtp(credential, false);
  }

  @ApiTags('Verify OTP')
  @ApiBody({
    description: 'Verify OTP',
    schema: {
      type: 'object',
      properties: {
        credential: {
          type: 'string',
          description: 'Email or phone number',
        },
        otp: {
          type: 'string',
          description: 'OTP',
        },
        device: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              example: 'device-id',
              description: 'Device ID',
            },
            token: {
              type: 'string',
              example: 'device-token',
              description: 'Notification token',
            },
            platform: {
              type: 'string',
              example: 'android',
              enum: ['android', 'ios'],
              description: 'Device platform',
            },
            brand: {
              type: 'string',
              example: 'samsung',
              description: 'Device brand',
            },
            model: {
              type: 'string',
              example: 'samsung',
              description: 'Device model',
            },
            version: {
              type: 'string',
              example: '10',
              description: 'Device version',
            },
          },
        },
      },
    },
  })
  @Public()
  @Post('verify-otp')
  verifyOtp(
    @Body()
    verifyOtpDto: VerifyOtpDto,
  ) {
    const { credential, otp, device } = verifyOtpDto;
    return this.accountService.verifyOtp(credential, otp, device);
  }

  @ApiTags('Refresh token')
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        refresh_token: {
          type: 'string',
          description: 'Refresh token',
        },
      },
    },
  })
  @Public()
  @Post('refresh-token') // refresh token
  refreshToken(@Body() body: { refresh_token: string }) {
    const { refresh_token } = body ?? {};
    return this.accountService.refreshToken(refresh_token);
  }

  @ApiTags('Get profile')
  @ApiHeader({
    name: 'Authorization',
    description: 'Bearer token',
  })
  @Get('profile')
  getProfile(@Request() req) {
    const { id } = req?.user ?? {};
    return this.accountService.getProfile(id);
  }

  @ApiTags('Complete profile')
  @ApiParam({
    name: 'id',
    description: 'Account ID',
    type: 'string',
  })
  @ApiBody({
    description: 'Complete profile',
    schema: {
      type: 'object',
      properties: {
        username: {
          type: 'string',
          description: 'Username',
          example: 'john_doe',
        },
        firstname: {
          type: 'string',
          description: 'First name',
          example: 'John',
        },
        lastname: {
          type: 'string',
          description: 'Last name',
          example: 'Doe',
        },
        birthdate: {
          type: 'string',
          description: 'Birthdate',
          example: '1990-01-01',
        },
        gender: {
          type: 'string',
          description: 'Masculin, Feminin, Other',
          example: 'M',
        },
        email: {
          type: 'string',
          description: 'Email',
          example: 'johndoe@mydomain.com',
        },
        phoneNumber: {
          type: 'string',
          description: 'Phone number',
          example: '+33612345678',
        },
      },
    },
  })
  @Patch('complete-profile')
  completeProfile(@Request() req, @Body() createAccountDto: CreateAccountDto) {
    const { id } = req?.user ?? {};
    return this.accountService.completeProfile(id, createAccountDto);
  }
}
