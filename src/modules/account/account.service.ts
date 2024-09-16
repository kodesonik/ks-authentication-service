import { Device } from './entities/device.schema';
import {
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException,
  // NotFoundException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { InjectModel } from '@nestjs/mongoose';
import { Account } from './entities/account.schema';
import { Model } from 'mongoose';
import RedisService from 'src/services/redis.service';
import { JwtService } from '@nestjs/jwt';
import { IDevice } from 'src/models/device';
import { ConfigService } from '@nestjs/config';
import { AuthMethod, Gender, Role } from 'src/models';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { ClientProxy } from '@nestjs/microservices';
import { firstValueFrom } from 'rxjs';

@Injectable()
export class AccountService {
  constructor(
    @InjectModel(Account.name) private readonly accountModel: Model<Account>,
    @InjectModel(Device.name) private readonly deviceModel: Model<Device>,
    private readonly redisService: RedisService,
    @Inject('MESSAGING_SERVICE')
    private readonly messagingService: ClientProxy,
    @Inject('BACKUP_SERVICE') private readonly backupService: ClientProxy,
    @Inject('TRANSACTION_SERVICE')
    private readonly transactionService: ClientProxy,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  private isEmail(key: string) {
    return key.includes('@');
  }

  private async hashPassword(password: string): Promise<string> {
    return await bcrypt.hash(password, 10);
  }

  async isEmailUnique(email: string): Promise<boolean> {
    //Check if the user email provide is unique
    const response = await this.accountModel.findOne({ email });
    // Logger.log(response, 'isEmailUnique');
    return !response;
  }

  async isUsernameUnique(username: string): Promise<boolean> {
    //Check if the username provide is unique
    const response = await this.accountModel.findOne({ username });

    return !response;
  }

  async isPhoneUnique(phone: string): Promise<boolean> {
    //Check if the user phone provide is unique
    const response = await this.accountModel.findOne({ phone });

    return !response;
  }

  async isReferralCodeUnique(referralCode: string): Promise<boolean> {
    //Check if the referralCode provide is unique
    const response = await this.accountModel.findOne({ referralCode });
    return !response;
  }

  async generateReferralCode(username: string): Promise<string> {
    const code = username.slice(0, 3).toUpperCase();
    const randomString = Math.random().toString(36).slice(2, 10);
    const referralCode = `${code}${randomString}`;
    if (!(await this.isReferralCodeUnique(referralCode))) {
      return this.generateReferralCode(username);
    }
    return referralCode;
  }

  private async generateToken(
    data: any,
    tokenType: 'access' | 'refresh' | 'temporary',
  ) {
    const { _id, ...rest } = data;
    const token = await this.jwtService.signAsync(
      { id: _id, ...rest },
      {
        expiresIn: this.configService.get('jwt.' + tokenType + '.expiresIn'),
        secret: this.configService.get('jwt.' + tokenType + '.secret'),
      },
    );
    return token;
  }

  private async decriptToken(
    token: string,
    tokenType: 'access' | 'refresh' | 'temporary',
  ) {
    return this.jwtService.verify(token, {
      secret: this.configService.get('jwt.' + tokenType + '.secret'),
    });
  }

  async decodeToken(
    token: string,
    tokenType: 'access' | 'refresh' | 'temporary',
  ) {
    try {
      if (!tokenType) tokenType = 'access';
      const decripted = await this.decriptToken(token, tokenType);
      if (!decripted) throw new BadRequestException('invalid token');
      const account = await this.accountModel.findById(decripted.id);
      if (tokenType === 'temporary') return decripted;
      if (!account) throw new BadRequestException('account not found');
      // if (!account.isActive)
      //   throw new BadRequestException('account not active');
      return account.toObject();
    } catch (error) {
      Logger.error(error.message, 'DecodeToken');
      return { error: error.message, status: error.status };
    }
  }

  //register
  async register(registerDto: RegisterDto) {
    try {
      // if no username provided
      if (!registerDto.username) registerDto.username = registerDto.email;
      //Check if the user email provide is unique
      const isEmailUnique = await this.isEmailUnique(registerDto.email);
      if (!isEmailUnique) {
        throw new BadRequestException('Email already exist');
      }

      //Check if the username provide is unique
      const isUsernameUnique = await this.isUsernameUnique(
        registerDto.username,
      );
      if (!isUsernameUnique) {
        throw new BadRequestException('Username already exist');
      }

      //Check if the user phone provide is unique
      const isPhoneUnique = await this.isPhoneUnique(registerDto.phone);
      if (!isPhoneUnique) {
        throw new BadRequestException('Phone already exist');
      }

      // hash password
      Logger.log(registerDto);
      registerDto.password = await this.hashPassword(registerDto.password);
      // generate referral code
      const referralCode = await this.generateReferralCode(
        registerDto.username,
      );

      // Find referrer
      let referrer: any;
      if (registerDto.referralCode) {
        referrer = await this.accountModel.findOne({
          referralCode: registerDto.referralCode,
        });
      }

      // save user in database
      const account = await this.accountModel.create({
        ...registerDto,
        isActive: false,
        referralCode,
        referredBy: referrer?._id || null,
      });
      // Logger.log(account);

      // generate tokens
      const { _id, ...rest } = account.toObject();
      const access_token = await this.generateToken(
        { id: _id, _id, ...rest },
        'temporary',
      );
      // const refresh_token = await this.generateToken(
      //   { id: _id, _id, rest },
      //   'refresh',
      // );

      // save tokens in redis
      this.redisService.set(access_token, account._id.toString(), 10);
      // this.redisService.set(refresh_token, account._id.toString(), 525600);

      // generate otp 6 digit
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      // // save otp in redis
      this.redisService.set(registerDto.email, otp, 10);

      const res = await firstValueFrom(
        this.messagingService.send(
          { cmd: 'send-mail-otp' },
          {
            to: registerDto.email,
            otp,
          },
        ),
      );
      console.log('res', res);
      // message: `otp sent to ${registerDto.email}`
      return {
        access_token,
        // refresh_token,
        account: rest,
        message: `otp sent to ${registerDto.email}`,
      };
    } catch (error) {
      Logger.error(error.message, 'Register');
      return { error: error.message, status: error.status };
    }
  }

  // Confirm account
  async confirmAccount(userId: string, otp: string) {
    try {
      // find account with email
      const account = await this.accountModel.findById(userId);
      if (!account) throw new BadRequestException('account not found');
      if (account.isActive)
        throw new BadRequestException('account already active');

      if (account.confirmedAt)
        throw new BadRequestException('account already confirmed');
      // compare otp
      const isValid = await this.redisService.get(account.email);
      if (!isValid) throw new BadRequestException('invalid otp');
      if (isValid !== otp) throw new BadRequestException('invalid otp');
      // activate account
      await account.updateOne({ isActive: true, confirmedAt: new Date() });
      // remove otp from redis
      this.redisService.delete(account.email);

      // Generate wallet
      const res = await firstValueFrom(
        this.transactionService.send(
          { cmd: 'create-wallet' },
          { accountId: account._id },
        ),
      );

      if (res && res.error) throw new BadRequestException(res.error);

      // Reward referrer
      // if (account.referredBy) {
      //   const referrer = await this.accountModel.findOne({
      //     referralCode: account.referredBy,
      //   });
      //   if (referrer) {
      //     await this.transactionService.send(
      //       { cmd: 'create-transaction' },
      //       {
      //         accountId: referrer._id,
      //         amount: this.configService.get('referral.referrerReward'),
      //         type: this.configService.get('referral.rewardType'),
      //       },
      //     );
      //     if (this.configService.get('referral.referredReward') > 0)
      //       await this.transactionService.send(
      //         { cmd: 'create-transaction' },
      //         {
      //           accountId: account._id,
      //           amount: this.configService.get('referral.referredReward'),
      //           type: this.configService.get('referral.rewardType'),
      //         },
      //       );
      //   }
      // }
      // generate tokens
      const { _id, ...rest } = account.toObject();
      const access_token = await this.generateToken(
        { id: _id, _id, ...rest, isActive: true, confirmedAt: new Date() },
        'access',
      );

      const refresh_token = await this.generateToken(
        {
          id: _id,
          _id,
          ...rest,
          isActive: true,
          confirmedAt: new Date(),
        },
        'refresh',
      );
      return {
        message: 'account activated',
        access_token,
        refresh_token,
        account: rest,
      };
    } catch (error) {
      Logger.error(error.message, 'ConfirmAccount');
      return { error: error.message, status: error.status };
    }
  }

  // resend confirmation account code
  async resendConfirmationAccountCode(userId: string) {
    try {
      // check if account with userId exist
      const account = await this.accountModel.findById(userId);
      if (!account) throw new BadRequestException('account not found');
      // if (account.isActive)
        // throw new BadRequestException('account already active');
      if (account.confirmedAt)
        throw new BadRequestException('account already confirmed');

      // generate token
      const token = await this.generateToken(
        { id: account._id, ...account.toObject() },
        'temporary',
      );

      // generate otp
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      // save otp in redis
      this.redisService.set(account.email, otp, 10);
      // send otp to email
      const res = await firstValueFrom(
        this.messagingService.send(
          { cmd: 'send-mail-otp' },
          { to: account.email, otp },
        ),
      );
      console.log('res', res);
      return {
        message: 'success.OTP_SEND_TO_CREDENTIAL',
        params: { credential: account.email },
        access_token: token,
      };
    } catch (error) {
      Logger.error(error.message, 'ResendConfirmationAccountCode');
      return { error: error.message, status: error.status };
    }
  }

  // login
  async login(loginDto: LoginDto) {
    try {
      // find account with username or email
      const account = await this.accountModel.findOne({
        $or: [{ email: loginDto.username }, { username: loginDto.username }],
      });
      if (!account) throw new BadRequestException('account.NOT_FOUND');
      if (!account.isActive)
        throw new BadRequestException('account.NOT_ACTIVE');

      if (!account.confirmedAt)
        return this.resendConfirmationAccountCode(account._id?.toString());
      // compare password
      const isValid = await bcrypt.compare(loginDto.password, account.password);
      if (!isValid) throw new BadRequestException('invalid password');
      // generate tokens
      const { _id, ...rest } = account.toObject();
      const access_token = await this.generateToken(
        { id: _id, _id, ...rest },
        'access',
      );
      const refresh_token = await this.generateToken(
        { id: _id, _id, ...rest },
        'refresh',
      );
      // save tokens in redis
      this.redisService.set(access_token, account._id.toString(), 10);
      this.redisService.set(refresh_token, account._id.toString(), 525600);
      return { access_token, refresh_token, account: rest };
    } catch (error) {
      Logger.error(error.message, 'Login');
      return { error: error.message, status: error.status };
    }
  }

  // logout
  async logout(token: string) {
    try {
      // Check if token exist
      const id = await this.redisService.get(token);
      if (!id) throw new BadRequestException('invalid token');
      // Check if account exist
      const account = await this.accountModel.findById(id);
      if (!account) throw new BadRequestException('account not found');
      // Check if account is active
      if (!account.isActive)
        throw new BadRequestException('account not active');
      // Remove token from redis
      this.redisService.delete(token);
      return { message: 'logged out' };
    } catch (error) {
      Logger.error(error.message, 'Logout');
      return { error: error.message, status: error.status };
    }
  }

  // change username
  async changeUsername(id: string, username: string) {
    // check if new username is unique
    const isUsernameUnique = await this.isUsernameUnique(username);
    if (!isUsernameUnique) {
      throw new BadRequestException('Username already exist');
    }
    // update username
    await this.accountModel.updateOne({ _id: id }, { username });
    return { message: 'Username changed' };
  }

  // change email
  async changeEmail(id: string, email: string) {
    // check if account is active
    const account = await this.accountModel.findById(id);
    if (!account) throw new BadRequestException('error.ACCOUNT_NOT_FOUND');
    if (!account.isActive)
      throw new BadRequestException('error.ACCOUNT_NOT_ACTIVE');

    // check if email is unique
    const isEmailUnique = await this.isEmailUnique(email);
    if (!isEmailUnique) {
      throw new BadRequestException('Email already exist');
    }
    // Generate otp
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    // Generate token
    const token = await this.generateToken(
      { ...account, id: account._id.toString() },
      'temporary',
    );

    // save token and otp in redis
    this.redisService.set(token, account._id.toString(), 10);
    this.redisService.set(
      account._id.toString(),
      JSON.stringify({ otp, newEmail: email }),
      10,
    );

    // send otp on new email
    const res = await firstValueFrom(
      this.messagingService.send(
        { cmd: 'send-mail-otp' },
        {
          to: email,
          otp,
        },
      ),
    );
    // console.log('res', res);
    if (res && res.error) throw new BadRequestException(res.error);
    return {
      message: 'success.OTP_SEND',
      params: { email },
      access_token: token,
    };
  }

  // change phone
  async changePhone(id: string, phone: string) {
    // check if phone is unique
    const isPhoneUnique = await this.isPhoneUnique(phone);
    if (!isPhoneUnique) {
      throw new BadRequestException('Phone number already exist');
    }

    // check if account is active
    const account = await this.accountModel.findById(id);
    if (!account) throw new BadRequestException('account not found');
    if (!account.isActive) throw new BadRequestException('account not active');

    // generate otp
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    // generate token
    const token = await this.generateToken(
      { ...account, id: account._id.toString() },
      'temporary',
    );
    // save token and otp in redis
    this.redisService.set(token, account._id.toString(), 10);
    this.redisService.set(
      account._id.toString(),
      JSON.stringify({ otp, newPhone: phone }),
      10,
    );

    // send otp to new phone
    const res = await firstValueFrom(
      this.messagingService.send({ cmd: 'send-sms-otp' }, { to: phone, otp }),
    );
    if (res && res.error) throw new BadRequestException(res.error);
    return {
      message: 'success.OTP_SEND_TO_PHONE',
      params: { phone },
      access_token: token,
    };
  }

  // confirm change email
  async confirmChangeEmail(id: string, otp: string) {
    // verify otp
    const savedData = await this.redisService.get(id);
    if (!savedData) throw new BadRequestException('otp expired');
    const { otp: savedOtp, newEmail } = JSON.parse(savedData);
    if (savedOtp !== otp) throw new BadRequestException('invalid otp');

    // check if account is active
    const account = await this.accountModel.findById(id);
    if (!account) throw new BadRequestException('account not found');
    if (!account.isActive) throw new BadRequestException('account not active');

    // check if new email is unique
    const isEmailUnique = await this.isEmailUnique(newEmail);
    if (!isEmailUnique) {
      throw new BadRequestException('Email already exist');
    }

    // update email in redis
    await this.accountModel.findByIdAndUpdate(id, { email: newEmail });
    return { message: 'success.EMAIL_CHANGED' };
  }

  // confirm change phone
  async confirmChangePhone(id: string, otp: string) {
    // verify otp
    const savedData = await this.redisService.get(id);
    if (!savedData) throw new BadRequestException('otp expired');
    const { otp: savedOtp, newPhone } = JSON.parse(savedData);
    if (savedOtp !== otp) throw new BadRequestException('invalid otp');

    // check if account is active
    const account = await this.accountModel.findById(id);
    if (!account) throw new BadRequestException('account not found');
    if (!account.isActive) throw new BadRequestException('account not active');

    // update phone in redis
    await this.accountModel.findByIdAndUpdate(id, { phone: newPhone });
    return { message: 'success.PHONE_CHANGED' };
  }

  // forgot password
  async forgotPassword(credential: string) {
    // check if account with credential exist
    const account = await this.accountModel.findOne({
      $or: [{ email: credential }, { phone: credential }],
    });
    if (!account) throw new BadRequestException('error.ACCOUNT_NOT_FOUND');
    if (!account.isActive)
      throw new BadRequestException('error.ACCOUNT_NOT_ACTIVE');

    // generate otp
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    // generate token
    const token = await this.generateToken(
      { ...account, id: account._id.toString() },
      'temporary',
    );
    // save otp and token in cache
    this.redisService.set(token, account._id.toString(), 10);
    this.redisService.set(account._id.toString(), otp, 10);

    // send otp to user
    const mode: 'mail' | 'whatsapp' = this.isEmail(credential)
      ? 'mail'
      : 'whatsapp';
    const res = await firstValueFrom(
      this.messagingService.send(
        { cmd: `send-${mode}-otp` },
        { to: credential, otp },
      ),
    );

    if (res && res.error) throw new BadRequestException(res.error);
    return {
      message: 'success.OTP_SEND_TO_CREDENTIAL',
      params: { credential: mode === 'mail' ? account.email : account.phone },
      access_token: token,
    };
  }

  // reset password
  async resetPassword(id: string, password: string) {
    // check if account is active
    const account = await this.accountModel.findById(id);
    if (!account) throw new BadRequestException('error.ACCOUNT_NOT_FOUND');
    if (!account.isActive)
      throw new BadRequestException('error.ACCOUNT_NOT_ACTIVE');

    // generate hash
    const hash = await this.hashPassword(password);
    // update password
    await this.accountModel.updateOne({ _id: id }, { password: hash });
    return { message: 'success.PASSWORD_RESET' };
  }

  // change password
  async changePassword(id: string, oldPassword: string, newPassword: string) {
    // check if old password is valid
    const account = await this.accountModel.findById(id);
    if (!account) throw new BadRequestException('error.ACCOUNT_NOT_FOUND');
    if (!account.isActive)
      throw new BadRequestException('error.ACCOUNT_NOT_ACTIVE');
    const isValid = await bcrypt.compare(oldPassword, account.password);
    if (!isValid) throw new BadRequestException('error.INVALID_PASSWORD');

    // hash and save new password
    const hash = await this.hashPassword(newPassword);
    await this.accountModel.updateOne({ _id: id }, { password: hash });
    return { message: 'success.PASSWORD_CHANGED' };
  }

  // send otp
  async sendOtp(credential: string, resend: boolean) {
    try {
      // generate otp 6 digit
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      // Logger.log(otp);
      // Logger.log(credential);
      // save otp in redis
      const token = await this.generateToken({ credential }, 'temporary');
      this.redisService.set(credential, otp, 10);
      // send otp to credential
      let mode: 'mail' | 'whatsapp' | 'sms' = this.isEmail(credential)
        ? 'mail'
        : 'whatsapp';
      mode = mode === 'whatsapp' && resend ? 'sms' : mode;
      const res = await firstValueFrom(
        this.messagingService.send(
          { cmd: `send-${mode}-otp` },
          {
            to: credential,
            otp,
          },
        ),
      );
      console.log('res', res);
      return {
        message: `otp sent to ${credential} via ${mode}.`,
        access_token: token,
      };
    } catch (error) {
      Logger.error(error.message);
      throw new InternalServerErrorException(error.message);
    }
  }

  // verify otp
  async verifyOtp(
    credential: string,
    otp: string,
    device: Omit<IDevice, 'isLoggedIn' | 'isActive'>,
  ) {
    if (!device) throw new BadRequestException('device not found');
    const data = await this.redisService.get(credential);
    // Logger.log(data);
    if (!data) throw new ForbiddenException('otp expired');
    if (data !== otp) throw new BadRequestException('invalid otp');
    let account = await this.accountModel.findOne({
      $or: [{ email: credential }, { phone: credential }],
    });
    if (!account) {
      // create account
      const isEmail = credential.includes('@');
      const usernameFirstPart = isEmail ? credential.split('@')[0] : credential;
      const usernameSecondPart = Math.floor(1000 + Math.random() * 9000);
      const username = `${usernameFirstPart}${usernameSecondPart}`;
      const dts = { username, defaultUsername: true, authMethods: [] };
      if (isEmail) {
        dts['email'] = credential;
        dts['authMethods'].push('mail');
      } else {
        dts['phone'] = credential;
        dts['authMethods'].push('phone');
      }
      // const backup = await this.backupUser(credential);
      // if (backup) dts = { ...dts, ...backup, completed: true };
      account = await this.accountModel.create(dts);
    }

    const accountDevices = await this.deviceModel.find({
      accountId: account._id.toString(),
    });

    // Logger.log(account._id.toString());

    let deviceExist = await this.deviceModel.findOne({ id: device.id });
    if (!deviceExist)
      deviceExist = await this.deviceModel.create({
        ...device,
        accountId: account._id.toString(),
      });
    else if (!deviceExist.isActive)
      throw new ForbiddenException('Cannot login with this device');

    // Disconnect all other devices
    const loggedInDevices = accountDevices.filter((d) => d.isLoggedIn);
    const maxLoggedInDevices = this.configService.get(
      'auth.maxLoggedInDevices',
    );
    if (
      loggedInDevices.length &&
      loggedInDevices.length + 1 >= maxLoggedInDevices
    ) {
      // throw new ForbiddenException('Too many devices logged in');
      // logout the first device
      await this.deviceModel.updateOne(
        { id: loggedInDevices[0].id },
        { isLoggedIn: false },
      );
    }

    // Connect device
    await deviceExist.updateOne({ isLoggedIn: true });
    const { _id, ...rest } = account.toObject();
    const access_token = await this.generateToken(
      { id: _id, _id, ...rest },
      'access',
    );
    const refresh_token = await this.generateToken(
      { id: _id, _id, ...rest },
      'refresh',
    );

    // save refresh and access tokens in redis
    this.redisService.set(refresh_token, deviceExist?.id, 525600);
    this.redisService.set(access_token, deviceExist?.id, 10);

    //Remove Otp from redis
    this.redisService.delete(credential);
    return {
      access_token,
      refresh_token,
      account: rest,
      message: 'otp verified',
    };
  }

  // refresh token
  async refreshToken(refresh_token: string) {
    // Check if refresh token exist
    // const deviceId = await this.redisService.get(refresh_token);

    // Check if device is active
    // if (!deviceId) throw new ForbiddenException('invalid refresh token');
    // const device = await this.deviceModel.findOne({ id: deviceId });
    // if (!device) throw new ForbiddenException('device not found');
    // if (!device.isActive) throw new ForbiddenException('device not active');

    // Check if account is active
    const decripted = await this.decriptToken(refresh_token, 'refresh');
    if (!decripted) throw new BadRequestException('account not found');
    const account = await this.accountModel.findById(decripted.id);
    if (!account) throw new BadRequestException('account not found');
    if (!account.isActive) throw new BadRequestException('account not active');

    // Generate new tokens
    const { _id, ...rest } = account.toObject();
    const access_token = await this.generateToken(
      { id: _id, _id, ...rest },
      'access',
    );

    // save access token in redis
    this.redisService.set(access_token, _id.toString(), 10);
    return {
      access_token,
      refresh_token,
      account: rest,
      message: 'token refreshed',
    };
  }

  // get profile
  async getProfile(id: string) {
    const account = await this.accountModel.findById(id).select('-password');
    if (!account) throw new BadRequestException('account not found');
    if (!account.isActive) throw new BadRequestException('account not active');
    // if (!account.ownerId)
    // throw new NotFoundException('Please complete your profile');
    // const { data } = await this.userService.get(`user/${account.ownerId}/`, {});
    console.log(account);
    return { ...account.toObject(), id: account._id };
  }

  // complete profile
  async completeProfile(id: string, createAccountDto: any) {
    const account = await this.accountModel.findById(id);
    if (!account) throw new BadRequestException('account not found');
    if (!account.isActive) throw new BadRequestException('account not active');
    if (account.completed)
      throw new BadRequestException('profile already completed');
    // if (account.ownerId)
    //   throw new BadRequestException('profile already completed');
    // const { status, doc } = await this.userService.send(`user`, {
    //   userName: createAccountDto.username,
    //   email: createAccountDto.email,
    //   phoneNumber: createAccountDto.phoneNumber,
    //   birthDate: createAccountDto.birthdate,
    //   firstName: createAccountDto.firstname,
    //   gender: createAccountDto.gender,
    // });
    // Logger.log(doc);
    // if (status !== 'success')
    // throw new InternalServerErrorException('user not created');
    // const user = doc;
    const updateAccountDto = {
      // ownerId: user._id,
      completed: true,
    };

    if (
      !account.authMethods.includes(AuthMethod.EMAIL) &&
      createAccountDto.email
    )
      updateAccountDto['email'] = createAccountDto.email;
    if (
      !account.authMethods.includes(AuthMethod.PHONE) &&
      createAccountDto.phoneNumber
    )
      updateAccountDto['phone'] = createAccountDto.phoneNumber;
    if (createAccountDto.avatar)
      updateAccountDto['avatar'] = createAccountDto.avatar;
    if (account.defaultUsername && createAccountDto.username)
      updateAccountDto['username'] = createAccountDto.username;
    if (createAccountDto.firstname)
      updateAccountDto['firstname'] = createAccountDto.firstname;
    if (createAccountDto.lastname)
      updateAccountDto['lastname'] = createAccountDto.lastname;
    if (createAccountDto.birthdate)
      updateAccountDto['birthdate'] = createAccountDto.birthdate;
    if (createAccountDto.interests)
      updateAccountDto['interests'] = createAccountDto.interests;
    await account.updateOne(updateAccountDto);
    return { message: 'profile completed' };
  }

  //Backup user from old database
  async backupUser(credential: string, role?: Role) {
    const user = await firstValueFrom(
      this.backupService.send({ cmd: 'find-user' }, { credential, role }),
    );

    if (!user) return;
    // const userData = await firstValueFrom({ cmd: 'find-user-data'}, { id: user.id });
    // if (!userData) return user;
    // Emit backup data to event service
    return {
      avatar: user.profileImage,
      email: user.email,
      firstname: user.firstName,
      lastname: user.lastName,
      phone: user.phoneNumber,
      gender: user.gender || Gender.UNSPECIFIED,
      birthdate: user.birthDate,
      interests: user.interests || [],
      role: user.role,
    };
  }

  async delete(id: string, password: string) {
    const account = await this.accountModel.findById(id);
    if (!account) throw new NotFoundException('error.ACCOUNT_NOT_FOUND');
    // verify password
    const isValid = await bcrypt.compare(password, account.password);
    if (!isValid) throw new BadRequestException('error.INVALID_PASSWORD');
    if (account.deletedAt) throw new BadRequestException('error.ALREADY_DONE');
    if (!account.isActive)
      throw new BadRequestException('error.ACCOUNT_NOT_ACTIVE');

    // generate otp
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // generate token
    const token = await this.generateToken({ ...account, id }, 'temporary');

    // save otp and token in cache
    this.redisService.set(token, id, 10);
    this.redisService.set(id, otp, 10);

    // send otp via credential
    const mode: 'mail' | 'whatsapp' = this.isEmail(account.username)
      ? 'mail'
      : 'whatsapp';
    const recipient = mode === 'mail' ? account.username : account.phone;
    const res = await firstValueFrom(
      this.messagingService.send(
        { cmd: `send-${mode}-otp` },
        {
          to: recipient,
          otp,
        },
      ),
    );
    if (res.error)
      throw new InternalServerErrorException('error.FAILED_TO_SEND_OTP');

    return {
      message: 'success.OTP_SEND_TO_CREDENTIAL',
      params: {
        credential: mode === 'mail' ? account.username : account.phone,
      },
      access_token: token,
    };
  }

  async confirmDelete(id: string, otp: string) {
    const data = await this.redisService.get(id);
    if (!data) throw new ForbiddenException('error.OTP_EXPIRED');
    if (data !== otp) throw new BadRequestException('error.INVALID_OTP');

    const account = await this.accountModel.findById(id);
    if (!account) throw new NotFoundException('error.ACCOUNT_NOT_FOUND');
    if (account.deletedAt) throw new BadRequestException('error.ALREADY_DONE');
    if (!account.isActive)
      throw new BadRequestException('error.ACCOUNT_NOT_ACTIVE');
    await this.accountModel.findByIdAndUpdate(account._id, {
      deletedAt: new Date(),
    });

    return { message: 'success.ACCOUNT_DELETED' };
  }
}
