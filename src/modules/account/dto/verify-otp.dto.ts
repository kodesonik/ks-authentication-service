import { IDevice } from 'src/models/device';

export class VerifyOtpDto {
  credential: string;
  otp: string;
  device: Omit<IDevice, 'isActive' | 'isLoggedIn'>;
}
