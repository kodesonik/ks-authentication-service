import { AuthMethod, Gender } from '.';

export default interface IAccount {
  id: string;
  lastname: string;
  firstname: string;
  username: string;
  phone: number;
  email: string;
  avatar: string;
  role: string;
  birthdate: Date;
  gender: Gender;
  address: string;
  defaultUsername: boolean;
  authMethods: AuthMethod[];
  isActive: boolean;
  completed: boolean;
  lastLogin: Date;
  confirmedAt: Date;
  referralCode: string;
  referredBy: any;
}
