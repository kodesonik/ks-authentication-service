import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';
import { AuthMethod, Gender, Role } from 'src/models';
import IAccount from 'src/models/account';

export type AccountDocument = HydratedDocument<IAccount>;

@Schema({
  timestamps: true,
  versionKey: false,
})
export class Account implements Omit<IAccount, 'id'> {
  @Prop()
  lastname: string;

  @Prop()
  firstname: string;

  @Prop({ required: true, unique: true, lowercase: true })
  username: string;

  @Prop()
  phone: number;

  @Prop()
  email: string;

  @Prop()
  avatar: string;

  @Prop()
  birthdate: Date;

  @Prop({
    enum: ['M', 'F', 'U'],
    default: 'U',
  })
  gender: Gender;

  @Prop()
  address: string;

  @Prop({ default: Role.USER })
  role: string;

  @Prop({ default: false })
  defaultUsername: boolean;

  @Prop()
  authMethods: AuthMethod[];

  @Prop()
  password: string;

  @Prop({ default: true })
  isActive: boolean;

  @Prop({ default: false })
  completed: boolean;

  @Prop()
  lastLogin: Date;

  @Prop()
  interests: string[];

  @Prop({ default: null })
  deletedAt: Date;

  @Prop({ default: null })
  confirmedAt: Date;

  @Prop({ default: null })
  referralCode: string;

  @Prop({ default: null, ref: 'Account' })
  referredBy: any;
}

export const AccountSchema = SchemaFactory.createForClass(Account);
