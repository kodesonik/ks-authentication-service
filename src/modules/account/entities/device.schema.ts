import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';
import { IDevice } from 'src/models/device';

export type DeviceDocument = HydratedDocument<IDevice>;

@Schema({
  timestamps: true,
  versionKey: false,
//   _id: false,
})
export class Device implements IDevice {
  @Prop({ required: true, lowercase: true })
  id: string;

  @Prop({ required: true })
  token: string;

  @Prop()
  model: string;

  @Prop()
  brand: string;

  @Prop({ required: true })
  platform: string;

  @Prop()
  version: string;

  @Prop({ default: false })
  isLoggedIn: boolean;

  @Prop({ default: true })
  isActive: boolean;

  @Prop({ required: true })
  accountId: string;
}

export const DeviceSchema = SchemaFactory.createForClass(Device);
