import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { Account, AccountSchema } from '../account/entities/account.schema';
import { Device, DeviceSchema } from '../account/entities/device.schema';
import { ServiceModule } from 'src/services/service.module';
import { ConfigService } from '@nestjs/config';
import { ClientProxyFactory } from '@nestjs/microservices';
import { UserGateway } from './user.gateway';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Account.name, schema: AccountSchema },
      { name: Device.name, schema: DeviceSchema },
    ]),
    ServiceModule,
  ],
  controllers: [UserController, UserGateway],
  providers: [
    UserService,
    {
      provide: 'MESSAGING_SERVICE',
      useFactory: (configService: ConfigService) => {
        const serviceOptions = configService.get('messagingService');
        return ClientProxyFactory.create(serviceOptions);
      },
      inject: [ConfigService],
    },
    {
      provide: 'BACKUP_SERVICE',
      useFactory: (configService: ConfigService) => {
        const serviceOptions = configService.get('backupService');
        return ClientProxyFactory.create(serviceOptions);
      },
      inject: [ConfigService],
    },
  ],
})
export class UserModule {}
