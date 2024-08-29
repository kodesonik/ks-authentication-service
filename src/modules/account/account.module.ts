import { Module } from '@nestjs/common';
import { AccountService } from './account.service';
import { AccountController } from './account.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { Account, AccountSchema } from './entities/account.schema';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { jwtConstants } from './constants';
import { ServiceModule } from 'src/services/service.module';
import { ServiceProvider } from 'src/configs/services.provider';
import { HttpModule } from '@nestjs/axios';
// import { APP_GUARD } from '@nestjs/core';
// import { AuthGuard } from './auth.guard';
import { Device, DeviceSchema } from './entities/device.schema';
import { AccountGateway } from './account.gateway';
import { ClientProxyFactory } from '@nestjs/microservices';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Account.name, schema: AccountSchema },
      { name: Device.name, schema: DeviceSchema },
    ]),
    HttpModule,
    JwtModule.register({
      global: true,
      secret: jwtConstants.secret,
      // signOptions: { expiresIn: '60s' },
    }),
    ServiceModule,
  ],
  controllers: [AccountController, AccountGateway],
  providers: [
    AccountService,
    ConfigService,
    ServiceProvider,
    // {
    //   provide: APP_GUARD,
    //   useClass: AuthGuard,
    // },
    // {
    //   provide: 'USER_SERVICE',
    //   useFactory: (
    //     configService: ConfigService,
    //     serviceProvider: ServiceProvider,
    //   ) => {
    //     // const userServiceOptions = configService.get('userService');
    //     // return ClientProxyFactory.create(userServiceOptions);
    //     return {
    //       send: serviceProvider.makePost('userService'),
    //       get: serviceProvider.makeGet('userService'),
    //       update: serviceProvider.makePatch('userService'),
    //       delete: serviceProvider.makeDelete('userService'),
    //     };
    //   },
    //   inject: [ConfigService, ServiceProvider],
    // },
    // {
    //   provide: 'COMMUNICATION_SERVICE',
    //   useFactory: (
    //     configService: ConfigService,
    //     serviceProvider: ServiceProvider,
    //   ) => {
    //     return {
    //       send: serviceProvider.makePost('communicationService'),
    //       get: serviceProvider.makeGet('communicationService'),
    //       update: serviceProvider.makePatch('communicationService'),
    //       delete: serviceProvider.makeDelete('communicationService'),
    //     };
    //   },
    //   inject: [ConfigService, ServiceProvider],
    // },
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
export class AccountModule {}
