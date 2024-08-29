// redis.config.ts
import { FactoryProvider } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Redis } from 'ioredis';

// interface RedisConfig {
//   host: string;
//   port: number;
//   password?: string;
// }

// export const redisConfig: RedisConfig = {
//   host: process.env.REDIS_HOST || 'localhost',
//   port: parseInt(process.env.REDIS_PORT, 10) || 6379,
//   password: process.env.REDIS_PASSWORD,
// };

// export const redisClientFactory: FactoryProvider<Redis> = {
export const redisClientProvider: FactoryProvider<Redis> = {
  provide: 'RedisClient',
  inject: [ConfigService],
  useFactory: (configService: ConfigService) => {
    const redisInstance = new Redis({
      host: configService.get('redisDb.host'),
      port: configService.get('redisDb.port'),
      password: configService.get('redisDb.password'),
      username: configService.get('redisDb.user'),
      db: configService.get('redisDb.db'),
    });
    redisInstance.on('error', (e) => {
      throw new Error(`Redis connection failed: ${e}`);
    });
    return redisInstance;
  },
};
