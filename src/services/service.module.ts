import { Module } from '@nestjs/common';
import { redisClientProvider } from 'src/configs';
import RedisService from './redis.service';

@Module({
  providers: [redisClientProvider, RedisService],
  exports: [RedisService],
})
export class ServiceModule {}
