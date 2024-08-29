import { Inject, Injectable } from '@nestjs/common';
import { Redis } from 'ioredis';

@Injectable()
export default class RedisService {
  constructor(@Inject('RedisClient') private readonly redisClient: Redis) {}

  /**
   * Get a value from redis
   * @param key: string
   */
  async get(key: string): Promise<string | null> {
    return this.redisClient.get(key);
  }

  /**
   * Set a key value pair in redis
   * @param key: string
   * @param value: string
   * @param ttl: time to live in minutes
   */
  async set(key: string, value: string, ttl: number): Promise<string> {
    return await this.redisClient.set(key, value, 'EX', ttl * 60);
  }

  /**
   * Delete a key from redis
   * @param key: string
   */
  async delete(key: string): Promise<number> {
    return this.redisClient.del(key);
  }
}
