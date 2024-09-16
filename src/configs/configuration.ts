import { Transport } from '@nestjs/microservices';

export default () => ({
  port: parseInt(process.env.PORT, 10) || 3000,
  mongoDb: {
    host: process.env.MONGO_HOST,
    port: parseInt(process.env.MONGO_PORT, 10) || 5432,
    username: process.env.MONGO_USERNAME,
    password: process.env.MONGO_PASSWORD,
    dbname: process.env.MONGO_DBNAME,
  },
  redisDb: {
    host: process.env.REDIS_HOST,
    port: parseInt(process.env.REDIS_PORT, 10) || 6379,
    password: process.env.REDIS_PASSWORD,
    user: process.env.REDIS_USER,
    db: parseInt(process.env.REDIS_DB, 10),
  },
  googleMap: {
    key: process.env.GOOGLE_MAP_KEY,
  },
  auth: {
    maxLoggedInDevices: parseInt(process.env.MAX_LOGGED_IN_DEVICES, 10) || 1,
  },
  jwt: {
    access: {
      secret: process.env.JWT_ACCESS_SECRET,
      expiresIn: process.env.JWT_ACCESS_EXPIRATION,
    },
    refresh: {
      secret: process.env.JWT_REFRESH_SECRET,
      expiresIn: process.env.JWT_REFRESH_EXPIRATION,
    },
    temporary: {
      secret: process.env.JWT_TEMPORARY_SECRET,
      expiresIn: process.env.JWT_TEMPORARY_EXPIRATION,
    },
  },
  messagingService: {
    options: {
      host: process.env.MESSAGING_SERVICE_HOST,
      port: process.env.MESSAGING_SERVICE_PORT,
    },
    transport: Transport.TCP,
  },
  transactionService: {
    options: {
      host: process.env.TRANSACTION_SERVICE_HOST,
      port: process.env.TRANSACTION_SERVICE_PORT,
    },
    transport: Transport.TCP,
  },
  backupService: {
    options: {
      host: process.env.BACKUP_SERVICE_HOST,
      port: process.env.BACKUP_SERVICE_PORT,
    },
    transport: Transport.TCP,
  },
  root: {
    lastname: process.env.ROOT_LASTNAME,
    firstname: process.env.ROOT_FIRSTNAME,
    username: process.env.ROOT_USERNAME,
    email: process.env.ROOT_EMAIL,
    phone: parseInt(process.env.ROOT_PHONE, 10),
  },
  referral: {
    referrerReward: parseInt(process.env.REFERRER_REWARD, 10) || 100,
    referredReward: parseInt(process.env.REFERRED_REWARD, 10) || 50,
    referrerRewardType: process.env.REFERRER_REWARD_TYPE || 'points',
    referredRewardType: process.env.REFERRED_REWARD_TYPE || 'points',
  },
});
