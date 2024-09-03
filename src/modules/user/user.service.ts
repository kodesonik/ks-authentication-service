import { Inject, Injectable, Logger } from '@nestjs/common';
import { UpdateUserDto } from './dto/update-user.dto';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { ClientProxy } from '@nestjs/microservices';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import RedisService from 'src/services/redis.service';
import { Account } from '../account/entities/account.schema';
import { Role } from 'src/models';
import * as bcrypt from 'bcrypt';
import { firstValueFrom } from 'rxjs';
import { CreateUserDto } from './dto/create-user.dto';
import { UserQueryDto } from './dto/user-query.dto';

@Injectable()
export class UserService {
  constructor(
    @InjectModel(Account.name) private readonly accountModel: Model<Account>,
    private readonly redisService: RedisService,
    @Inject('MESSAGING_SERVICE')
    private readonly messagingService: ClientProxy,
    @Inject('BACKUP_SERVICE') private readonly backupService: ClientProxy,
    private readonly configService: ConfigService,
  ) {}

  async create(createUserDto: CreateUserDto) {
    try {
      if (!createUserDto.role) {
        createUserDto.role = Role.USER;
      }
      // generate a random password of 8 characters
      const password = Math.random().toString(36).slice(-8);
      // hash the generated password
      const hashedPassword = await bcrypt.hash(password, 10);
      const doc = await this.accountModel.create({
        ...createUserDto,
        password: hashedPassword,
      });

      // send email to user
      const res = await firstValueFrom(
        this.messagingService.emit(
          { cmd: 'send-email' },
          {
            to: doc.email,
            subject: 'Account created',
            text: `Your account has been created successfully. Your password is ${password}`,
          },
        ),
      );
      Logger.log(res);
      return { message: 'User created successfully', doc };
    } catch (error) {
      return { error: error.message, status: error.status };
    }
  }

  async findAll({ skip = 0, limit = 10, q }: UserQueryDto) {
    try {
      let query = {};
      if (q) {
        query = {
          $or: [
            { firstname: { $regex: q, $options: 'i' } },
            { lastname: { $regex: q, $options: 'i' } },
            { email: { $regex: q, $options: 'i' } },
            { phone: { $regex: q, $options: 'i' } },
          ],
        };
      }
      const docs = await this.accountModel.find(query).skip(skip).limit(limit);
      return { count: docs.length, docs, skip, limit };
    } catch (error) {
      return { error: error.message, status: error.status };
    }
  }

  async findOne(id: string) {
    try {
      const doc = await this.accountModel.findById(id);
      return { doc };
    } catch (error) {
      return { error: error.message, status: error.status };
    }
  }

  async update(updateUserDto: UpdateUserDto) {
    try {
      const { id, ...data } = updateUserDto;
      const doc = await this.accountModel.findByIdAndUpdate(id, data, {
        new: true,
      });
      return { message: 'User updated successfully', doc };
    } catch (error) {
      return { error: error.message, status: error.status };
    }
  }

  async remove(id: string) {
    try {
      const doc = await this.accountModel.findByIdAndDelete(id);
      return { message: 'User deleted successfully', doc };
    } catch (error) {
      return { error: error.message, status: error };
    }
  }
}
