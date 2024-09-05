import { Inject, Injectable, Logger } from '@nestjs/common';
import { UpdateUserDto } from './dto/update-user.dto';
import { ConfigService } from '@nestjs/config';
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
  ) {
    // create root account if not exists
    this.initRootAccount();
  }

  private async initRootAccount() {
    try {
      const rootEmail = this.configService.get('root.email');
      const root = await this.accountModel.findOne({ email: rootEmail });
      if (!root) {
        Logger.log('Root admin not found! Initializing account...');
        const rootFirstname = this.configService.get('root.firstname');
        const rootLastname = this.configService.get('root.lastname');
        const rootUsername = this.configService.get('root.username');
        const phone = this.configService.get('root.phone');
        const birthdate = this.configService.get('root.birthdate');
        const password = Math.random().toString(36).slice(-8);
        const hashedPassword = await bcrypt.hash(password, 10);
        await this.accountModel.create({
          firstname: rootFirstname,
          lastname: rootLastname,
          username: rootUsername,
          email: rootEmail,
          phone,
          birthdate,
          password: hashedPassword,
          role: Role.ADMIN,
        });

        // send email to root
        const res = await firstValueFrom(
          this.messagingService.emit(
            { cmd: 'send-mail' },
            {
              emails: [rootEmail],
              subject: 'Account created',
              message: `Your account has been created successfully. Your password is ${password}`,
            },
          ),
        );
        if (res && res.error) {
          Logger.error(res.error, 'root account');
        }
      }
    } catch (error) {
      Logger.error(error.message, 'root account');
    }
  }

  async create(createUserDto: CreateUserDto) {
    try {
      if (!createUserDto.role) {
        createUserDto.role = Role.USER;
      }

      if (!createUserDto.username)
        createUserDto.username = createUserDto.email || createUserDto.phone;
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
          { cmd: 'send-mail' },
          {
            to: [doc.email],
            subject: 'Account created',
            message: `Your account has been created successfully. Your password is ${password}`,
          },
        ),
      );
      if (res && res.error) {
        Logger.error(res.error, 'create user');
      }
      return { message: 'User created successfully', doc };
    } catch (error) {
      return { error: error.message, status: error.status };
    }
  }

  async findAll({
    skip = 0,
    limit = 10,
    q,
    sort = ['createdAt'],
    order = 'ASC',
  }: UserQueryDto) {
    try {
      let query: any = {
        deletedAt: null,
      };
      if (q) {
        query = {
          ...query,
          $or: [
            { firstname: { $regex: q, $options: 'i' } },
            { lastname: { $regex: q, $options: 'i' } },
            { email: { $regex: q, $options: 'i' } },
            { phone: { $regex: q, $options: 'i' } },
          ],
        };
      }
      const orderBy = order === 'ASC' ? 1 : -1;
      const sortBy = {};
      sort.forEach((field) => {
        sortBy[field] = orderBy;
      });
      const docs = await this.accountModel
        .find(query)
        .select('-password')
        .sort(sortBy)
        .skip(skip)
        .limit(limit);
      return { count: docs.length, docs, skip, limit, sortBy };
    } catch (error) {
      return { error: error.message, status: error.status };
    }
  }

  async findTrashed({
    skip = 0,
    limit = 10,
    q,
    sort = ['createdAt'],
    order = 'ASC',
  }: UserQueryDto) {
    try {
      const orderBy = order === 'ASC' ? 1 : -1;
      const sortBy = {};
      sort.forEach((field) => {
        sortBy[field] = orderBy;
      });
      let query: any = {
        deletedAt: { $ne: null },
      };
      if (q) {
        query = {
          ...query,
          $or: [
            { firstname: { $regex: q, $options: 'i' } },
            { lastname: { $regex: q, $options: 'i' } },
            { email: { $regex: q, $options: 'i' } },
            { phone: { $regex: q, $options: 'i' } },
          ],
        };
      }
      const docs = await this.accountModel
        .find(query)
        .select('-password')
        .sort(sortBy)
        .skip(skip)
        .limit(limit);
      return { count: docs.length, docs, skip, limit, sortBy };
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
      const account = await this.accountModel.findById(id);
      if (!account) return { error: 'error.NOT_FOUND' };
      const doc = await this.accountModel.findByIdAndUpdate(id, data, {
        new: true,
      });
      return { message: 'User updated successfully', doc };
    } catch (error) {
      return { error: error.message, status: error.status };
    }
  }

  async deactivateAccount(id: string) {
    try {
      const account = await this.accountModel.findById(id);
      if (!account) {
        return { error: 'error.NOT_FOUND', status: 404 };
      }
      if (!account.isActive) {
        return { error: 'error.ALREADY_DONE', status: 400 };
      }
      account.isActive = false;
      await account.save();
      return { message: 'User deactivated successfully', doc: account };
    } catch (error) {
      return { error: error.message, status: error };
    }
  }

  async activateAccount(id: string) {
    try {
      const account = await this.accountModel.findById(id);
      if (!account) {
        return { error: 'error.NOT_FOUND', status: 404 };
      }

      if (account.isActive) {
        return { error: 'error.ALREADY_DONE', status: 400 };
      }
      account.isActive = true;
      await account.save();
      return { message: 'User activated successfully', doc: account };
    } catch (error) {
      return { error: error.message, status: error };
    }
  }

  async remove(id: string) {
    try {
      const account = await this.accountModel.findById(id).select('-password');
      if (!account) {
        return { error: 'error.NOT_FOUND', status: 404 };
      }
      // if (!account.isActive) {
      //   return { error: 'error.ACCOUNT_NOT_ACTIVE', status: 400 };
      // }
      if (account.deletedAt) {
        return { error: 'error.ALREADY_DONE', status: 400 };
      }
      account.deletedAt = new Date();
      await account.save();
      return { message: 'User deleted successfully', doc: account };
    } catch (error) {
      return { error: error.message, status: error };
    }
  }

  async restore(id: string) {
    try {
      const account = await this.accountModel.findById(id);
      if (!account) {
        return { error: 'error.NOT_FOUND', status: 404 };
      }
      if (!account.deletedAt) {
        return { error: 'error.ALREADY_DONE', status: 400 };
      }
      account.deletedAt = null;
      await account.save();
      return { message: 'User restored successfully', doc: account };
    } catch (error) {
      return { error: error.message, status: error };
    }
  }
}
