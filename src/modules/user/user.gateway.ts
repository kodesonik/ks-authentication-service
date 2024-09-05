import { Controller } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { UserService } from './user.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserQueryDto } from './dto/user-query.dto';

@Controller()
export class UserGateway {
  constructor(private readonly userService: UserService) {}

  @MessagePattern({ cmd: 'create-user' })
  create(@Payload() createUserDto: CreateUserDto) {
    return this.userService.create(createUserDto);
  }

  @MessagePattern({ cmd: 'find-all-users' })
  findAll(@Payload() userQueryDto: UserQueryDto) {
    console.log(userQueryDto);
    return this.userService.findAll(userQueryDto);
  }

  @MessagePattern({ cmd: 'find-trashed-users' })
  findTrashed(@Payload() userQueryDto: UserQueryDto) {
    return this.userService.findTrashed(userQueryDto);
  }

  @MessagePattern({ cmd: 'find-one-user' })
  findOne(@Payload() payload: { id: string }) {
    return this.userService.findOne(payload.id);
  }

  @MessagePattern({ cmd: 'update-user' })
  update(@Payload() updateUserDto: UpdateUserDto) {
    return this.userService.update(updateUserDto);
  }

  @MessagePattern({ cmd: 'activate-user' })
  activate(@Payload() payload: { id: string }) {
    return this.userService.activateAccount(payload.id);
  }

  @MessagePattern({ cmd: 'deactivate-user' })
  deactivate(@Payload() payload: { id: string }) {
    return this.userService.deactivateAccount(payload.id);
  }

  @MessagePattern({ cmd: 'delete-user' })
  remove(@Payload() payload: { id: string }) {
    return this.userService.remove(payload.id);
  }

  @MessagePattern({ cmd: 'restore-user' })
  restore(@Payload() payload: { id: string }) {
    return this.userService.restore(payload.id);
  }
}
