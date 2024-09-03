import { Role } from 'src/models';

export class CreateUserDto {
  lastname: string;
  firstname: string;
  username: string;
  password: string;
  email: string;
  phone: string;
  birthdate: Date;
  role: Role;
}
