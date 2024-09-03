import { Role } from 'src/models';

export class CreateAccountDto {
  email?: string;
  phoneNumber?: string;
  firstname: string;
  lastname: string;
  birthdate: string;
  gender: string;
  role: Role;
}
