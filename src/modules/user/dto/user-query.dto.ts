export class UserQueryDto {
  q: string;
  limit: number;
  skip: number;
  lang: string;
  sort: string[];
  order: 'ASC' | 'DESC';
}
