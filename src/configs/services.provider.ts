import { HttpService } from '@nestjs/axios';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { lastValueFrom, map } from 'rxjs';

@Injectable()
export class ServiceProvider {
  constructor(
    private httpService: HttpService,
    private configService: ConfigService,
  ) {}

  get(key: string): any {
    return this.configService[key];
  }

  makeGet = (key) => async (event: string, body: any) => {
    const url = this.configService.get(`${key}.url`) + event;
    Logger.log('get url: ' + url);
    Logger.log('body: ' + JSON.stringify(body));
    return lastValueFrom(
      this.httpService
        .get(url, {
          headers: { 'Content-Type': 'application/json' },
          params: body,
        })
        .pipe(map((res) => ({ status: res.status, ...res.data }))),
    );
  };

  makePost = (key) => (event: string, body: any, token) => {
    const url = this.configService.get(`${key}.url`) + event;
    Logger.log('post url: ' + url);
    Logger.log('body: ' + JSON.stringify(body));
    return lastValueFrom(
      this.httpService
        .post(url, body, {
          headers: { 'Content-Type': 'application/json', Authorization: token },
        })
        .pipe(map((res) => ({ status: res.status, ...res.data }))),
    );
  };

  makePatch = (key) => (event: string, body: any, token) => {
    const url = this.configService.get(`${key}.url`) + event;
    Logger.log('url: ' + url);
    return lastValueFrom(
      this.httpService
        .patch(url, body, {
          headers: { 'Content-Type': 'application/json', Authorization: token },
        })
        .pipe(map((res) => ({ status: res.status, ...res.data }))),
    );
  };

  makeDelete = (key) => (event: string, body: any, token) => {
    const url = this.configService.get(`${key}.url`) + event;
    Logger.log('url: ' + url);
    return lastValueFrom(
      this.httpService
        .delete(url, {
          headers: { 'Content-Type': 'application/json', Authorization: token },
          params: body,
        })
        .pipe(map((res) => ({ status: res.status, ...res.data }))),
    );
  };
}
