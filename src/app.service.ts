import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class AppService {
  testEndpoint(): { message: string } {
    Logger.log('Endpoint has been checked!!!');
    return { message: 'Server is working' };
  }
}
