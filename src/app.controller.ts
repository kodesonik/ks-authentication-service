import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';
import { ApiNotFoundResponse, ApiOkResponse, ApiTags } from '@nestjs/swagger';

@ApiTags('Test Endpoint')
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @ApiOkResponse({
    description: 'Server is working!',
    // type: { message: string },
  })
  @ApiNotFoundResponse({ description: 'Not found!' })
  getHello(): { message: string } {
    return this.appService.testEndpoint();
  }
}
