import { NestFactory } from '@nestjs/core';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from './app.module';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { Logger, ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const port = process.env.PORT || 3000;
  const host = process.env.HOST || '0.0.0.0';
  const protocole = process.env.PROTOCOLE || 'http';
  let app;
  if (protocole === 'https') {
    app = await NestFactory.create(AppModule);
    app.useGlobalPipes(new ValidationPipe());
    app.setGlobalPrefix('api/v1/');
    // Documentation
    const config = new DocumentBuilder()
      .setTitle('Documentation Authentication Service')
      .setDescription('The API description')
      .setVersion('1.0')
      // .addTag('cats')
      .build();
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('docs', app, document);
    // Start server

    await app.listen(port, () => {
      console.log(`Server is running on http://localhost:${port}`);
    });
  } else {
    app = await NestFactory.createMicroservice<MicroserviceOptions>(AppModule, {
      transport: Transport[protocole],
      options: {
        host,
        port,
      },
    });
    // app.useGlobalPipes(new ValidationPipe());
    app.listen();
    Logger.log(
      `Server is running on ${protocole}://${host}:${port}`,
      'Bootstrap',
    );
  }
}
bootstrap();
