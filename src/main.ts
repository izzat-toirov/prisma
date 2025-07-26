import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import * as cookieParser from 'cookie-parser';
// somewhere in your initialization file

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser());
  const config = app.get(ConfigService);
  app.setGlobalPrefix('api');
  const PORT = config.get<number>('PORT');
  await app.listen(PORT ?? 3030, () => {
    console.log(`Server started at http://localhost:${PORT}`);
  });
}
bootstrap();
