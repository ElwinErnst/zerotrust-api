import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    // logger: ['error', 'warn', 'log'], // ajustable
  });

  const port = Number(process.env.PORT ?? '3010');
  await app.listen(port);
}
void bootstrap();
