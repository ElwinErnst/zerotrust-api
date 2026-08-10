import { NestFactory } from '@nestjs/core';
import helmet from 'helmet';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    // logger: ['error', 'warn', 'log'], // ajustable
  });

  // Security headers (HSTS, X-Content-Type-Options, frameguard, etc.).
  app.use(helmet());

  // Trust the reverse proxy so per-IP rate limiting sees the real client IP.
  (
    app.getHttpAdapter().getInstance() as unknown as {
      set: (k: string, v: unknown) => void;
    }
  ).set('trust proxy', true);

  const port = Number(process.env.PORT ?? '3010');
  await app.listen(port);
}
void bootstrap();
