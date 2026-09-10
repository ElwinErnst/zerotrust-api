import { registerAs } from '@nestjs/config';

export default registerAs('db', () => ({
  host: process.env.DB_HOST ?? 'localhost',
  port: Number(process.env.DB_PORT ?? 5432),
  username: process.env.DB_USER ?? 'postgres',
  password: process.env.DB_PASS ?? 'postgres',
  database: process.env.DB_NAME ?? 'zerotrust',
  // Default OFF: schema is owned by migrations (migrationsRun on boot). Set
  // DB_SYNC=true only for throwaway local experimentation, never in the stack.
  synchronize: String(process.env.DB_SYNC ?? 'false') === 'true',
}));
