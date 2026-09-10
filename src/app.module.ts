import { join } from 'path';
import { Module, OnModuleInit } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import dbConfig from './config/db.config';
import authDirectoryConfig from './config/auth-directory.config';
import billingMeteringConfig from './config/billing-metering.config';
import jwtConfig from './config/jwt.config';
import ztConfig from './config/zt.config';
import upstreamsConfig from './config/upstreams.config';
import { policiesConfig } from './config/policies.config';
import policyGeneratorConfig from './config/policy-generator.config';
import { AuthDirectoryModule } from './common/modules/auth-directory/auth-directory.module';

import { AuthModule } from './modules/auth/auth.module';
import { PolicyModule } from './modules/policy/policy.module';
import { PolicyGeneratorModule } from './modules/policy-generator/policy-generator.module';
import { GatewayModule } from './modules/gateway/gateway.module';
import { AdminModule } from './modules/admin/admin.module';
import { AdminService } from './modules/admin/admin.service';
import { ApiAccessModule } from './modules/api-access/api-access.module';
import { AuditModule } from './modules/audit/audit.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [
        dbConfig,
        jwtConfig,
        upstreamsConfig,
        ztConfig,
        policiesConfig,
        policyGeneratorConfig,
        authDirectoryConfig,
        billingMeteringConfig,
      ],
    }),
    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        const db = configService.get<{
          host: string;
          port: number;
          username: string;
          password: string;
          database: string;
          synchronize: boolean;
        }>('db')!;

        return {
          type: 'postgres' as const,
          host: db.host,
          port: db.port,
          username: db.username,
          password: db.password,
          database: db.database,
          autoLoadEntities: true,
          synchronize: db.synchronize,
          // Compiled migrations live next to this module under
          // dist/database/migrations after build; run them on boot.
          migrations: [join(__dirname, 'database', 'migrations', '*.js')],
          migrationsRun: true,
        };
      },
    }),
    // Per-IP rate limiting for the gateway (300 req/min default, tunable via env).
    ThrottlerModule.forRoot([
      {
        ttl: Number(process.env.THROTTLE_TTL_MS ?? 60_000),
        limit: Number(process.env.THROTTLE_LIMIT ?? 300),
      },
    ]),
    AuthDirectoryModule,
    AuthModule,
    PolicyModule,
    PolicyGeneratorModule,
    GatewayModule,
    AdminModule,
    ApiAccessModule,
    AuditModule,
  ],
  providers: [{ provide: APP_GUARD, useClass: ThrottlerGuard }],
})
export class AppModule implements OnModuleInit {
  constructor(private readonly admin: AdminService) {}

  async onModuleInit(): Promise<void> {
    // carga policies/upstreams al boot (para que PolicyService lo lea de AdminService o config)
    await this.admin.loadAll();
  }
}
