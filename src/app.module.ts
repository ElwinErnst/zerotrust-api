import { Module, OnModuleInit } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import jwtConfig from './config/jwt.config';
import ztConfig from './config/zt.config';
import upstreamsConfig from './config/upstreams.config';
import { policiesConfig } from './config/policies.config';

import { AuthModule } from './modules/auth/auth.module';
import { PolicyModule } from './modules/policy/policy.module';
import { GatewayModule } from './modules/gateway/gateway.module';
import { AdminModule } from './modules/admin/admin.module';
import { AdminService } from './modules/admin/admin.service';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [jwtConfig, upstreamsConfig, ztConfig, policiesConfig],
    }),
    AuthModule,
    PolicyModule,
    GatewayModule,
    AdminModule,
  ],
})
export class AppModule implements OnModuleInit {
  constructor(private readonly admin: AdminService) {}

  async onModuleInit(): Promise<void> {
    // carga policies/upstreams al boot (para que PolicyService lo lea de AdminService o config)
    await this.admin.loadAll();
  }
}
