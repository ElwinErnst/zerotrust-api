import { Module } from '@nestjs/common';
import { GatewayController } from './gateway.controller';
import { GatewayService } from './gateway.service';
import { AuthModule } from '../auth/auth.module';
import { PolicyModule } from '../policy/policy.module';

@Module({
  imports: [AuthModule, PolicyModule],
  controllers: [GatewayController],
  providers: [GatewayService],
})
export class GatewayModule {}
