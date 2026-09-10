import { Module } from '@nestjs/common';
import { BillingMeteringService } from '../../common/modules/billing-metering/billing-metering.service';
import { GatewayController } from './gateway.controller';
import { GatewayService } from './gateway.service';
import { AuthModule } from '../auth/auth.module';
import { PolicyModule } from '../policy/policy.module';
import { AuditModule } from '../audit/audit.module';

@Module({
  imports: [AuthModule, PolicyModule, AuditModule],
  controllers: [GatewayController],
  providers: [GatewayService, BillingMeteringService],
})
export class GatewayModule {}
