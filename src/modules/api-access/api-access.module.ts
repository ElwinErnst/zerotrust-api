import { Module } from '@nestjs/common';
import { BillingMeteringService } from '../../common/modules/billing-metering/billing-metering.service';
import { AuthDirectoryModule } from '../../common/modules/auth-directory/auth-directory.module';
import { AdminModule } from '../admin/admin.module';
import { AuthModule } from '../auth/auth.module';
import { ApiAccessController } from './api-access.controller';

@Module({
  imports: [AuthModule, AuthDirectoryModule, AdminModule],
  controllers: [ApiAccessController],
  providers: [BillingMeteringService],
})
export class ApiAccessModule {}
