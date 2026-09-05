import { Module } from '@nestjs/common';
import { AuthDirectoryModule } from '../../common/modules/auth-directory/auth-directory.module';
import { PolicyService } from './policy.service';
import { TenantPolicyProvider } from './tenant-policy-provider';

@Module({
  imports: [AuthDirectoryModule],
  providers: [PolicyService, TenantPolicyProvider],
  exports: [PolicyService],
})
export class PolicyModule {}
