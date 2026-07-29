import { Module } from '@nestjs/common';
import { AuthDirectoryModule } from '../../common/modules/auth-directory/auth-directory.module';
import { PolicyService } from './policy.service';

@Module({
  imports: [AuthDirectoryModule],
  providers: [PolicyService],
  exports: [PolicyService],
})
export class PolicyModule {}
