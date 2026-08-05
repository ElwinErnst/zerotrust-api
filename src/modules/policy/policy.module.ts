import { Module } from '@nestjs/common';
import { AuthDirectoryModule } from '../../common/modules/auth-directory/auth-directory.module';
import { PolicyStoreController } from './policy-store.controller';
import { PolicyStoreService } from './policy-store.service';
import { PolicyService } from './policy.service';

@Module({
  imports: [AuthDirectoryModule],
  controllers: [PolicyStoreController],
  providers: [PolicyService, PolicyStoreService],
  exports: [PolicyService, PolicyStoreService],
})
export class PolicyModule {}
