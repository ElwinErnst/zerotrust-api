import { Module } from '@nestjs/common';
import { AuthDirectoryModule } from '../../common/modules/auth-directory/auth-directory.module';
import { AuthModule } from '../auth/auth.module';
import { PolicyStoreController } from './policy-store.controller';
import { PolicyStoreService } from './policy-store.service';
import { PolicyService } from './policy.service';
import { PolicyAdminGuard } from './policy-admin.guard';

@Module({
  imports: [AuthDirectoryModule, AuthModule],
  controllers: [PolicyStoreController],
  providers: [PolicyService, PolicyStoreService, PolicyAdminGuard],
  exports: [PolicyService, PolicyStoreService],
})
export class PolicyModule {}
