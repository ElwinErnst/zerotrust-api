import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { PolicyGeneratorController } from './policy-generator.controller';
import { PolicyGeneratorService } from './policy-generator.service';
import { PolicyGenerateGuard } from './policy-generate.guard';

@Module({
  imports: [AuthModule],
  controllers: [PolicyGeneratorController],
  providers: [PolicyGeneratorService, PolicyGenerateGuard],
  exports: [PolicyGeneratorService],
})
export class PolicyGeneratorModule {}
