import { Module } from '@nestjs/common';
import { PolicyGeneratorController } from './policy-generator.controller';
import { PolicyGeneratorService } from './policy-generator.service';

@Module({
  controllers: [PolicyGeneratorController],
  providers: [PolicyGeneratorService],
  exports: [PolicyGeneratorService],
})
export class PolicyGeneratorModule {}
