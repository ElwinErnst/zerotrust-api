import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from '../auth/auth.module';
import { AuditEvent } from './entities/audit-event.entity';
import { AuditService } from './audit.service';
import { AuditRetentionService } from './audit-retention.service';
import { AuditController } from './audit.controller';

@Module({
  imports: [TypeOrmModule.forFeature([AuditEvent]), AuthModule],
  controllers: [AuditController],
  providers: [AuditService, AuditRetentionService],
  exports: [AuditService],
})
export class AuditModule {}
