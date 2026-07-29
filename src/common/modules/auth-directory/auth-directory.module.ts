import { Global, Module } from '@nestjs/common';
import { AuthDirectoryService } from './auth-directory.service';

@Global()
@Module({
  providers: [AuthDirectoryService],
  exports: [AuthDirectoryService],
})
export class AuthDirectoryModule {}
