import { Module } from '@nestjs/common';
import { JwtVerifyService } from './jwt-verify.service';

@Module({
  providers: [JwtVerifyService],
  exports: [JwtVerifyService],
})
export class AuthModule {}
