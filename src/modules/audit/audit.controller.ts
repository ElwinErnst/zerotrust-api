import {
  Controller,
  ForbiddenException,
  Get,
  Headers,
  Query,
} from '@nestjs/common';
import { JwtVerifyService } from '../auth/jwt-verify.service';
import { AuditService } from './audit.service';

/**
 * Read API for this service's audit events (mainly the policy decision log).
 * Tenant is taken from the verified JWT — never a path param — so there is no
 * cross-tenant surface. OWNER/ADMIN only. Same response shape as the other
 * services' /audit-events so the console can merge them into one timeline.
 */
@Controller('api/zt')
export class AuditController {
  constructor(
    private readonly jwtVerify: JwtVerifyService,
    private readonly audit: AuditService,
  ) {}

  @Get('audit-events')
  async list(
    @Headers('authorization') authorization?: string,
    @Query('page') page?: string,
    @Query('limit') limit?: string,
  ) {
    const user = this.jwtVerify.verifyBearer(authorization);

    const isAdmin = user.roles.some((role) =>
      ['OWNER', 'ADMIN'].includes(role),
    );
    if (!isAdmin) {
      throw new ForbiddenException(
        'Only OWNER or ADMIN can read the audit log',
      );
    }

    return this.audit.list(user.tenantId, {
      page: page ? Number(page) : undefined,
      limit: limit ? Number(limit) : undefined,
    });
  }
}
