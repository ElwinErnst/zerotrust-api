import {
  Controller,
  ForbiddenException,
  Get,
  Headers,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthDirectoryService } from '../../common/modules/auth-directory/auth-directory.service';
import { BillingMeteringService } from '../../common/modules/billing-metering/billing-metering.service';
import { JwtVerifyService } from '../auth/jwt-verify.service';
import { AdminService } from '../admin/admin.service';

@Controller('api/zt')
export class ApiAccessController {
  constructor(
    private readonly jwtVerify: JwtVerifyService,
    private readonly authDirectory: AuthDirectoryService,
    private readonly admin: AdminService,
    private readonly billingMetering: BillingMeteringService,
  ) {}

  @Get('status')
  async status(@Headers('authorization') authorization?: string) {
    const user = await this.assertApiAccess(authorization);
    await this.recordZeroTrustUsage(user, [
      'zt_api_requests',
      'zt_api_status_requests',
    ]);
    return {
      tenantId: user.tenantId,
      actorType: user.actorType ?? 'user',
      ...this.admin.getStatus(),
    };
  }

  @Get('policies')
  async policies(@Headers('authorization') authorization?: string) {
    const user = await this.assertApiAccess(authorization);
    await this.recordZeroTrustUsage(user, [
      'zt_api_requests',
      'zt_api_policies_requests',
    ]);
    return this.admin.getPolicies();
  }

  @Get('upstreams')
  async upstreams(@Headers('authorization') authorization?: string) {
    const user = await this.assertApiAccess(authorization);
    await this.recordZeroTrustUsage(user, [
      'zt_api_requests',
      'zt_api_upstreams_requests',
    ]);
    return this.admin.getUpstreams();
  }

  private async assertApiAccess(authorization?: string) {
    const user = this.jwtVerify.verifyBearer(authorization);
    const entitlements = await this.authDirectory.getTenantEntitlements(
      user.tenantId,
    );

    if (!entitlements) {
      throw new UnauthorizedException('Tenant entitlements not found');
    }

    if (!entitlements.features.apiZeroTrust) {
      throw new ForbiddenException(
        'Zero Trust API Pack is not enabled for this tenant',
      );
    }

    const hasHumanAdminRole = user.roles.some((role) =>
      ['OWNER', 'ADMIN'].includes(role),
    );
    const isApiClient = user.roles.includes('API_CLIENT');

    if (!hasHumanAdminRole && !isApiClient) {
      throw new ForbiddenException(
        'Insufficient role for Zero Trust API access',
      );
    }

    return user;
  }

  private async recordZeroTrustUsage(
    user: {
      tenantId: string;
      actorType?: 'user' | 'service_account';
      clientAppId?: string;
      serviceAccountId?: string;
    },
    metrics: string[],
  ) {
    await Promise.all(
      metrics.map((metric) =>
        this.billingMetering.recordUsageEvent({
          tenantId: user.tenantId,
          addonCode: 'ZERO_TRUST_API',
          metric,
          quantity: 1,
          sourceService: 'zerotrust-api',
          actorType: user.actorType ?? 'user',
          clientAppId: user.clientAppId,
          serviceAccountId: user.serviceAccountId,
        }),
      ),
    );
  }
}
