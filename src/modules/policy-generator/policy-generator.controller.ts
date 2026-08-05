import { Body, Controller, HttpCode, Post } from '@nestjs/common';
import { GeneratePolicyDto } from './dto/generate-policy.dto';
import { PolicyGeneratorService } from './policy-generator.service';

// Note: this controller is intentionally minimal. Auth in front of the ZT
// gateway is handled by the gateway module itself; when this endpoint is
// exposed publicly it will sit behind a JWT + OWNER/ADMIN guard.
@Controller('policies')
export class PolicyGeneratorController {
  constructor(private readonly generator: PolicyGeneratorService) {}

  @Post('generate')
  @HttpCode(200)
  generate(@Body() dto: GeneratePolicyDto) {
    return this.generator.generate({
      intent: dto.intent,
      tenantSlug: dto.tenantSlug,
    });
  }
}
