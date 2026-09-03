import { Body, Controller, HttpCode, Post, UseGuards } from '@nestjs/common';
import { GeneratePolicyDto } from './dto/generate-policy.dto';
import { PolicyGeneratorService } from './policy-generator.service';
import { PolicyGenerateGuard } from './policy-generate.guard';

@Controller('policies')
@UseGuards(PolicyGenerateGuard)
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
