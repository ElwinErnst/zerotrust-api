import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  NotFoundException,
  Param,
  ParseUUIDPipe,
  Put,
} from '@nestjs/common';
import { policySetSchema } from '../policy-generator/schema/policy.schema';
import { PolicyStoreService } from './policy-store.service';

@Controller('policies')
export class PolicyStoreController {
  constructor(private readonly store: PolicyStoreService) {}

  @Put(':tenantId')
  @HttpCode(200)
  put(
    @Param('tenantId', new ParseUUIDPipe()) tenantId: string,
    @Body() body: unknown,
  ) {
    // Body is validated at the boundary with the exact same Zod schema that
    // the generator emits. Whether the caller PUTs a hand-crafted policy or
    // the output of `POST /policies/generate`, it flows through the same
    // gate — the evaluator can trust any stored policy set.
    const parsed = policySetSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({
        message: 'Invalid policy set',
        issues: parsed.error.issues,
      });
    }
    return this.store.set(tenantId, parsed.data);
  }

  @Get(':tenantId')
  get(@Param('tenantId', new ParseUUIDPipe()) tenantId: string) {
    const stored = this.store.get(tenantId);
    if (!stored) {
      throw new NotFoundException('No compiled policy set for this tenant');
    }
    return stored;
  }

  @Delete(':tenantId')
  @HttpCode(204)
  remove(@Param('tenantId', new ParseUUIDPipe()) tenantId: string): void {
    const removed = this.store.remove(tenantId);
    if (!removed) {
      throw new NotFoundException('No compiled policy set for this tenant');
    }
  }
}
