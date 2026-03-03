import { Controller, Get, Post, ForbiddenException, Req } from '@nestjs/common';
import type { Request } from 'express';
import { AdminService } from './admin.service';
import { isLoopback } from '../../common/utils/ip';

@Controller('/admin')
export class AdminController {
  constructor(private readonly admin: AdminService) {}

  private assertLocal(req: Request): void {
    if (!isLoopback(req)) throw new ForbiddenException('Local admin only');
  }

  @Get('/status')
  status(@Req() req: Request) {
    this.assertLocal(req);
    return this.admin.getStatus();
  }

  @Get('/policies')
  policies(@Req() req: Request) {
    this.assertLocal(req);
    return this.admin.getPolicies();
  }

  @Get('/upstreams')
  upstreams(@Req() req: Request) {
    this.assertLocal(req);
    return this.admin.getUpstreams();
  }

  @Post('/reload')
  async reload(@Req() req: Request) {
    this.assertLocal(req);
    await this.admin.loadAll();
    return { ok: true, ...this.admin.getStatus() };
  }
}
