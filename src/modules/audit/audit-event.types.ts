/**
 * Normalized audit event shape, mirrored from the reference definition in
 * auth-api. Each service owns its own audit_events table and exposes it with
 * this shape so the console can merge every system into one timeline.
 *
 * In zerotrust-api the high-value events are runtime policy decisions
 * (category 'decision', outcome 'allow' | 'deny').
 */
export type AuditSystem = 'auth' | 'billing' | 'zerotrust' | 'vault';
export type AuditCategory = 'access' | 'config' | 'decision' | 'billing';
export type AuditOutcome = 'success' | 'failure' | 'allow' | 'deny';
export type AuditActorType = 'user' | 'service_account' | 'system';

export type AuditEventInput = {
  tenantId: string;
  system: AuditSystem;
  category: AuditCategory;
  action: string;
  actorType?: AuditActorType | null;
  actorId?: string | null;
  resourceType?: string | null;
  resourceId?: string | null;
  outcome: AuditOutcome;
  detail?: Record<string, unknown> | null;
};
