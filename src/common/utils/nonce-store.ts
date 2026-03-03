export class NonceStore {
  private readonly seen = new Map<string, number>(); // nonce -> expiresAtMs

  constructor(private readonly ttlMs: number) {}

  /**
   * Registra un nonce. Retorna false si ya existe (replay).
   */
  use(nonce: string, nowMs: number): boolean {
    this.gc(nowMs);

    const exp = this.seen.get(nonce);
    if (typeof exp === 'number' && exp > nowMs) return false;

    this.seen.set(nonce, nowMs + this.ttlMs);
    return true;
  }

  private gc(nowMs: number): void {
    // limpieza simple; O(n) pero map chico
    for (const [k, exp] of this.seen.entries()) {
      if (exp <= nowMs) this.seen.delete(k);
    }
  }
}
