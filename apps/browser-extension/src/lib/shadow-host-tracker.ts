import { accessibleShadowRoot } from "./form-discovery";

type PendingHost = { phase: "definition" | "root"; deadline: number };

/** Bounded definition/hydration tracking with fair rotation for large component trees. */
export class ShadowHostTracker {
  private hosts = new Map<Element, PendingHost>();
  private expired = new WeakSet<Element>();
  private timer: ReturnType<typeof setTimeout> | null = null;
  private delay = 250;

  constructor(private readonly onRoot: (root: ShadowRoot) => void) {}

  watch(host: Element) {
    if (!host.localName.includes("-") || !host.isConnected || this.hosts.has(host) || this.expired.has(host) || this.hosts.size >= 256) return;
    const defined = host.matches(":defined");
    this.hosts.set(host, { phase: defined ? "root" : "definition", deadline: Date.now() + (defined ? 30_000 : 60_000) });
    this.delay = 250;
    this.schedule();
  }

  reset() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.hosts.clear();
    this.expired = new WeakSet();
    this.delay = 250;
  }

  private schedule() {
    if (this.timer || this.hosts.size === 0) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      const now = Date.now();
      for (const [host, state] of this.hosts) {
        if (!host.isConnected) this.hosts.delete(host);
        else if (now >= state.deadline) { this.hosts.delete(host); this.expired.add(host); }
      }
      // Rotate a bounded batch; the first unhydrated components cannot starve
      // later login components. Registration and hydration have separate clocks.
      let found = false;
      for (const [host, state] of [...this.hosts].slice(0, 64)) {
        this.hosts.delete(host);
        const root = accessibleShadowRoot(host);
        if (root) { found = true; this.onRoot(root); continue; }
        if (state.phase === "definition" && host.matches(":defined")) {
          state.phase = "root";
          state.deadline = now + 30_000;
        }
        this.hosts.set(host, state);
      }
      this.delay = found ? 250 : Math.min(this.delay * 2, 2_000);
      this.schedule();
    }, this.delay);
  }
}
