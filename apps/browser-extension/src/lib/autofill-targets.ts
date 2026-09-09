import { classifyControl, formControls, semanticCluster, type SupportedControl } from "./form-discovery";
import { createUuid } from "./uuid";
import type { AutofillTarget } from "./protocol";

/** Opaque, expiring references; DOM nodes and form membership stay in this frame. */
export class AutofillTargets {
  private entries = new Map<string, { control: HTMLElement; root: ParentNode; kind: string; documentId: string; expiresAt: number }>();

  capture(control: HTMLElement, documentId: string): AutofillTarget | undefined {
    const kind = classifyControl(control);
    if (!kind || !control.isConnected) return undefined;
    const now = Date.now();
    for (const [id, entry] of this.entries) if (entry.expiresAt <= now || !entry.control.isConnected) this.entries.delete(id);
    const root = semanticCluster(control).root;
    for (const [targetId, entry] of this.entries) {
      if (entry.control === control && entry.root === root && entry.kind === kind && entry.documentId === documentId) {
        entry.expiresAt = now + 60_000;
        return { documentId, targetId };
      }
    }
    if (this.entries.size >= 64) this.entries.delete(this.entries.keys().next().value!);
    const targetId = createUuid();
    this.entries.set(targetId, { control, root, kind, documentId, expiresAt: now + 60_000 });
    return { documentId, targetId };
  }

  resolve(target: AutofillTarget, documentId: string): Set<SupportedControl> | null {
    const entry = this.entries.get(target.targetId);
    if (!entry || target.documentId !== documentId || entry.documentId !== documentId || entry.expiresAt <= Date.now() ||
      !entry.control.isConnected || classifyControl(entry.control) !== entry.kind || semanticCluster(entry.control).root !== entry.root) return null;
    return new Set([entry.control, ...formControls(entry.root)]);
  }

  clear() { this.entries.clear(); }
}
