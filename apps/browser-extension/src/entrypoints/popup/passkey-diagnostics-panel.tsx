import { useState } from "react";

import { Button } from "@/components/ui/button";
import { explainPasskeyDiagnostic, type PasskeyDiagnostic } from "@/lib/passkey-diagnostics";

function parseEntries(value: unknown): PasskeyDiagnostic[] {
  const entries = (value as { entries?: unknown } | null)?.entries;
  if (!Array.isArray(entries)) return [];
  return entries.filter((entry): entry is PasskeyDiagnostic => typeof entry?.at === "number" && typeof entry?.message === "string");
}

/** Lets a user see how recent passkey requests were handled without developer tools. */
export function PasskeyDiagnosticsPanel() {
  const [entries, setEntries] = useState<PasskeyDiagnostic[] | null>(null);
  const [busy, setBusy] = useState(false);

  async function refresh() {
    setBusy(true);
    try {
      setEntries(parseEntries(await browser.runtime.sendMessage({ kind: "vaultmesh.passkey-diagnostics.get" })));
    } catch {
      setEntries([]);
    } finally {
      setBusy(false);
    }
  }

  async function clear() {
    setBusy(true);
    try {
      await browser.runtime.sendMessage({ kind: "vaultmesh.passkey-diagnostics.clear" });
      setEntries([]);
    } finally {
      setBusy(false);
    }
  }

  if (entries === null) {
    return <Button type="button" size="sm" variant="outline" className="self-start text-xs" disabled={busy} onClick={() => void refresh()}>查看最近的通行密钥请求</Button>;
  }
  return (
    <div className="flex flex-col gap-2 rounded-md bg-muted px-3 py-2 text-xs" aria-label="最近的通行密钥请求">
      <div className="flex items-center justify-between gap-2">
        <span className="font-medium">最近的通行密钥请求</span>
        <span className="flex gap-1">
          <Button type="button" size="xs" variant="ghost" disabled={busy} onClick={() => void refresh()}>刷新</Button>
          <Button type="button" size="xs" variant="ghost" disabled={busy || entries.length === 0} onClick={() => void clear()}>清除</Button>
          <Button type="button" size="xs" variant="ghost" onClick={() => setEntries(null)}>收起</Button>
        </span>
      </div>
      {entries.length === 0 ? <p className="text-muted-foreground">暂无记录。请在网站上重试一次，再点“刷新”。记录只保存在本次浏览器会话的内存里，不含请求内容。</p> : (
        <ol className="flex max-h-56 flex-col gap-2 overflow-auto">
          {[...entries].reverse().map((entry) => (
            <li key={`${entry.at}:${entry.message}`} className="flex flex-col gap-0.5">
              <span className="text-muted-foreground">{new Date(entry.at).toLocaleTimeString()}</span>
              <span className="break-all">{entry.message.replace("[VaultMesh Passkey] ", "")}</span>
              {explainPasskeyDiagnostic(entry.message) ? <span className="text-foreground/80">{explainPasskeyDiagnostic(entry.message)}</span> : null}
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
