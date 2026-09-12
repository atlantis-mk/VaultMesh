import { QR_SCAN, QrGrantSchema, QrResponseSchema, clearQr, parseTotpQr, type QrGrant, type TotpQr } from "./qr-contracts";

/** Only the invoking popup receives QR material. The worker issues metadata-only grants. */
export async function collectQr(grant: QrGrant, current: () => boolean): Promise<TotpQr[]> {
  const parsed = QrGrantSchema.parse(grant);
  const expiresAt = Math.min(parsed.expiresAt, Date.now() + 10000);
  const valid = () => current() && Date.now() < expiresAt;
  if (!valid()) return [];
  const values: TotpQr[] = [];
  await Promise.all(parsed.frames.map((frame) => new Promise<void>((resolve) => {
    let completed = false;
    const timer = setTimeout(() => { completed = true; resolve(); }, Math.max(1, expiresAt - Date.now()));
    try {
      chrome.tabs.sendMessage(parsed.tabId, { kind: QR_SCAN, requestId: parsed.requestId, url: frame.url, expiresAt }, { frameId: frame.frameId }, (raw) => {
        try {
          if (chrome.runtime.lastError || completed || !valid()) return;
          const response = QrResponseSchema.safeParse(raw);
          if (!response.success) return;
          try {
            if (response.data.requestId !== parsed.requestId) return;
            for (const item of response.data.values) {
              // Labels are derived again from the URI, never trusted separately.
              const value = parseTotpQr(item.uri);
              if (value && values.length < 20 && !values.some((existing) => existing.uri === value.uri)) values.push(value);
            }
          } finally { clearQr(response.data.values); }
        } finally {
          if (Array.isArray(raw?.values)) for (const value of raw.values) if (value && typeof value === "object") value.uri = "";
          completed = true; clearTimeout(timer); resolve();
        }
      });
    } catch { completed = true; clearTimeout(timer); resolve(); }
  })));
  if (!valid()) clearQr(values);
  return values;
}
