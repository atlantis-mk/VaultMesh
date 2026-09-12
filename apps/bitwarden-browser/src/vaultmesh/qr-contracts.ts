import { z } from "zod";
export const QR_SCAN = "vaultmesh.native-qr.scan";
export const QR_CHECK = "vaultmesh.native-qr.check";
export function parseTotpQr(raw: string): { uri: string; issuer: string | null; account: string | null } | null {
  try {
    if (raw.length > 10000) return null;
    const uri = new URL(raw.trim());
    if (uri.protocol !== "otpauth:" || uri.hostname !== "totp" || !uri.pathname.slice(1) || uri.username || uri.password || uri.port || uri.hash) return null;
    for (const key of ["secret", "algorithm", "digits", "period", "issuer"]) if (uri.searchParams.getAll(key).length > 1) return null;
    if (!/^[A-Z2-7]+=*$/i.test(uri.searchParams.get("secret")?.replace(/\s/g, "") ?? "")) return null;
    if (uri.searchParams.has("algorithm") && uri.searchParams.get("algorithm")?.toUpperCase() !== "SHA1"
      || uri.searchParams.has("digits") && uri.searchParams.get("digits") !== "6"
      || uri.searchParams.has("period") && uri.searchParams.get("period") !== "30") return null;
    const label = decodeURIComponent(uri.pathname.slice(1)); const separator = label.indexOf(":");
    return { uri: raw.trim(), issuer: (uri.searchParams.get("issuer") || (separator < 0 ? "" : label.slice(0, separator))).slice(0, 256) || null,
      account: (separator < 0 ? label : label.slice(separator + 1)).slice(0, 2048) || null };
  } catch { return null; }
}
export const TotpQrSchema = z.object({ uri: z.string().min(1).max(10000).refine((value) => !!parseTotpQr(value)), issuer: z.string().max(256).nullable(), account: z.string().max(2048).nullable() }).strict();
export type TotpQr = z.infer<typeof TotpQrSchema>;
export const QrGrantSchema = z.object({ requestId: z.uuid(), tabId: z.number().int().nonnegative(), topUrl: z.string().url().max(8192), expiresAt: z.number().int().positive(),
  frames: z.array(z.object({ frameId: z.number().int().nonnegative(), url: z.string().url().max(8192) }).strict()).min(1).max(16) }).strict();
export type QrGrant = z.infer<typeof QrGrantSchema>;
export const QrResponseSchema = z.object({ requestId: z.uuid(), values: z.array(TotpQrSchema).max(20) }).strict();
export function clearQr(values: TotpQr[]): void { for (const value of values) value.uri = ""; values.length = 0; }
