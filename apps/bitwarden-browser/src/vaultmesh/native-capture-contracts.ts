import { z } from "zod";
import { NativeItemSourceSchema } from "./vendor/browser-native-item-plan";
export const CAPTURE_ITEM_SAVE = "vaultmesh.native-capture.item-save";
export const CapturedItemValuesSchema = z.array(z.object({ source: NativeItemSourceSchema, value: z.string().min(1).max(10000) }).strict()).min(1).max(30)
  .refine((rows) => new Set(rows.map((row) => row.source)).size === rows.length);
export const CAPTURE_OPTIONS = "vaultmesh.native-capture.options";
export const CAPTURE_SAVE = "vaultmesh.native-capture.save";
export const CAPTURE_STATUS = "vaultmesh.native-capture.status";
export const CaptureRequestSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal(CAPTURE_STATUS) }).strict(),
  z.object({ kind: z.literal(CAPTURE_OPTIONS), captureId: z.string().uuid(), itemKind: z.enum(["card", "identity"]).optional() }).strict(),
  z.object({ kind: z.literal(CAPTURE_ITEM_SAVE), captureId: z.string().uuid(), nonce: z.string().uuid(), itemKind: z.enum(["card", "identity"]),
    values: CapturedItemValuesSchema, itemId: z.string().uuid().optional() }).strict(),
  z.object({ kind: z.literal(CAPTURE_SAVE), captureId: z.string().uuid(), nonce: z.string().uuid(),
    username: z.string().max(2048), password: z.string().min(1).max(10000), itemId: z.string().uuid().optional(),
  }).strict(),
]);
export const CaptureOptionsSchema = z.object({ nonce: z.string().uuid(), expiresAt: z.string().datetime(),
  candidates: z.array(z.object({ id: z.string().uuid(), title: z.string().max(1024), subtitle: z.string().max(2048) }).strict()).max(200),
}).strict();
export function clearCapture(value: unknown): void {
  if (value && typeof value === "object" && "values" in value && Array.isArray(value.values)) {
    for (const row of value.values) if (row && typeof row === "object") row.value = "";
  }
  if (value && typeof value === "object" && "password" in value) value.password = "";
  if (value && typeof value === "object" && "username" in value) value.username = "";
}
