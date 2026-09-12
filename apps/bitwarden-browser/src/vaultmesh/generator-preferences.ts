import { z } from "zod";
export const GENERATOR_KEY = "vaultmesh.bitwarden-dev.generator.v1";
const password = z.object({ length: z.number().int().min(8).max(128), uppercase: z.boolean(), lowercase: z.boolean(), numbers: z.boolean(), symbols: z.boolean(),
  minimumNumbers: z.number().int().min(0).max(8), minimumSymbols: z.number().int().min(0).max(8), avoidAmbiguous: z.boolean() }).strict()
  .refine((value) => value.uppercase || value.lowercase || value.numbers || value.symbols)
  .refine((value) => passwordMinimum(value) <= value.length);
export const GeneratorPreferencesSchema = z.object({
  mode: z.enum(["password", "passphrase", "username", "uuid"]), password,
  passphrase: z.object({ wordCount: z.number().int().min(3).max(8), separator: z.enum(["-", ".", "_", " "]), capitalize: z.boolean(), includeNumber: z.boolean() }).strict(),
  username: z.object({ length: z.number().int().min(8).max(24), prefix: z.string().max(8).regex(/^[a-zA-Z0-9_-]*$/), style: z.enum(["readable", "random"]), includeNumber: z.boolean() }).strict()
    .refine((value) => value.prefix.length + (value.prefix ? 1 : 0) + 2 <= value.length),
  uuid: z.object({ hyphens: z.boolean(), uppercase: z.boolean(), braces: z.boolean() }).strict(),
}).strict();
export type GeneratorPreferences = z.infer<typeof GeneratorPreferencesSchema>;
export const DEFAULT_GENERATOR_PREFERENCES: GeneratorPreferences = {
  mode: "password", password: { length: 20, uppercase: true, lowercase: true, numbers: true, symbols: true, minimumNumbers: 1, minimumSymbols: 1, avoidAmbiguous: true },
  passphrase: { wordCount: 5, separator: "-", capitalize: false, includeNumber: true },
  username: { length: 16, prefix: "vm", style: "readable", includeNumber: true }, uuid: { hyphens: true, uppercase: false, braces: false },
};
function passwordMinimum(value: { uppercase: boolean; lowercase: boolean; numbers: boolean; symbols: boolean; minimumNumbers: number; minimumSymbols: number }) {
  return Number(value.uppercase) + Number(value.lowercase) + (value.numbers ? Math.max(1, value.minimumNumbers) : 0) + (value.symbols ? Math.max(1, value.minimumSymbols) : 0);
}
export function nativePasswordRequest(value: GeneratorPreferences["password"]) {
  password.parse(value);
  return { all: value.length - passwordMinimum(value), uppercase: value.uppercase ? 1 : undefined, lowercase: value.lowercase ? 1 : undefined,
    digits: value.numbers ? Math.max(1, value.minimumNumbers) : undefined, special: value.symbols ? Math.max(1, value.minimumSymbols) : undefined, ambiguous: !value.avoidAmbiguous };
}
export async function loadGeneratorPreferences(): Promise<GeneratorPreferences> {
  return new Promise<GeneratorPreferences>((resolve) => chrome.storage.local.get(GENERATOR_KEY, (result) => {
    const parsed = GeneratorPreferencesSchema.safeParse(result?.[GENERATOR_KEY]);
    resolve(!chrome.runtime.lastError && parsed.success ? parsed.data : GeneratorPreferencesSchema.parse(DEFAULT_GENERATOR_PREFERENCES));
  })).catch(() => GeneratorPreferencesSchema.parse(DEFAULT_GENERATOR_PREFERENCES));
}
export async function saveGeneratorPreferences(value: GeneratorPreferences): Promise<boolean> {
  const parsed = GeneratorPreferencesSchema.safeParse(value);
  if (!parsed.success) return false;
  return new Promise<boolean>((resolve) => chrome.storage.local.set({ [GENERATOR_KEY]: parsed.data }, () => resolve(!chrome.runtime.lastError))).catch(() => false);
}
