import { PasswordRandomizer } from "../../libs/tools/generator/core/src/engine/password-randomizer";
import { UsernameRandomizer } from "../../libs/tools/generator/core/src/engine/username-randomizer";
import { WebCryptoRandomizer } from "./password-generator";
import { GeneratorPreferencesSchema, nativePasswordRequest, type GeneratorPreferences } from "./generator-preferences";
import { createVaultMeshUuid } from "./uuid";

export async function generateCredential(preferences: GeneratorPreferences): Promise<string> {
  const settings = GeneratorPreferencesSchema.parse(preferences);
  const random = new WebCryptoRandomizer();
  const password = new PasswordRandomizer(random, Date.now);
  if (settings.mode === "password") return password.randomAscii(nativePasswordRequest(settings.password));
  if (settings.mode === "passphrase") return password.randomEffLongWords({ numberOfWords: settings.passphrase.wordCount,
    separator: settings.passphrase.separator, capitalize: settings.passphrase.capitalize, number: settings.passphrase.includeNumber });
  if (settings.mode === "uuid") {
    let value = createVaultMeshUuid();
    if (!settings.uuid.hyphens) value = value.replaceAll("-", "");
    if (settings.uuid.uppercase) value = value.toUpperCase();
    return settings.uuid.braces ? `{${value}}` : value;
  }
  const { prefix, length, style, includeNumber } = settings.username;
  const start = prefix ? `${prefix}_` : "";
  const remaining = length - start.length;
  let body = "";
  const words = new UsernameRandomizer(random);
  while (body.length < remaining) body += style === "readable" ? await words.randomWords({ numberOfWords: 1, casing: "lowercase" })
    : await random.pick([..."abcdefghijklmnopqrstuvwxyz"]);
  body = body.slice(0, remaining);
  if (includeNumber) body = `${body.slice(0, -2)}${await random.uniform(10, 99)}`;
  return start + body;
}
