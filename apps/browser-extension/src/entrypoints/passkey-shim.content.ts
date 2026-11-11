import { createWindowTransport, installCapabilityShim, installPasskeyShim } from "@/lib/passkey-shim";

// MAIN world, Chromium only (ADR-0057). The shim holds no secrets; it asks the
// isolated bridge whether VaultMesh serves each request and otherwise calls the
// browser's own WebAuthn implementation in the same call.
export default defineContentScript({
  matches: ["http://*/*", "https://*/*"],
  exclude: ["firefox"],
  allFrames: true,
  matchAboutBlank: true,
  matchOriginAsFallback: true,
  runAt: "document_start",
  world: "MAIN",
  main() {
    const credentials = navigator.credentials;
    if (!credentials || typeof PublicKeyCredential === "undefined") return;
    const marker = Symbol.for("vaultmesh.passkey-shim");
    const prototype = Object.getPrototypeOf(credentials) as Record<symbol, unknown>;
    if (prototype[marker]) return;
    Object.defineProperty(prototype, marker, { value: true });
    const transport = createWindowTransport();
    installPasskeyShim(
      prototype as never,
      transport,
      { PublicKeyCredential, AuthenticatorAttestationResponse, AuthenticatorAssertionResponse },
      undefined,
      (reason) => {
        console.debug(`[VaultMesh Passkey] handled by browser (${reason})`);
        transport.note?.(reason);
      },
    );
    installCapabilityShim(
      PublicKeyCredential as never,
      transport,
      undefined,
      (reason) => console.debug(`[VaultMesh Passkey] ${reason}`),
    );
  },
});
