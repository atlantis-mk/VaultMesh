import { afterEach, expect, it, vi } from "vitest";
import { openDeviceAssist } from "./device-assist-overlay";

afterEach(() => { document.body.innerHTML = ""; vi.restoreAllMocks(); });

it("CT-DEVICE-ASSIST-002 re-binds the original field for every start instead of reusing an expired binding", async () => {
  document.body.innerHTML = '<input id="code" autocomplete="one-time-code">';
  const target = document.querySelector<HTMLInputElement>("#code")!;
  Object.defineProperty(target, "getClientRects", { value: () => [{ width: 240, height: 32 }] });
  const bindings = [{ documentId: crypto.randomUUID(), targetId: crypto.randomUUID() }, undefined];
  const bind = vi.fn(() => bindings.shift());
  const send = vi.fn(async () => ({ status: "no-supported-fields" }));
  const close = openDeviceAssist(document, target, bind, "sms", send);
  await vi.waitFor(() => expect(send).toHaveBeenCalledTimes(1));
  expect(send).toHaveBeenCalledWith({ kind: "vaultmesh.device-assist-start", assistKind: "sms", target: expect.objectContaining({ targetId: expect.any(String) }) });
  close();
  // A second panel whose binding can no longer be captured must not send a stale target.
  const again = openDeviceAssist(document, target, bind, "sms", send);
  await vi.waitFor(() => expect(bind).toHaveBeenCalledTimes(2));
  expect(send).toHaveBeenCalledTimes(1);
  again();
});
