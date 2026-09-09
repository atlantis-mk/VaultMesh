import { describe, expect, it } from "vitest";
import { runCaptureSaveOnce } from "./capture-save-gate";

describe("CT-AUTOFILL-002 concurrent save confirmation", () => {
  it("shares the same write across simultaneous confirmation surfaces", async () => {
    const inFlight = new Map<string, Promise<string>>();
    let complete!: (value: string) => void;
    let writes = 0;
    const save = () => { writes += 1; return new Promise<string>((resolve) => { complete = resolve; }); };
    const popup = runCaptureSaveOnce(inFlight, "capture", save);
    const notification = runCaptureSaveOnce(inFlight, "capture", save);
    const confirmationWindow = runCaptureSaveOnce(inFlight, "capture", save);
    await Promise.resolve();
    expect(writes).toBe(1);
    complete("saved");
    expect(await Promise.all([popup, notification, confirmationWindow])).toEqual(["saved", "saved", "saved"]);
    expect(inFlight.size).toBe(0);
  });

  it("releases a failed operation and keeps independent captures independent", async () => {
    const inFlight = new Map<string, Promise<string>>();
    const failed = runCaptureSaveOnce(inFlight, "a", async () => { throw new Error("write failed"); });
    const other = runCaptureSaveOnce(inFlight, "b", async () => "saved");
    await expect(failed).rejects.toThrow("write failed");
    await expect(other).resolves.toBe("saved");
    expect(inFlight.size).toBe(0);
  });
});
