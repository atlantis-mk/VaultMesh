/** Popup, notification and confirmation window can confirm the same capture. */
export function runCaptureSaveOnce<T>(inFlight: Map<string, Promise<T>>, captureId: string, save: () => Promise<T>): Promise<T> {
  const existing = inFlight.get(captureId);
  if (existing) return existing;
  // Install the entry synchronously, before any mutation or callback runs.
  const operation = Promise.resolve().then(save).finally(() => {
    if (inFlight.get(captureId) === operation) inFlight.delete(captureId);
  });
  inFlight.set(captureId, operation);
  return operation;
}
