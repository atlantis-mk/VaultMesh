export type FrameLike = { frameId: number; parentFrameId: number; url: string };

export function sameOriginFrameIds(frames: FrameLike[], topOrigin: string) {
  const byId = new Map(frames.map((frame) => [frame.frameId, frame]));
  const origins = new Map<number, string | null>();

  const originFor = (frame: FrameLike, visiting = new Set<number>()): string | null => {
    if (origins.has(frame.frameId)) return origins.get(frame.frameId) ?? null;
    const direct = httpOrigin(frame.url);
    if (direct) {
      origins.set(frame.frameId, direct);
      return direct;
    }
    if (!inheritsParentOrigin(frame.url) || frame.parentFrameId < 0 || visiting.has(frame.frameId)) return null;
    visiting.add(frame.frameId);
    const parent = byId.get(frame.parentFrameId);
    const inherited = parent ? originFor(parent, visiting) : null;
    origins.set(frame.frameId, inherited);
    return inherited;
  };

  return frames.filter((frame) => originFor(frame) === topOrigin).map((frame) => frame.frameId);
}

/** True only when the frame and every ancestor resolve to exactly `origin`.
 * Unknown ancestors, opaque origins and cycles all fail closed. */
export function sameOriginWithAncestors(frames: FrameLike[], frameId: number, origin: string): boolean {
  const byId = new Map(frames.map((frame) => [frame.frameId, frame]));
  const resolve = (frame: FrameLike, seen: Set<number>): string | null => {
    const direct = httpOrigin(frame.url);
    if (direct) return direct;
    if (!inheritsParentOrigin(frame.url) || frame.parentFrameId < 0 || seen.has(frame.frameId)) return null;
    seen.add(frame.frameId);
    const parent = byId.get(frame.parentFrameId);
    return parent ? resolve(parent, seen) : null;
  };
  let current = byId.get(frameId);
  const visited = new Set<number>();
  while (current) {
    if (visited.has(current.frameId) || resolve(current, new Set()) !== origin) return false;
    visited.add(current.frameId);
    if (current.parentFrameId < 0) return true;
    current = byId.get(current.parentFrameId);
  }
  return false;
}

function httpOrigin(url: string) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.origin : null;
  } catch {
    return null;
  }
}

function inheritsParentOrigin(url: string) {
  return url === "about:srcdoc" || url === "about:blank" || url.startsWith("about:blank#") || url.startsWith("about:blank?");
}
