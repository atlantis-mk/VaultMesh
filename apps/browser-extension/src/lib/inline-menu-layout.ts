/** Stay inside the originating frame, including short authentication iframes. */
export function inlineMenuLayout(
  anchor: Pick<DOMRect, "left" | "right" | "top" | "bottom" | "width">,
  viewport: { width: number; height: number; left?: number; top?: number },
) {
  const leftEdge = (viewport.left ?? 0) + 8;
  const topEdge = (viewport.top ?? 0) + 8;
  const rightEdge = (viewport.left ?? 0) + viewport.width - 8;
  const bottomEdge = (viewport.top ?? 0) + viewport.height - 8;
  if (rightEdge <= leftEdge || bottomEdge <= topEdge || anchor.bottom <= topEdge - 8 ||
      anchor.right <= leftEdge - 8 || anchor.top >= bottomEdge + 8 || anchor.left >= rightEdge + 8) return null;
  const width = Math.min(Math.max(240, anchor.width), rightEdge - leftEdge);
  const below = bottomEdge - anchor.bottom - 4;
  const above = anchor.top - topEdge - 4;
  const side = below >= 180 || below >= above ? "below" : "above";
  const available = side === "below" ? below : above;
  // If neither side fits a useful list, use a scrollable in-frame overlay.
  const compact = available < 96;
  const maxHeight = Math.min(280, compact ? bottomEdge - topEdge : available);
  return {
    left: Math.max(leftEdge, Math.min(anchor.left, rightEdge - width)), width, maxHeight,
    top: compact ? topEdge : side === "below" ? anchor.bottom + 4 : undefined,
    bottom: !compact && side === "above" ? anchor.top - 4 : undefined,
  };
}
