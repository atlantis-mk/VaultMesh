import { describe, expect, it } from "vitest";

import { paginateVaultItems, VAULT_PAGE_SIZE } from "./vault-pagination";

describe("CT-BROWSER-001 vault pagination", () => {
  const items = Array.from({ length: 503 }, (_, index) => ({ id: index, suggested: index === 500 || index === 501 }));

  it("renders no more than 25 summaries and reaches the last page", () => {
    const first = paginateVaultItems(items, 1);
    const last = paginateVaultItems(items, 999);
    expect(first.items).toHaveLength(VAULT_PAGE_SIZE);
    expect(first.items.slice(0, 2).map((item) => item.id)).toEqual([500, 501]);
    expect(last.page).toBe(21);
    expect(last.items).toHaveLength(3);
  });

  it("converges after a filtered list becomes shorter", () => {
    expect(paginateVaultItems(items.slice(0, 7), 12)).toMatchObject({ page: 1, pageCount: 1 });
  });
});
