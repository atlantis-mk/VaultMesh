export const VAULT_PAGE_SIZE = 25;

export function paginateVaultItems<Item extends { suggested?: boolean }>(items: readonly Item[], requestedPage: number) {
  const ordered = items
    .map((item, index) => ({ item, index }))
    .sort((left, right) => Number(Boolean(right.item.suggested)) - Number(Boolean(left.item.suggested)) || left.index - right.index)
    .map(({ item }) => item);
  const pageCount = Math.max(1, Math.ceil(ordered.length / VAULT_PAGE_SIZE));
  const page = Math.min(pageCount, Math.max(1, Math.trunc(requestedPage) || 1));
  const start = (page - 1) * VAULT_PAGE_SIZE;
  return { page, pageCount, items: ordered.slice(start, start + VAULT_PAGE_SIZE) };
}
