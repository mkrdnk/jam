import type { NavItem } from "@/types";

export function findPageBySlug(
  nav: NavItem[],
  slug: string,
): NavItem | undefined {
  for (const item of nav) {
    if (item.slug === slug) return item;
    if (item.children) {
      const found = findPageBySlug(item.children, slug);
      if (found) return found;
    }
  }
  return undefined;
}

export function getPageIndex(
  nav: NavItem[],
  slug: string,
): number {
  const flat = flattenNav(nav);
  return flat.findIndex((p) => p.slug === slug);
}

export function getAdjacentPages(
  nav: NavItem[],
  slug: string,
): { prev: NavItem | undefined; next: NavItem | undefined } {
  const flat = flattenNav(nav);
  const idx = flat.findIndex((p) => p.slug === slug);
  return {
    prev: idx > 0 ? flat[idx - 1] : undefined,
    next: idx < flat.length - 1 ? flat[idx + 1] : undefined,
  };
}

export function flattenNav(items: NavItem[]): NavItem[] {
  const result: NavItem[] = [];
  for (const item of items) {
    if (item.slug) result.push(item);
    if (item.children) result.push(...flattenNav(item.children));
  }
  return result;
}

export function getFirstPageSlug(nav: NavItem[]): string {
  return flattenNav(nav)[0]?.slug ?? "";
}

export function isGroupActive(
  group: NavItem,
  currentSlug: string,
): boolean {
  if (group.slug === currentSlug) return true;
  if (!group.children) return false;
  return group.children.some(
    (child) =>
      child.slug === currentSlug ||
      (child.children && isGroupActive(child, currentSlug)),
  );
}
