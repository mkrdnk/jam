export interface NavItem {
  id: string;
  title: string;
  slug?: string;
  url?: string;
  children?: NavItem[];
}

export interface SearchPage {
  slug: string;
  title: string;
  text: string;
}

export type SearchIndex = Record<string, SearchPage[]>;

export interface VersionManifest {
  versions: string[];
  docs: Record<
    string,
    { nav: NavItem[]; pages: { slug: string; title: string }[]; apiModules?: string[] }
  >;
}
