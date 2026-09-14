import fs from "node:fs";
import path from "node:path";
import matter from "gray-matter";
import YAML from "yaml";

interface NavItem {
  id: string;
  title: string;
  slug?: string;
  url?: string;
  children?: NavItem[];
}

interface VersionManifest {
  versions: string[];
  docs: Record<string, { nav: NavItem[]; pages: { slug: string; title: string }[] }>;
}

interface YmlPage {
  label: string;
  file?: string;
  url?: string;
  pages?: YmlPage[];
}

interface YmlBlock {
  block: string;
  pages: YmlPage[];
}

function scanVersions(baseDir: string): string[] {
  if (!fs.existsSync(baseDir)) return [];
  return fs
    .readdirSync(baseDir)
    .filter((d) => {
      const full = path.join(baseDir, d);
      return fs.statSync(full).isDirectory() && /^v?\d+\.\d+\.\d+$/.test(d);
    })
    .sort((a, b) => {
      const parse = (v: string) => v.replace(/^v/, "").split(".").map(Number);
      const [aM, am, ap] = parse(a);
      const [bM, bm, bp] = parse(b);
      return bM - aM || bm - am || bp - ap;
    });
}

function slugFromRelative(relPath: string): string {
  return relPath.replace(/\.md$/, "").replace(/\//g, "--").replace(/\\/g, "--");
}

function titleFromFile(filePath: string, fallback: string): string {
  if (!fs.existsSync(filePath)) return fallback;
  const raw = fs.readFileSync(filePath, "utf-8");
  const { data, content } = matter(raw);
  if (data.title) return data.title;
  const m = content.match(/^#\s+(.+)$/m);
  if (m) return m[1];
  return fallback;
}

function escapeForTs(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/`/g, "\\`").replace(/\$/g, "\\$");
}

function buildNavFromYml(ymlRoot: YmlBlock[], versionDir: string): NavItem[] {
  const buildItems = (pages: YmlPage[], parentId: string): NavItem[] =>
    pages.flatMap((page, index) => {
      if (page.pages) {
        const children = buildItems(page.pages, `${parentId}:${index}`);
        return children.length
          ? [{ id: `group:${parentId}:${page.label}`, title: page.label, children }]
          : [];
      }
      if (page.url) return [{ id: `url:${page.url}`, title: page.label, url: page.url }];
      if (!page.file) return [];
      const rel = page.file.replace(/\\/g, "/");
      const full = path.join(versionDir, rel);
      if (!fs.existsSync(full)) return [];
      const slug = slugFromRelative(rel);
      return [{ id: slug, title: titleFromFile(full, page.label), slug }];
    });

  return ymlRoot.flatMap((block) => {
    const children = buildItems(block.pages || [], block.block);
    return children.length
      ? [{ id: `group:${block.block}`, title: block.block, children }]
      : [];
  });
}

function collectPages(items: NavItem[]): { slug: string; title: string }[] {
  const pages: { slug: string; title: string }[] = [];
  for (const item of items) {
    if (item.slug) pages.push({ slug: item.slug, title: item.title });
    if (item.children) pages.push(...collectPages(item.children));
  }
  return pages;
}

async function main() {
  const ROOT = path.resolve(import.meta.dirname, "..");
  const CONTENT_DIR = path.join(ROOT, "docs-content");
  const GENERATED_DIR = path.join(ROOT, "src", "generated");

  const ymlPath = path.join(CONTENT_DIR, "nav.yml");
  if (!fs.existsSync(ymlPath)) {
    console.error("Missing docs-content/nav.yml");
    process.exit(1);
  }
  const ymlRoot = YAML.parse(fs.readFileSync(ymlPath, "utf-8")) as {
    nav: YmlBlock[];
  };
  if (!Array.isArray(ymlRoot?.nav)) {
    console.error("nav.yml must have a top-level `nav` list");
    process.exit(1);
  }

  const versions = scanVersions(CONTENT_DIR);
  if (versions.length === 0) {
    console.error("No versions found in docs-content/");
    process.exit(1);
  }

  fs.mkdirSync(GENERATED_DIR, { recursive: true });

  const manifest: VersionManifest = { versions, docs: {} };
  const pageEntries: { key: string; content: string }[] = [];

  for (const version of versions) {
    const versionDir = path.join(CONTENT_DIR, version);
    const nav = buildNavFromYml(ymlRoot.nav, versionDir);
    const pages = collectPages(nav);

    const apiDir = path.join(versionDir, "api");
    const apiModules = fs.existsSync(apiDir)
      ? fs.readdirSync(apiDir, { recursive: true })
        .filter((entry): entry is string => typeof entry === "string" && entry.endsWith(".md") && entry !== "index.md")
        .map((entry) => entry.replace(/\\/g, "/").replace(/\.md$/, "").replace(/\//g, "."))
        .sort()
      : [];
    manifest.docs[version] = { nav, pages, apiModules };

    for (const page of pages) {
      const filePath = path.join(versionDir, page.slug.replace(/--/g, "/") + ".md");
      const raw = fs.readFileSync(filePath, "utf-8");
      const { content } = matter(raw);
      pageEntries.push({ key: `${version}/${page.slug}`, content });
    }
  }

  fs.writeFileSync(
    path.join(GENERATED_DIR, "manifest.json"),
    JSON.stringify(manifest, null, 2),
  );

  const pageLines = pageEntries.map(
    (e) =>
      `  ${JSON.stringify(e.key)}: () => (\n` +
      `    <MarkdownRenderer content={\`${escapeForTs(e.content)}\`} />\n` +
      `  ),`,
  );

  fs.writeFileSync(
    path.join(GENERATED_DIR, "pages.tsx"),
    "// Auto-generated by scripts/build-docs.ts — do not edit\n\n" +
      `import type { ComponentType } from "react";\n` +
      `import { MarkdownRenderer } from "@/components/MarkdownRenderer";\n\n` +
      `export const mdPages: Record<string, ComponentType> = {\n` +
      pageLines.join("\n") +
      `\n};\n`,
  );

  console.log(`Generated ${versions.length} version(s), ${pageEntries.length} page(s).`);
}

main();