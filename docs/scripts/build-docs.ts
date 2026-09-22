import fs from "node:fs"
import path from "node:path"
import matter from "gray-matter"
import YAML from "yaml"

interface NavItem {
  id: string
  title: string
  slug?: string
  url?: string
  children?: NavItem[]
}

interface DocumentationPage {
  slug: string
  title: string
}

interface VersionManifest {
  versions: string[]
  docs: Record<string, {
    nav: NavItem[]
    pages: DocumentationPage[]
    apiModules: string[]
  }>
}

interface YmlPage {
  label: string
  file?: string
  url?: string
  pages?: YmlPage[]
}

interface YmlBlock {
  block: string
  pages: YmlPage[]
}

interface LlmPage extends DocumentationPage {
  content: string
}

function scanVersions(baseDir: string): string[] {
  if (!fs.existsSync(baseDir)) return []
  return fs
    .readdirSync(baseDir)
    .filter((d) => {
      const full = path.join(baseDir, d)
      return fs.statSync(full).isDirectory() && /^v?\d+\.\d+\.\d+$/.test(d)
    })
    .sort((a, b) => {
      const parse = (v: string) => v.replace(/^v/, "").split(".").map(Number)
      const [aM, am, ap] = parse(a)
      const [bM, bm, bp] = parse(b)
      return bM - aM || bm - am || bp - ap
    })
}

function slugFromRelative(relPath: string): string {
  return relPath.replace(/\.md$/, "").replace(/\//g, "--").replace(/\\/g, "--")
}

function escapeForTs(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/`/g, "\\`").replace(/\$/g, "\\$")
}

function linksToLatest(content: string, version: string): string {
  return content.replaceAll(`](/${version}/`, "](/latest/")
}

function searchTextFromMarkdown(content: string): string {
  return content
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/```[^\n]*\n([\s\S]*?)```/g, " $1 ")
    .replace(/!\[([^\]]*)\]\([^)]*\)/g, " $1 ")
    .replace(/\[([^\]]+)\]\([^)]*\)/g, " $1 ")
    .replace(/<[^>]+>/g, " ")
    .replace(/^[ \t]*[:]{3}\w+[^\n]*$/gm, " ")
    .replace(/^[ \t]*#{1,6}[ \t]+/gm, "")
    .replace(/^[ \t]*[-*+>][ \t]+/gm, "")
    .replace(/[`*~|]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
}

function buildNavFromYml(ymlRoot: YmlBlock[], versionDir: string): NavItem[] {
  const buildItems = (pages: YmlPage[], parentId: string): NavItem[] =>
    pages.flatMap((page, index) => {
      if (page.pages) {
        const children = buildItems(page.pages, `${parentId}:${index}`)
        return children.length
          ? [
              {
                id: `group:${parentId}:${page.label}`,
                title: page.label,
                children,
              },
            ]
          : []
      }
      if (page.url)
        return [{ id: `url:${page.url}`, title: page.label, url: page.url }]
      if (!page.file) return []
      const rel = page.file.replace(/\\/g, "/")
      const full = path.join(versionDir, rel)
      if (!fs.existsSync(full)) return []
      const slug = slugFromRelative(rel)
      return [{ id: slug, title: page.label, slug }]
    })

  return ymlRoot.flatMap((block) => {
    const children = buildItems(block.pages || [], block.block)
    return children.length
      ? [{ id: `group:${block.block}`, title: block.block, children }]
      : []
  })
}

function collectPages(items: NavItem[]): DocumentationPage[] {
  const pages: DocumentationPage[] = []
  for (const item of items) {
    if (item.slug) pages.push({ slug: item.slug, title: item.title })
    if (item.children) pages.push(...collectPages(item.children))
  }
  return pages
}

function buildLlmDocs(version: string, pages: LlmPage[]): string {
  const sections = pages.map((page) => {
    const route =
      page.slug === "api--index"
        ? "/api"
        : `/latest/${page.slug.replace(/--/g, "/")}`
    return [
      "---",
      "",
      `Document: ${page.title}`,
      `Source: ${route}`,
      "",
      page.content.trim(),
    ].join("\n")
  })

  return [
    "# Jam documentation",
    "",
    `Complete documentation for Jam ${version} (latest).`,
    "The documents follow the same order as the documentation navigation.",
    "",
    ...sections,
    "",
  ].join("\n")
}

async function main() {
  const ROOT = path.resolve(import.meta.dirname, "..")
  const CONTENT_DIR = path.join(ROOT, "docs-content")
  const GENERATED_DIR = path.join(ROOT, "src", "generated")
  const PUBLIC_DIR = path.join(ROOT, "public")

  const ymlPath = path.join(CONTENT_DIR, "nav.yml")
  if (!fs.existsSync(ymlPath)) {
    console.error("Missing docs-content/nav.yml")
    process.exit(1)
  }
  const ymlRoot = YAML.parse(fs.readFileSync(ymlPath, "utf-8")) as {
    nav: YmlBlock[]
  }
  if (!Array.isArray(ymlRoot?.nav)) {
    console.error("nav.yml must have a top-level `nav` list")
    process.exit(1)
  }

  const versions = scanVersions(CONTENT_DIR)
  if (versions.length === 0) {
    console.error("No versions found in docs-content/")
    process.exit(1)
  }

  fs.mkdirSync(GENERATED_DIR, { recursive: true })

  const manifest: VersionManifest = { versions, docs: {} }
  const searchIndex: Record<string, {
    slug: string
    title: string
    text: string
  }[]> = {}
  const pageEntries: {
    key: string
    content: string
  }[] = []
  const llmPages: LlmPage[] = []

  for (const version of versions) {
    const versionDir = path.join(CONTENT_DIR, version)
    const nav = buildNavFromYml(ymlRoot.nav, versionDir)
    const pages = collectPages(nav)

    const apiDir = path.join(versionDir, "api")
    const apiModules = fs.existsSync(apiDir)
      ? fs
          .readdirSync(apiDir, { recursive: true })
          .filter(
            (entry): entry is string =>
              typeof entry === "string" &&
              entry.endsWith(".md") &&
              entry !== "index.md",
          )
          .map((entry) =>
            entry.replace(/\\/g, "/").replace(/\.md$/, "").replace(/\//g, "."),
          )
          .sort()
      : []
    const indexedPages: {
      slug: string
      title: string
      text: string
    }[] = []

    for (const page of pages) {
      const filePath = path.join(
        versionDir,
        page.slug.replace(/--/g, "/") + ".md",
      )
      const raw = fs.readFileSync(filePath, "utf-8")
      const { content } = matter(raw)
      indexedPages.push({
        ...page,
        text: searchTextFromMarkdown(content),
      })
      pageEntries.push({
        key: `${version}/${page.slug}`,
        content:
          version === versions[0] ? linksToLatest(content, version) : content,
      })
      if (version === versions[0]) {
        llmPages.push({
          ...page,
          content: linksToLatest(content, version),
        })
      }
    }
    manifest.docs[version] = { nav, pages, apiModules }
    searchIndex[version] = indexedPages
  }

  fs.writeFileSync(
    path.join(GENERATED_DIR, "manifest.json"),
    JSON.stringify(manifest, null, 2),
  )

  fs.writeFileSync(
    path.join(GENERATED_DIR, "search-index.json"),
    JSON.stringify(searchIndex, null, 2),
  )

  const pageLines = pageEntries.map(
    (e) =>
      `  ${JSON.stringify(e.key)}: () => (\n` +
      `    <MarkdownRenderer content={\`${escapeForTs(e.content)}\`} />\n` +
      `  ),`,
  )

  fs.writeFileSync(
    path.join(GENERATED_DIR, "pages.tsx"),
    "// Auto-generated by scripts/build-docs.ts — do not edit\n\n" +
      `import type { ComponentType } from "react";\n` +
      `import { MarkdownRenderer } from "@/components/MarkdownRenderer";\n\n` +
      `export const mdPages: Record<string, ComponentType> = {\n` +
      pageLines.join("\n") +
      `\n};\n`,
  )

  fs.mkdirSync(PUBLIC_DIR, { recursive: true })
  fs.writeFileSync(
    path.join(PUBLIC_DIR, "llm-docs.txt"),
    buildLlmDocs(versions[0], llmPages),
  )

  console.log(
    `Generated ${versions.length} version(s), ${pageEntries.length} page(s).`,
  )
  console.log(`Generated llm-docs.txt from ${llmPages.length} latest page(s).`)
}

main()
