import fs from "node:fs"
import path from "node:path"

interface PageManifest {
  slug: string
}

interface VersionManifest {
  versions: string[]
  docs: Record<string, { pages: PageManifest[] }>
}

const ROOT = path.resolve(import.meta.dirname, "..")
const DIST_DIR = path.join(ROOT, "dist")
const INDEX_PATH = path.join(DIST_DIR, "index.html")
const MANIFEST_PATH = path.join(ROOT, "src", "generated", "manifest.json")
const TOP_LEVEL_ROUTES = ["api", "search"]

function routeFromSlug(slug: string): string {
  const segments = slug.split("--")
  if (
    segments.some(
      (segment) =>
        !segment ||
        segment === "." ||
        segment === ".." ||
        segment.includes("/") ||
        segment.includes("\\"),
    )
  ) {
    throw new Error(`Invalid documentation slug: ${JSON.stringify(slug)}`)
  }
  return segments.join("/")
}

function readManifest(): VersionManifest {
  if (!fs.existsSync(MANIFEST_PATH)) {
    throw new Error(`Documentation manifest not found: ${MANIFEST_PATH}`)
  }

  const manifest = JSON.parse(
    fs.readFileSync(MANIFEST_PATH, "utf-8"),
  ) as VersionManifest
  if (!Array.isArray(manifest.versions) || manifest.versions.length === 0) {
    throw new Error("Documentation manifest does not contain any versions")
  }
  return manifest
}

function documentationRoutes(manifest: VersionManifest): Set<string> {
  const routes = new Set(TOP_LEVEL_ROUTES)
  const newestVersion = manifest.versions[0]

  for (const version of manifest.versions) {
    const pages = manifest.docs[version]?.pages
    if (!Array.isArray(pages)) {
      throw new Error(`Documentation pages are missing for version ${version}`)
    }

    for (const page of pages) {
      const pageRoute = routeFromSlug(page.slug)
      routes.add(`${version}/${pageRoute}`)
      if (version === newestVersion) {
        routes.add(`latest/${pageRoute}`)
      }
    }
  }

  return routes
}

function writeEntryPoint(route: string): void {
  const routeDirectory = path.join(DIST_DIR, ...route.split("/"))
  fs.mkdirSync(routeDirectory, { recursive: true })
  fs.copyFileSync(INDEX_PATH, path.join(routeDirectory, "index.html"))
}

function verifyOutput(
  manifest: VersionManifest,
  routes: Set<string>,
  indexContents: Buffer,
): void {
  const newestVersion = manifest.versions[0]
  const representativePage = "integrations/django/dmr"
  const requiredRoutes = [
    `latest/${representativePage}`,
    `${newestVersion}/${representativePage}`,
    ...TOP_LEVEL_ROUTES,
  ]

  for (const route of requiredRoutes) {
    if (!routes.has(route)) {
      throw new Error(
        `Required static route is absent from the manifest: /${route}/`,
      )
    }

    const entryPoint = path.join(DIST_DIR, route, "index.html")
    if (
      !fs.existsSync(entryPoint) ||
      !fs.readFileSync(entryPoint).equals(indexContents)
    ) {
      throw new Error(`Static route verification failed: /${route}/`)
    }
  }

  const unknownEntryPoint = path.join(
    DIST_DIR,
    "__unknown-documentation-route__",
    "index.html",
  )
  if (
    routes.has("__unknown-documentation-route__") ||
    fs.existsSync(unknownEntryPoint)
  ) {
    throw new Error("An unknown documentation route was generated")
  }

  const fallbackPath = path.join(DIST_DIR, "404.html")
  if (
    !fs.existsSync(fallbackPath) ||
    !fs.readFileSync(fallbackPath).equals(indexContents)
  ) {
    throw new Error("The GitHub Pages 404.html fallback was not generated")
  }
}

function main(): void {
  if (!fs.existsSync(INDEX_PATH)) {
    throw new Error(`Built application entry point not found: ${INDEX_PATH}`)
  }

  const manifest = readManifest()
  const routes = documentationRoutes(manifest)
  const indexContents = fs.readFileSync(INDEX_PATH)

  for (const route of routes) {
    writeEntryPoint(route)
  }
  fs.copyFileSync(INDEX_PATH, path.join(DIST_DIR, "404.html"))

  verifyOutput(manifest, routes, indexContents)
  console.log(
    `Generated and verified ${routes.size} static documentation route(s).`,
  )
}

main()
