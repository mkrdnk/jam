import { useState, useEffect, useCallback, type ReactNode } from "react"
import { useLocation, useNavigate, useSearchParams } from "react-router-dom"
import { CodeBlock } from "./components/CodeBlock"
import { mdPages } from "./generated/pages"
import manifest from "./generated/manifest.json"
import { findPageBySlug, getAdjacentPages, getFirstPageSlug } from "./lib/nav"
import type { NavItem as MdNavItem, VersionManifest } from "./types"

// ─── TYPES ────────────────────────────────────────────────────────────────────

const MD_MANIFEST = manifest as unknown as VersionManifest
const DOC_VERSIONS: string[] = MD_MANIFEST.versions

type Theme = "light" | "dark"
type PageId = "home" | "search"

// ─── SYNTAX HIGHLIGHTING ──────────────────────────────────────────────────────

const PY_KW = new Set([
  "from","import","def","class","return","if","else","elif","for","while","with","as",
  "await","async","True","False","None","not","and","or","in","is","raise","try",
  "except","finally","pass","break","continue","yield","lambda","global","nonlocal",
  "del","assert","property","staticmethod","classmethod",
])
const PY_BUILTIN = new Set(["print","len","range","type","isinstance","hasattr","getattr","setattr","open","super"])
const PY_TYPES = new Set(["str","int","float","bool","list","dict","tuple","set","bytes","Optional","Union","List","Dict","Any","Callable","Type","Literal","ClassVar","Final","TypeVar"])

interface Token { text: string; cls: string }

function tokenizePython(code: string): Token[] {
  const tokens: Token[] = []
  let i = 0
  while (i < code.length) {
    if (code[i] === "#") {
      let j = i
      while (j < code.length && code[j] !== "\n") j++
      tokens.push({ text: code.slice(i, j), cls: "tok-cmt" })
      i = j; continue
    }
    if (code.startsWith('"""', i) || code.startsWith("'''", i)) {
      const q = code.slice(i, i + 3)
      const end = code.indexOf(q, i + 3)
      const str = end === -1 ? code.slice(i) : code.slice(i, end + 3)
      tokens.push({ text: str, cls: "tok-str" })
      i += str.length; continue
    }
    if ((code[i] === "f" || code[i] === "b" || code[i] === "r") && (code[i+1] === '"' || code[i+1] === "'")) {
      const q = code[i+1]; let j = i + 2
      while (j < code.length && code[j] !== q && code[j] !== "\n") { if (code[j] === "\\") j++; j++ }
      tokens.push({ text: code.slice(i, j + 1), cls: "tok-str" })
      i = j + 1; continue
    }
    if (code[i] === '"' || code[i] === "'") {
      const q = code[i]; let j = i + 1
      while (j < code.length && code[j] !== q && code[j] !== "\n") { if (code[j] === "\\") j++; j++ }
      tokens.push({ text: code.slice(i, j + 1), cls: "tok-str" })
      i = j + 1; continue
    }
    if (code[i] === "@") {
      let j = i + 1
      while (j < code.length && /[\w.]/.test(code[j])) j++
      tokens.push({ text: code.slice(i, j), cls: "tok-dec" })
      i = j; continue
    }
    if (/\d/.test(code[i])) {
      let j = i + 1
      while (j < code.length && /[\d._xXoObBaAfFeE]/.test(code[j])) j++
      tokens.push({ text: code.slice(i, j), cls: "tok-num" })
      i = j; continue
    }
    if (/[a-zA-Z_]/.test(code[i])) {
      let j = i + 1
      while (j < code.length && /\w/.test(code[j])) j++
      const word = code.slice(i, j)
      let k = j
      while (k < code.length && code[k] === " ") k++
      const isCall = code[k] === "("
      if (word === "self" || word === "cls") tokens.push({ text: word, cls: "tok-self" })
      else if (PY_KW.has(word)) tokens.push({ text: word, cls: "tok-kw" })
      else if (PY_TYPES.has(word)) tokens.push({ text: word, cls: "tok-type" })
      else if (PY_BUILTIN.has(word) && isCall) tokens.push({ text: word, cls: "tok-builtin" })
      else if (isCall) tokens.push({ text: word, cls: "tok-fn" })
      else if (/^[A-Z]/.test(word)) tokens.push({ text: word, cls: "tok-cls" })
      else tokens.push({ text: word, cls: "" })
      i = j; continue
    }
    if (/[=+\-*/<>!&|^~%]/.test(code[i])) {
      let j = i + 1
      while (j < code.length && /[=+\-*/<>!&|^~%]/.test(code[j])) j++
      tokens.push({ text: code.slice(i, j), cls: "tok-op" })
      i = j; continue
    }
    tokens.push({ text: code[i], cls: "" })
    i++
  }
  return tokens
}

// ─── CODE BLOCK ───────────────────────────────────────────────────────────────

// ─── ICONS ────────────────────────────────────────────────────────────────────

function SearchIcon({ size = 14 }: { size?: number }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
}
function MoonIcon() {
  return <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
}
function SunIcon() {
  return <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
}
function MenuIcon() {
  return <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
}
function CloseIcon() {
  return <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
}
function ChevronRight({ size = 11 }: { size?: number }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="9 18 15 12 9 6"/></svg>
}
function GithubIcon({ size = 15 }: { size?: number }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0 1 12 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 2.221.77 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/></svg>
}

// ─── JAM LOGO ─────────────────────────────────────────────────────────────────

function JamLogo({ size = 24 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" fill="none">
      <rect x="1.5" y="1.5" width="37" height="37" rx="9" fill="#f5e2a1" stroke="#e8c87c" strokeWidth="1.5"/>
      <rect x="6" y="5.5" width="28" height="27" rx="6.5" fill="#c13037" stroke="#960e1c" strokeWidth="1.5"/>
      <circle cx="13" cy="13" r="2" fill="#960e1c" opacity="0.75"/>
      <circle cx="21" cy="11" r="1.5" fill="#960e1c" opacity="0.65"/>
      <circle cx="27.5" cy="14" r="1.5" fill="#960e1c" opacity="0.7"/>
      <circle cx="16" cy="19" r="2.5" fill="#960e1c" opacity="0.7"/>
      <circle cx="25" cy="20" r="2" fill="#960e1c" opacity="0.65"/>
      <circle cx="11.5" cy="22.5" r="1.5" fill="#960e1c" opacity="0.6"/>
      <circle cx="21" cy="26" r="1.5" fill="#960e1c" opacity="0.55"/>
    </svg>
  )
}

// ─── VERSION SWITCHER ─────────────────────────────────────────────────────────

function VersionSwitcher({ versions, value, onChange, compact, disabled }: {
  versions: string[]
  value?: string
  onChange?: (v: string) => void
  compact?: boolean
  disabled?: boolean
}) {
  if (!versions.length) return null
  const base: React.CSSProperties = compact ? {
    fontSize: 10.5, fontWeight: 600, fontFamily: "Inter, sans-serif",
    color: "var(--accent)", cursor: !!disabled ? "default" : "pointer",
    background: "var(--accent-bg)",
    border: "1px solid color-mix(in srgb, var(--accent) 35%, transparent)",
    borderRadius: 3, padding: "1px 4px",
    letterSpacing: "0.02em",
    outline: "none", opacity: disabled ? 0.6 : 1,
  } : {
    height: 32, fontSize: 13, fontFamily: "Inter, sans-serif",
    color: "var(--text-2)", cursor: !!disabled ? "default" : "pointer",
    background: "var(--bg-subtle)", border: "1px solid var(--border)",
    borderRadius: 5, padding: "0 6px 0 9px",
    outline: "none", transition: "border-color 0.15s",
    opacity: disabled ? 0.6 : 1,
  }
  return (
    <select
      value={value}
      onChange={(e) => onChange?.(e.target.value)}
      title="Documentation version"
      disabled={disabled}
      style={base}
      onFocus={(e) => (e.currentTarget.style.borderColor = "var(--accent)")}
      onBlur={(e) => (e.currentTarget.style.borderColor = compact ? "color-mix(in srgb, var(--accent) 35%, transparent)" : "var(--border)")}
    >
      {versions.map((v) => (
        <option key={v} value={v}>{v}</option>
      ))}
    </select>
  )
}

// ─── HEADER ───────────────────────────────────────────────────────────────────

function Header({ theme, onToggleTheme, onNavigate, onSearch, sidebarOpen, onToggleSidebar, versions, docVersion, onDocVersionChange }: {
  theme: Theme
  onToggleTheme: () => void
  onNavigate: (page: PageId) => void
  onSearch: (q: string) => void
  sidebarOpen: boolean
  onToggleSidebar: () => void
  versions?: string[]
  docVersion?: string
  onDocVersionChange?: (v: string) => void
}) {
  const [q, setQ] = useState("")

  return (
    <header style={{
      position: "fixed", top: 0, left: 0, right: 0, height: 56,
      background: "var(--bg)", borderBottom: "1px solid var(--border)",
      display: "flex", alignItems: "center", padding: "0 1.25rem", gap: 12,
      zIndex: 100,
    }}>
      <button
        onClick={onToggleSidebar}
        className="mobile-menu-btn"
        style={{
          display: "none", background: "none", border: "none",
          cursor: "pointer", color: "var(--text-2)", padding: "4px",
          borderRadius: 5, flexShrink: 0,
        }}
      >
        {sidebarOpen ? <CloseIcon /> : <MenuIcon />}
      </button>

      <div style={{ display: "flex", alignItems: "center", gap: 6, flexShrink: 0 }}>
        <button
          onClick={() => onNavigate("home")}
          style={{
            display: "flex", alignItems: "center", gap: 7,
            background: "none", border: "none", cursor: "pointer", padding: 0,
          }}
        >
          <JamLogo size={26} />
          <span style={{ fontWeight: 700, fontSize: 16, color: "var(--text)", letterSpacing: "-0.025em", fontFamily: "Inter, sans-serif" }}>
            Jam
          </span>
        </button>
        <VersionSwitcher versions={versions || []} value={docVersion} onChange={onDocVersionChange} compact disabled={false} />
      </div>

      <div style={{ flex: 1, maxWidth: 380, position: "relative" }}>
        <div style={{ position: "absolute", left: 9, top: "50%", transform: "translateY(-50%)", color: "var(--text-3)", pointerEvents: "none" }}>
          <SearchIcon size={13} />
        </div>
        <input
          type="text"
          placeholder="Search docs…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && q.trim()) { onSearch(q); setQ("") } }}
          style={{
            width: "100%", height: 32,
            background: "var(--bg-subtle)", border: "1px solid var(--border)",
            borderRadius: 5, padding: "0 2.25rem 0 1.875rem",
            fontFamily: "Inter, sans-serif", fontSize: 13,
            color: "var(--text)", outline: "none",
            transition: "border-color 0.15s",
          }}
          onFocus={(e) => (e.currentTarget.style.borderColor = "var(--accent)")}
          onBlur={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
        />
        <div style={{
          position: "absolute", right: 7, top: "50%", transform: "translateY(-50%)",
          fontSize: 10, color: "var(--text-3)",
          background: "var(--bg-surface)", border: "1px solid var(--border)",
          borderRadius: 3, padding: "1px 4px",
          fontFamily: "JetBrains Mono, monospace",
        }}>
          ↵
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 6, marginLeft: "auto", flexShrink: 0 }}>
        <a
          href="https://github.com/mkrdnk/jam"
          target="_blank"
          rel="noopener noreferrer"
          style={{
            display: "flex", alignItems: "center", gap: 5,
            color: "var(--text-2)", textDecoration: "none",
            fontSize: 13, fontWeight: 500, fontFamily: "Inter, sans-serif",
            padding: "4px 9px", borderRadius: 5,
            border: "1px solid var(--border)", background: "var(--bg-subtle)",
            transition: "border-color 0.15s",
          }}
          onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--text-3)")}
          onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
        >
          <GithubIcon size={13} />
          GitHub
        </a>
        <button
          onClick={onToggleTheme}
          style={{
            background: "var(--bg-subtle)", border: "1px solid var(--border)",
            cursor: "pointer", color: "var(--text-2)",
            padding: "5px 7px", borderRadius: 5, display: "flex", alignItems: "center",
            transition: "border-color 0.15s",
          }}
          title={theme === "dark" ? "Switch to light" : "Switch to dark"}
        >
          {theme === "dark" ? <SunIcon /> : <MoonIcon />}
        </button>
      </div>
    </header>
  )
}

// ─── MD NAV (docs-content) ────────────────────────────────────────────────────

function MdNavItemView({ item, depth, active, onClick }: {
  item: MdNavItem
  depth: number
  active: string | null | undefined
  onClick: (slug: string) => void
}) {
  if (item.url) {
    return (
      <a
        href={item.url}
        target="_blank"
        rel="noopener noreferrer"
        style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          width: "100%", textAlign: "left", textDecoration: "none",
          background: "none", border: "none",
          padding: `0.28125rem calc(1rem - 2px + ${depth * 10}px)`,
          fontSize: 13, fontWeight: 400,
          color: "var(--text-2)",
          fontFamily: "Inter, sans-serif",
          lineHeight: 1.5,
          transition: "color 0.1s",
        }}
        onMouseEnter={(e) => (e.currentTarget.style.color = "var(--text)")}
        onMouseLeave={(e) => (e.currentTarget.style.color = "var(--text-2)")}
      >
        <span>{item.title}</span>
        <span style={{ fontSize: 10, color: "var(--text-3)" }}>↗</span>
      </a>
    )
  }

  if (item.slug) {
    const isActive = active === item.slug
    return (
      <button
        onClick={() => onClick(item.slug!)}
        style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          width: "100%", textAlign: "left",
          background: isActive ? "var(--nav-active-bg)" : "none",
          border: "none",
          borderLeft: `2px solid ${isActive ? "var(--nav-active)" : "transparent"}`,
          cursor: "pointer",
          padding: `0.28125rem calc(1rem - 2px + ${depth * 10}px)`,
          fontSize: 13, fontWeight: isActive ? 600 : 400,
          color: isActive ? "var(--nav-active)" : "var(--text-2)",
          fontFamily: "Inter, sans-serif",
          lineHeight: 1.5,
          transition: "color 0.1s",
        }}
        onMouseEnter={(e) => { if (!isActive) e.currentTarget.style.color = "var(--text)" }}
        onMouseLeave={(e) => { if (!isActive) e.currentTarget.style.color = "var(--text-2)" }}
      >
        <span>{item.title}</span>
      </button>
    )
  }

  return (
    <div style={{ marginBottom: "0.125rem" }}>
      <div style={{
        fontSize: 10.5, fontWeight: 700,
        letterSpacing: "0.07em", textTransform: "uppercase",
        color: "var(--text-3)", padding: `0 ${0.875 + depth * 0.5}rem`,
        marginBottom: "0.125rem", marginTop: depth > 0 ? "0.375rem" : 0,
      }}>
        {item.title}
      </div>
      {item.children?.map((child) => (
        <MdNavItemView key={child.id ?? child.title} item={child} depth={depth + 1} active={active} onClick={onClick} />
      ))}
    </div>
  )
}

// ─── SIDEBAR ──────────────────────────────────────────────────────────────────

function Sidebar({ open, onClose, mdNav, activeMdSlug, onOpenMd }: {
  open: boolean
  onClose: () => void
  mdNav: MdNavItem[]
  activeMdSlug: string | null
  onOpenMd: (slug: string) => void
}) {
  return (
    <>
      {open && (
        <div
          className="sidebar-overlay"
          onClick={onClose}
          style={{
            display: "none", position: "fixed", inset: 0,
            background: "rgba(0,0,0,0.4)", zIndex: 90,
          }}
        />
      )}
      <nav
        className={open ? "sidebar open" : "sidebar"}
        style={{
          position: "fixed", top: 56, left: 0, bottom: 0, width: 248,
          background: "var(--bg-subtle)", borderRight: "1px solid var(--border)",
          overflowY: "auto", padding: "0.875rem 0 2rem", zIndex: 95,
        }}
      >
        {mdNav.length > 0 && (
          <div style={{ marginBottom: "1.375rem" }}>
            <div style={{
              fontSize: 10.5, fontWeight: 700,
              letterSpacing: "0.07em", textTransform: "uppercase",
              color: "var(--accent)", padding: "0 1rem",
              marginBottom: "0.25rem",
            }}>
              Docs
            </div>
            {mdNav.map((item) => (
              <MdNavItemView key={item.id} item={item} depth={0} active={activeMdSlug} onClick={(slug) => { onOpenMd(slug); onClose() }} />
            ))}
          </div>
        )}
      </nav>
    </>
  )
}

// ─── BREADCRUMB ───────────────────────────────────────────────────────────────

function Breadcrumb({ crumbs, onNavigate }: { crumbs: string[]; onNavigate: (page: PageId) => void }) {
  if (!crumbs.length) return null
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 12, color: "var(--text-3)", marginBottom: "1rem" }}>
      <button
        onClick={() => onNavigate("home")}
        style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-3)", fontFamily: "Inter, sans-serif", fontSize: 12, padding: 0 }}
        onMouseEnter={(e) => (e.currentTarget.style.color = "var(--accent)")}
        onMouseLeave={(e) => (e.currentTarget.style.color = "var(--text-3)")}
      >
        Docs
      </button>
      {crumbs.map((c, i) => (
        <span key={i} style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <ChevronRight size={10} />
          <span style={{ color: i === crumbs.length - 1 ? "var(--text-2)" : "var(--text-3)" }}>{c}</span>
        </span>
      ))}
    </div>
  )
}

// ─── MD PAGE ──────────────────────────────────────────────────────────────────

function mdBreadcrumb(nav: MdNavItem[], slug: string): string[] {
  for (const item of nav) {
    if (item.slug === slug) return [item.title]
    if (!item.url && item.children) {
      const sub = mdBreadcrumb(item.children, slug)
      if (sub.length) return [item.title, ...sub]
    }
  }
  return []
}

function MdPrevNext({ prev, next, onOpenMd }: {
  prev: MdNavItem | undefined
  next: MdNavItem | undefined
  onOpenMd: (slug: string) => void
}) {
  if (!prev && !next) return null
  return (
    <div style={{
      display: "grid", gridTemplateColumns: "1fr 1fr",
      gap: 12, marginTop: "3rem", paddingTop: "1.75rem",
      borderTop: "1px solid var(--border)",
    }}>
      {prev && prev.slug ? (
        <button
          onClick={() => onOpenMd(prev.slug!)}
          style={{
            background: "none", border: "1px solid var(--border)", borderRadius: 6,
            padding: "0.75rem 1rem", cursor: "pointer", textAlign: "left",
            transition: "border-color 0.15s", fontFamily: "Inter, sans-serif",
          }}
          onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--accent)")}
          onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
        >
          <div style={{ fontSize: 11, color: "var(--text-3)", marginBottom: 3 }}>← Previous</div>
          <div style={{ fontSize: 13.5, fontWeight: 600, color: "var(--text)" }}>{prev.title}</div>
        </button>
      ) : <div />}
      {next && next.slug ? (
        <button
          onClick={() => onOpenMd(next.slug!)}
          style={{
            background: "none", border: "1px solid var(--border)", borderRadius: 6,
            padding: "0.75rem 1rem", cursor: "pointer", textAlign: "right",
            transition: "border-color 0.15s", fontFamily: "Inter, sans-serif",
          }}
          onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--accent)")}
          onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
        >
          <div style={{ fontSize: 11, color: "var(--text-3)", marginBottom: 3 }}>Next →</div>
          <div style={{ fontSize: 13.5, fontWeight: 600, color: "var(--text)" }}>{next.title}</div>
        </button>
      ) : <div />}
    </div>
  )
}

function MdPage({ version, slug, versions, onVersionChange, onOpenMd, onHome, onDocs }: {
  version: string
  slug: string
  versions: string[]
  onVersionChange: (v: string) => void
  onOpenMd: (slug: string) => void
  onHome: () => void
  onDocs: () => void
}) {
  const nav = MD_MANIFEST.docs[version]?.nav || []
  const item = findPageBySlug(nav, slug)
  const PageComp = mdPages[`${version}/${slug}`]
  if (!item || !PageComp) return <NotFoundPage onHome={onHome} onDocs={onDocs} />

  const crumbs = mdBreadcrumb(nav, slug)
  const { prev, next } = getAdjacentPages(nav, slug)

  return (
    <div style={{ maxWidth: 700, margin: "0 auto", padding: "2.25rem 2rem 4rem" }}>
      <Breadcrumb crumbs={crumbs} onNavigate={onHome} />
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: "0.875rem" }}>
        <VersionSwitcher versions={versions} value={version} onChange={onVersionChange} disabled={versions.length <= 1} />
      </div>
      <PageComp />
      <MdPrevNext prev={prev} next={next} onOpenMd={onOpenMd} />
    </div>
  )
}

// ─── HOME PAGE ────────────────────────────────────────────────────────────────

const HERO_CODE = `from jam import Jam

jam = Jam(config="jam.toml")

token = jam.issue(
    subject={"sub": 123},
    permissions=["users.read"],
    via="jwt",
)

principal = jam.authenticate(token)
jam.authorize(principal, "users.read")`

const MODULES = [
  { name: "JWT",          desc: "RS256 · ES256 · EdDSA · HS256", slug: "usage--jose--jwt" },
  { name: "PASETO",       desc: "v2.local · v2.public · v4",     slug: "usage--paseto" },
  { name: "Sessions",     desc: "Redis · Database · Memory",     slug: "usage--sessions" },
  { name: "OAuth2",       desc: "GitHub · Google · Custom",      slug: "usage--oauth2" },
  // { name: "OIDC",         desc: "Authorization code · ID tokens", slug: "usage--oauth2" },
  { name: "Authorization", desc: "RBAC · Permissions · Policies", slug: "usage--authz" },
  { name: "OTP / TOTP",   desc: "RFC 4226 · RFC 6238 · 2FA",     slug: "usage--otp" },
  { name: "KeyChain",     desc: "Rotation · FileStorage · Custom", slug: "usage--keychain" },
  { name: "SAML",         desc: "IdP · SP",                      slug: "usage--saml" },
]

const INTEGRATIONS = [
  { name: "FastAPI", slug: "framework_integrations--fastapi" },
  { name: "Starlette", slug: "framework_integrations--starlette" },
  { name: "Litestar", slug: "framework_integrations--litestar" },
  { name: "Flask", slug: "framework_integrations--flask" },
]

const FOOTER_LINKS = [
  { label: "Installation", slug: "installation" },
  { label: "Configuration", slug: "configuration" },
  { label: "Philosophy", slug: "philosophy" },
  { label: "Contributing", slug: "contributing" },
]

function HomePage({ onOpenMd }: { onOpenMd: (slug: string) => void }) {
  return (
    <div style={{ background: "var(--bg)" }}>
      {/* Header strip */}
      <div style={{
        position: "fixed", top: 0, left: 0, right: 0, height: 56,
        background: "var(--bg)", borderBottom: "1px solid var(--border)", zIndex: 50,
        display: "flex", alignItems: "center", justifyContent: "flex-end",
        padding: "0 1.5rem", gap: 8,
      }}>
        {/* handled by parent */}
      </div>

      {/* Hero */}
      <div style={{ maxWidth: 1040, margin: "0 auto", padding: "5rem 2rem 0" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 480px", gap: "4rem", alignItems: "start" }}>

          {/* Left */}
          <div>
            <div style={{
              display: "inline-flex", alignItems: "center", gap: 7,
              background: "var(--bg-subtle)", border: "1px solid var(--border)",
              borderRadius: 4, padding: "3px 10px",
              fontSize: 11.5, fontWeight: 500, color: "var(--text-3)",
              marginBottom: "1.5rem", fontFamily: "JetBrains Mono, monospace",
              letterSpacing: "0.02em",
            }}>
              <span style={{ color: "#7ec8a4" }}>◆</span>
              pip install 'jamlib[cli]'
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: "1.25rem" }}>
              <JamLogo size={44} />
              <h1 style={{
                margin: 0, fontSize: "3.25rem", fontWeight: 800,
                letterSpacing: "-0.05em", color: "var(--text)", lineHeight: 1,
                fontFamily: "Inter, sans-serif",
              }}>
                Jam
              </h1>
            </div>

            <p style={{
              fontSize: "1.0625rem", lineHeight: 1.65, color: "var(--text-2)",
              margin: "0 0 0.625rem", maxWidth: 420,
              fontFamily: "Inter, sans-serif",
            }}>
              A modular authentication and authorization framework for Python.
            </p>
            <p style={{
              fontSize: "0.9375rem", lineHeight: 1.65, color: "var(--text-3)",
              margin: "0 0 2rem", maxWidth: 400,
              fontFamily: "Inter, sans-serif",
            }}>
              Each module is independent. Use only JWT, only Sessions, or only Authorization — without importing the rest.
            </p>

            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <button
                onClick={() => onOpenMd("usage--quickstart")}
                style={{
                  background: "var(--accent)", color: "#fff",
                  border: "none", borderRadius: 5,
                  padding: "0.5625rem 1.125rem",
                  fontSize: 13.5, fontWeight: 600,
                  cursor: "pointer", fontFamily: "Inter, sans-serif",
                  transition: "background 0.15s",
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--accent-2)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "var(--accent)")}
              >
                Get Started
              </button>
              <a
                href="https://github.com/mkrdnk/jam"
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  background: "none", color: "var(--text-2)",
                  border: "1px solid var(--border)", borderRadius: 5,
                  padding: "0.5625rem 1.125rem",
                  fontSize: 13.5, fontWeight: 500,
                  cursor: "pointer", fontFamily: "Inter, sans-serif",
                  textDecoration: "none", display: "flex", alignItems: "center", gap: 6,
                  transition: "border-color 0.15s, color 0.15s",
                }}
                onMouseEnter={(e) => { e.currentTarget.style.borderColor = "var(--text-3)"; e.currentTarget.style.color = "var(--text)" }}
                onMouseLeave={(e) => { e.currentTarget.style.borderColor = "var(--border)"; e.currentTarget.style.color = "var(--text-2)" }}
              >
                <GithubIcon size={13} />
                GitHub
              </a>
            </div>
          </div>

          {/* Right: code */}
          <div>
            <CodeBlock lang="python" filename="main.py">
              {tokenizePython(HERO_CODE.trim()).map((t, i) => t.cls
                ? <span key={i} className={t.cls}>{t.text}</span>
                : t.text
              )}
            </CodeBlock>
          </div>
        </div>

        {/* Divider */}
        <div style={{ borderTop: "1px solid var(--border)", margin: "4rem 0 0" }} />
      </div>

      {/* Modules */}
      <div style={{ maxWidth: 1040, margin: "0 auto", padding: "3rem 2rem" }}>
        <div style={{ display: "grid", gridTemplateColumns: "200px 1fr", gap: "3rem", alignItems: "start" }}>
          <div>
            <h2 style={{ margin: "0 0 0.5rem", fontSize: "0.9375rem", fontWeight: 700, color: "var(--text)", letterSpacing: "-0.01em", fontFamily: "Inter, sans-serif" }}>
              Modules
            </h2>
            <p style={{ margin: 0, fontSize: "0.8125rem", color: "var(--text-3)", lineHeight: 1.6, fontFamily: "Inter, sans-serif" }}>
              Independent, composable. Use exactly what you need.
            </p>
          </div>
          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(190px, 1fr))",
            gap: "1px",
            background: "var(--border)",
            border: "1px solid var(--border)",
            borderRadius: 7,
            overflow: "hidden",
          }}>
            {MODULES.map((m) => (
              <button
                key={m.name}
                onClick={() => onOpenMd(m.slug)}
                style={{
                  background: "var(--bg)",
                  border: "none", cursor: "pointer",
                  padding: "1rem 1.125rem",
                  textAlign: "left",
                  fontFamily: "Inter, sans-serif",
                  transition: "background 0.1s",
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-subtle)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "var(--bg)")}
              >
                <div style={{ fontSize: 13.5, fontWeight: 600, color: "var(--text)", marginBottom: "0.25rem" }}>
                  {m.name}
                </div>
                <div style={{ fontSize: 11.5, color: "var(--text-3)", lineHeight: 1.4, fontFamily: "JetBrains Mono, monospace" }}>
                  {m.desc}
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Divider */}
        <div style={{ borderTop: "1px solid var(--border)", margin: "3rem 0" }} />

        {/* Integrations */}
        <div style={{ display: "grid", gridTemplateColumns: "200px 1fr", gap: "3rem", alignItems: "center" }}>
          <div>
            <h2 style={{ margin: "0 0 0.5rem", fontSize: "0.9375rem", fontWeight: 700, color: "var(--text)", letterSpacing: "-0.01em", fontFamily: "Inter, sans-serif" }}>
              Integrations
            </h2>
            <p style={{ margin: 0, fontSize: "0.8125rem", color: "var(--text-3)", lineHeight: 1.6, fontFamily: "Inter, sans-serif" }}>
              First-class framework support.
            </p>
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {INTEGRATIONS.map((it) => (
              <button
                key={it.name}
                onClick={() => onOpenMd(it.slug)}
                style={{
                  background: "var(--bg-subtle)", border: "1px solid var(--border)",
                  borderRadius: 5, padding: "0.375rem 0.75rem",
                  fontSize: 13, fontWeight: 500, color: "var(--text-2)",
                  cursor: "pointer", fontFamily: "Inter, sans-serif",
                  transition: "border-color 0.15s, color 0.15s",
                }}
                onMouseEnter={(e) => { e.currentTarget.style.borderColor = "var(--accent)"; e.currentTarget.style.color = "var(--accent)" }}
                onMouseLeave={(e) => { e.currentTarget.style.borderColor = "var(--border)"; e.currentTarget.style.color = "var(--text-2)" }}
              >
                {it.name}
              </button>
            ))}
          </div>
        </div>

        {/* Divider */}
        <div style={{ borderTop: "1px solid var(--border)", margin: "3rem 0 2rem" }} />

        {/* Footer */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
            <JamLogo size={18} />
            <span style={{ fontSize: 12, color: "var(--text-3)", fontFamily: "Inter, sans-serif" }}>
              Apache-2.0 License · Python 3.10+
            </span>
          </div>
          <div style={{ display: "flex", gap: "1.25rem" }}>
            {FOOTER_LINKS.map((l) => (
              <button
                key={l.slug}
                onClick={() => onOpenMd(l.slug)}
                style={{ background: "none", border: "none", cursor: "pointer", fontSize: 12, color: "var(--text-3)", fontFamily: "Inter, sans-serif" }}
                onMouseEnter={(e) => (e.currentTarget.style.color = "var(--text-2)")}
                onMouseLeave={(e) => (e.currentTarget.style.color = "var(--text-3)")}
              >
                {l.label}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── SEARCH PAGE ──────────────────────────────────────────────────────────────

function SearchPage({ query, version, onOpenMd }: {
  query: string
  version: string
  onOpenMd: (slug: string) => void
}) {
  const [q, setQ] = useState(query)
  const pages = MD_MANIFEST.docs[version]?.pages || []
  const results = q.trim()
    ? pages.filter((p) => p.title.toLowerCase().includes(q.trim().toLowerCase()))
    : pages

  return (
    <div style={{ maxWidth: 680, margin: "0 auto", padding: "2rem 2rem" }}>
      <div style={{ marginBottom: "1.5rem" }}>
        <div style={{ position: "relative" }}>
          <div style={{ position: "absolute", left: 11, top: "50%", transform: "translateY(-50%)", color: "var(--text-3)" }}>
            <SearchIcon size={14} />
          </div>
          <input
            autoFocus
            type="text"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search docs…"
            style={{
              width: "100%", height: 40,
              background: "var(--bg-subtle)", border: "1px solid var(--border)",
              borderRadius: 6, padding: "0 1rem 0 2.5rem",
              fontFamily: "Inter, sans-serif", fontSize: 14,
              color: "var(--text)", outline: "none", transition: "border-color 0.15s",
            }}
            onFocus={(e) => (e.currentTarget.style.borderColor = "var(--accent)")}
            onBlur={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
          />
        </div>
        {q && (
          <p style={{ fontSize: 12, color: "var(--text-3)", margin: "0.5rem 0 0", fontFamily: "Inter, sans-serif" }}>
            {results.length} result{results.length !== 1 ? "s" : ""} for "{q}"
          </p>
        )}
      </div>

      {results.length === 0 ? (
        <div style={{ padding: "3rem 0", textAlign: "center" }}>
          <div style={{ fontSize: 13.5, color: "var(--text-2)", fontWeight: 500, marginBottom: "0.25rem", fontFamily: "Inter, sans-serif" }}>No results</div>
          <div style={{ fontSize: 13, color: "var(--text-3)", fontFamily: "Inter, sans-serif" }}>Try a different search term.</div>
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {results.map((r) => (
            <button
              key={r.slug}
              onClick={() => onOpenMd(r.slug)}
              style={{
                background: "none", border: "1px solid var(--border)", borderRadius: 6,
                padding: "0.875rem 1rem", cursor: "pointer", textAlign: "left",
                transition: "border-color 0.15s", fontFamily: "Inter, sans-serif",
              }}
              onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--accent)")}
              onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
            >
              <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: "0.25rem" }}>
                <span style={{ fontWeight: 600, fontSize: 13.5, color: "var(--text)" }}>{r.title}</span>
              </div>
              <span style={{ fontSize: 11, color: "var(--text-3)" }}>{r.slug.replace(/--/g, " / ")}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── 404 PAGE ─────────────────────────────────────────────────────────────────

function NotFoundPage({ onHome, onDocs }: { onHome: () => void; onDocs: () => void }) {
  return (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center",
      justifyContent: "center", minHeight: "60vh", padding: "4rem 2rem", textAlign: "center",
    }}>
      <div style={{
        fontFamily: "JetBrains Mono, monospace",
        fontSize: "6rem", fontWeight: 700, color: "var(--border)",
        lineHeight: 1, letterSpacing: "-0.04em", marginBottom: "1.5rem",
      }}>
        404
      </div>
      <p style={{ fontSize: 15, fontWeight: 500, color: "var(--text-2)", margin: "0 0 0.375rem", fontFamily: "Inter, sans-serif" }}>
        Page not found.
      </p>
      <p style={{ fontSize: 13.5, color: "var(--text-3)", margin: "0 0 2rem", maxWidth: 320, fontFamily: "Inter, sans-serif" }}>
        This page doesn&rsquo;t exist or has been moved.
      </p>
      <div style={{ display: "flex", gap: 8 }}>
        <button
          onClick={onHome}
          style={{
            background: "var(--accent)", color: "#fff", border: "none", borderRadius: 5,
            padding: "0.5rem 1rem", fontSize: 13.5, fontWeight: 600, cursor: "pointer", fontFamily: "Inter, sans-serif",
          }}
        >
          Home
        </button>
        <button
          onClick={onDocs}
          style={{
            background: "none", color: "var(--text-2)", border: "1px solid var(--border)", borderRadius: 5,
            padding: "0.5rem 1rem", fontSize: 13.5, fontWeight: 500, cursor: "pointer", fontFamily: "Inter, sans-serif",
          }}
        >
          Documentation
        </button>
      </div>
    </div>
  )
}

// ─── ROOT APP ─────────────────────────────────────────────────────────────────

export default function App() {
  const [theme, setTheme] = useState<Theme>(() =>
    typeof window !== "undefined" && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"
  )
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [docVersion, setDocVersion] = useState<string>(DOC_VERSIONS[0] || "")
  const location = useLocation()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark")
  }, [theme])

  useEffect(() => { window.scrollTo(0, 0) }, [location.pathname, location.search])

  const pathSegments = location.pathname.split("/").filter(Boolean)
  const first = pathSegments[0] ?? ""
  const isDocRoute = DOC_VERSIONS.includes(first) && pathSegments.length >= 2
  const searchVersion = searchParams.get("version") ?? docVersion
  const effectiveVersion = isDocRoute ? first : (first === "search" ? searchVersion : docVersion)
  const mdSlug = isDocRoute ? pathSegments.slice(1).join("--") : null
  const searchQuery = searchParams.get("q") ?? ""

  let mode: "home" | "doc" | "search" | "notfound"
  if (first === "search") mode = "search"
  else if (pathSegments.length === 0) mode = "home"
  else if (isDocRoute) mode = "doc"
  else mode = "notfound"

  const openMd = useCallback((slug: string, version?: string) => {
    const v = version ?? effectiveVersion
    navigate(`/${v}/${slug.replace(/--/g, "/")}`)
    setSidebarOpen(false)
  }, [effectiveVersion, navigate])

  const goHome = useCallback(() => { navigate("/"); setSidebarOpen(false) }, [navigate])
  const goDocs = useCallback(() => {
    const firstSlug = getFirstPageSlug(MD_MANIFEST.docs[effectiveVersion]?.nav || [])
    navigate(firstSlug ? `/${effectiveVersion}/${firstSlug.replace(/--/g, "/")}` : "/")
    setSidebarOpen(false)
  }, [effectiveVersion, navigate])
  const handleSearch = useCallback((q: string) => {
    navigate(`/search?q=${encodeURIComponent(q)}&version=${encodeURIComponent(effectiveVersion)}`)
    setSidebarOpen(false)
  }, [effectiveVersion, navigate])
  const toggleTheme = useCallback(() => setTheme((t) => (t === "light" ? "dark" : "light")), [])
  const toggleSidebar = useCallback(() => setSidebarOpen((o) => !o), [])

  const changeVersion = useCallback((v: string) => {
    setSidebarOpen(false)
    if (mode === "search") {
      navigate(`/search?q=${encodeURIComponent(searchQuery)}&version=${encodeURIComponent(v)}`)
      return
    }
    if (mode === "doc") {
      const target = mdSlug && findPageBySlug(MD_MANIFEST.docs[v]?.nav || [], mdSlug)
        ? mdSlug
        : getFirstPageSlug(MD_MANIFEST.docs[v]?.nav || [])
      navigate(target ? `/${v}/${target.replace(/--/g, "/")}` : "/")
      return
    }
    setDocVersion(v)
  }, [mdSlug, mode, navigate, searchQuery])

  const sharedHeaderProps = { theme, onToggleTheme: toggleTheme, onNavigate: goHome, onSearch: handleSearch, sidebarOpen, onToggleSidebar: toggleSidebar, versions: DOC_VERSIONS, docVersion: effectiveVersion, onDocVersionChange: changeVersion }

  const mdNav = MD_MANIFEST.docs[effectiveVersion]?.nav || []

  const shell = (children: ReactNode, mainStyle: React.CSSProperties = {}) => (
    <div style={{ minHeight: "100%", background: "var(--bg)" }}>
      <Header {...sharedHeaderProps} />
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} mdNav={mdNav} activeMdSlug={mdSlug} onOpenMd={openMd} />
      <main style={{ marginLeft: 248, paddingTop: 56, ...mainStyle }}>{children}</main>
      <style>{RESPONSIVE_CSS}</style>
    </div>
  )

  if (mode === "search") {
    return shell(<SearchPage query={searchQuery} version={effectiveVersion} onOpenMd={openMd} />)
  }

  if (mode === "doc" && mdSlug) {
    return shell(
      <MdPage version={effectiveVersion} slug={mdSlug} versions={DOC_VERSIONS} onVersionChange={changeVersion} onOpenMd={openMd} onHome={goHome} onDocs={goDocs} />,
      { minHeight: "100vh" },
    )
  }

  if (mode === "notfound") {
    return shell(<NotFoundPage onHome={goHome} onDocs={goDocs} />)
  }

  return (
    <div style={{ minHeight: "100%", background: "var(--bg)" }}>
      <Header {...sharedHeaderProps} />
      <div style={{ paddingTop: 56 }}>
        <HomePage onOpenMd={openMd} />
      </div>
      <style>{RESPONSIVE_CSS}</style>
    </div>
  )
}

const RESPONSIVE_CSS = `
  @media (max-width: 1180px) {
    aside { display: none !important; }
    main { margin-right: 0 !important; }
  }
  @media (max-width: 860px) {
    .mobile-menu-btn { display: flex !important; }
    .sidebar {
      transform: translateX(-100%);
      transition: transform 0.22s cubic-bezier(0.4,0,0.2,1);
    }
    .sidebar.open { transform: translateX(0); }
    main { margin-left: 0 !important; }
    .sidebar-overlay { display: block !important; }
  }
  @media (max-width: 700px) {
    div[style*="grid-template-columns: 1fr 480px"] { grid-template-columns: 1fr !important; }
    div[style*="grid-template-columns: 200px 1fr"] { grid-template-columns: 1fr !important; gap: 1rem !important; }
    div[style*="grid-template-columns: 196px 1fr"] { grid-template-columns: 1fr !important; }
  }
`
