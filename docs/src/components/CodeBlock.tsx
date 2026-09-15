import React, { useRef, useState, useCallback, type ReactNode } from "react";

export function CopyIcon() {
  return <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>;
}

export function CheckIcon() {
  return <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>;
}

export function CodeBlock({ code, lang = "python", filename, children, terminal }: {
  code?: string;
  lang?: string;
  filename?: string;
  children?: ReactNode;
  terminal?: boolean;
}) {
  const preRef = useRef<HTMLPreElement>(null);
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    const text = code?.trim() || preRef.current?.innerText || preRef.current?.textContent || "";
    if (!text) return;
    try { await navigator.clipboard.writeText(text); } catch {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }, [code]);

  const preStyle: React.CSSProperties = {
    margin: 0, padding: "1rem 1.125rem",
    overflowX: "auto",
    fontFamily: "JetBrains Mono, monospace",
    fontSize: 13,
    lineHeight: 1.75,
    color: "#cdd3de",
  };

  const block: React.CSSProperties = {
    position: "relative",
    background: "#0d0d0f",
    border: "1px solid #1c1c20",
    borderRadius: 6,
    overflow: "hidden",
    margin: "1rem 0",
  };

  // ~/ так как в лендинге код без подсветки (упрощённая версия с токенайзером)
  if (filename) {
    // Style: main/py header (from landing) — file tab + copy
    return (
      <div style={block}>
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "0 1rem", height: 36,
          borderBottom: "1px solid #1c1c20", background: "#0a0a0c",
        }}>
          <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 11.5, color: "#444455", letterSpacing: "0.02em" }}>
            {filename}
          </span>
          <button onClick={handleCopy} style={{
            background: "none", border: "none", cursor: "pointer",
            color: copied ? "#7ec8a4" : "#444455",
            fontSize: 11, fontFamily: "Inter, sans-serif",
            display: "flex", alignItems: "center", gap: 4,
            padding: "3px 6px", borderRadius: 4,
            transition: "color 0.15s",
          }}>
            {copied ? <CheckIcon /> : <CopyIcon />}
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
        <pre ref={preRef} style={preStyle}>
          <code>{children ?? code?.trim()}</code>
        </pre>
      </div>
    );
  }

  if (terminal) {
    return (
      <div style={block}>
        <div style={{
          display: "flex", alignItems: "center", gap: 10,
          padding: "0 1rem", height: 36,
          borderBottom: "1px solid #1c1c20", background: "#0a0a0c",
        }}>
          <div style={{ display: "flex", gap: 6 }}>
            <i style={{ width: 10, height: 10, borderRadius: "50%", background: "#ff5f57", display: "inline-block" }} />
            <i style={{ width: 10, height: 10, borderRadius: "50%", background: "#febc2e", display: "inline-block" }} />
            <i style={{ width: 10, height: 10, borderRadius: "50%", background: "#28c840", display: "inline-block" }} />
          </div>
          <span style={{ flex: 1, fontFamily: "Inter, sans-serif", fontSize: 11, color: "#555566" }}>
            {lang === "bash" ? "bash" : lang}
          </span>
          <button onClick={handleCopy} style={{
            background: "none", border: "none", cursor: "pointer",
            color: copied ? "#7ec8a4" : "#444455",
            fontSize: 11, fontFamily: "Inter, sans-serif",
            display: "flex", alignItems: "center", gap: 4,
            padding: "3px 6px", borderRadius: 4,
            transition: "color 0.15s",
          }}>
            {copied ? <CheckIcon /> : <CopyIcon />}
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
        <pre ref={preRef} style={preStyle}>
          <code>{children ?? code?.trim()}</code>
        </pre>
      </div>
    );
  }

  // Plain block short copy (no header) — для остальных языков
  return (
    <div style={block}>
      <pre ref={preRef} style={preStyle}>
        <code>{children ?? code?.trim()}</code>
      </pre>
      <button onClick={handleCopy} title="Copy code" style={{
        position: "absolute", top: 10, right: 10,
        background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.12)",
        cursor: "pointer",
        color: copied ? "#7ec8a4" : "#888899",
        fontSize: 11, fontFamily: "Inter, sans-serif",
        display: "flex", alignItems: "center", gap: 4,
        padding: "3px 6px", borderRadius: 4,
        transition: "color 0.15s, background 0.15s",
      }}>
        {copied ? <CheckIcon /> : <CopyIcon />}
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}