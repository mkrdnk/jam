import React, { Children, isValidElement, type ReactNode } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import remarkDirective from "remark-directive";
import rehypeHighlight from "rehype-highlight";
import { visit } from "unist-util-visit";
import { processMkDocsAdmonitions } from "@/lib/markdown";
import { Admonition } from "./Admonition";
import { CodeBlock } from "./CodeBlock";
import type { Plugin } from "unified";

const ADM_TYPES = new Set(["note", "tip", "warning", "danger", "deprecated", "info"]);

type DirectiveNode = {
  type: string;
  name?: string;
  data?: Record<string, unknown>;
  children?: Array<{
    type?: string;
    data?: { directiveLabel?: boolean };
    children?: Array<{ value?: string }>;
  }>;
};

const remarkAdmonitions: Plugin = () => {
  return (tree) => {
    visit(tree, (node) => {
      if (!node || typeof node !== "object") return;
      const directive = node as DirectiveNode;
      if (directive.type !== "containerDirective" && directive.type !== "textDirective") return;
      if (!directive.name || !ADM_TYPES.has(directive.name)) return;

      let label: string | null = null;
      if (directive.children) {
        const labelIdx = directive.children.findIndex((c) => c.data?.directiveLabel);
        if (labelIdx >= 0) {
          const value = directive.children[labelIdx]?.children?.[0]?.value;
          if (value) label = value;
          directive.children.splice(labelIdx, 1);
        }
      }

      directive.data = {
        hName: "admonition",
        hProperties: { type: directive.name, label: label ?? undefined },
      };
    });
  };
};

export function MarkdownRenderer({ content }: { content: string }) {
  const processed = processMkDocsAdmonitions(content);

  const components = {
    admonition: ({ type, label, children }: { type?: string; label?: string; children?: ReactNode }) => (
      <Admonition type={type} label={label}>{children}</Admonition>
    ),
    h1: ({ children }: { children?: ReactNode }) => <h1>{children}</h1>,
    h2: ({ children }: { children?: ReactNode }) => <h2>{children}</h2>,
    h3: ({ children }: { children?: ReactNode }) => <h3>{children}</h3>,
    h4: ({ children }: { children?: ReactNode }) => <h4>{children}</h4>,
    a: ({ href, children }: { href?: string; children?: ReactNode }) => (
      <a href={href} target="_blank" rel="noopener noreferrer">{children}</a>
    ),
    code({ className, children }: any) {
      return <code className={className}>{children}</code>;
    },
    pre({ children }: any) {
      let lang = "";
      let codeChildren: ReactNode = children;
      Children.forEach(children, (ch) => {
        if (isValidElement(ch)) {
          const cls = (ch.props as any).className as string | undefined;
          if (cls) {
            const m = cls.match(/language-([\w-]+)/);
            if (m) lang = m[1];
          }
          codeChildren = (ch.props as any).children;
        }
      });
      const terminal = ["shell", "bash", "zsh", "sh"].includes(lang);
      return <CodeBlock lang={lang} terminal={terminal}>{codeChildren}</CodeBlock>;
    },
    table: ({ children }: { children?: ReactNode }) => (
      <div style={{ overflowX: "auto" }}><table>{children}</table></div>
    ),
  };

  return (
    <div className="prose">
      <ReactMarkdown
        remarkPlugins={[remarkGfm, remarkDirective, remarkAdmonitions]}
        rehypePlugins={[rehypeHighlight]}
        components={components as any}
      >
        {processed}
      </ReactMarkdown>
    </div>
  );
}