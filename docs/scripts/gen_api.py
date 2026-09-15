"""Generate the Markdown API reference from the package source tree."""

from __future__ import annotations

import ast
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src" / "jam"
CONTENT = ROOT / "docs" / "docs-content"


def module_name(path: Path) -> str:
    name = ".".join(path.relative_to(ROOT / "src").with_suffix("").parts)
    return name.removesuffix(".__init__")


def clean_docstring(node: ast.AST) -> str:
    return ast.get_docstring(node, clean=True) or ""


def signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    return ast.unparse(node).split(":", 1)[0]


def render_module(path: Path, module: str) -> str:
    tree = ast.parse(path.read_text())
    lines = [f"# {module}", "", f"Source: `src/{path.relative_to(ROOT / 'src')}`", ""]

    module_doc = clean_docstring(tree)
    if module_doc:
        lines.extend([module_doc, ""])

    definitions = [
        node for node in tree.body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and not node.name.startswith("_")
    ]
    for node in definitions:
        kind = "class" if isinstance(node, ast.ClassDef) else "function"
        lines.extend([f"## `{node.name}`", "", f"```python", f"{kind} {signature(node) if kind == 'function' else ast.unparse(node).split(':', 1)[0]}", "```", ""])
        doc = clean_docstring(node)
        if doc:
            lines.extend([doc, ""])
        if isinstance(node, ast.ClassDef):
            methods = [
                child for child in node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                and not child.name.startswith("_")
            ]
            for method in methods:
                lines.extend([f"### `{method.name}`", "", "```python", signature(method), "```", ""])
                method_doc = clean_docstring(method)
                if method_doc:
                    lines.extend([method_doc, ""])
    if not definitions:
        lines.extend(["This module does not expose documented public definitions.", ""])
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    versions = sorted(
        (path for path in CONTENT.iterdir() if path.is_dir() and re.fullmatch(r"v?\d+\.\d+\.\d+", path.name)),
        reverse=True,
    )
    if not versions:
        raise SystemExit("No documentation versions found")

    api_dir = versions[0] / "api"
    api_dir.mkdir(exist_ok=True)
    modules: list[tuple[str, Path]] = []
    for path in sorted(SOURCE.rglob("*.py")):
        if "__pycache__" in path.parts or "tests" in path.parts:
            continue
        modules.append((module_name(path), path))
        output = api_dir / f"{module_name(path).replace('.', '/')}.md"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_module(path, module_name(path)))

    index = ["# API reference", "", "Generated from the public definitions in `src/jam`.", ""]
    for module, path in modules:
        rendered = render_module(path, module).splitlines()
        if rendered and rendered[0].startswith("# "):
            rendered[0] = f"## {rendered[0][2:]}"
        index.extend(["", *rendered])
    (api_dir / "index.md").write_text("\n".join(index) + "\n")
    print(f"Generated {len(modules)} API modules.")


if __name__ == "__main__":
    main()
