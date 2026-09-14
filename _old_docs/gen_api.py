from pathlib import Path

import mkdocs_gen_files


PACKAGE = "jam"
SRC = Path("src") / PACKAGE
API_DIR = Path("api")

nav = mkdocs_gen_files.Nav()

for path in sorted(SRC.rglob("*.py")):
    if "tests" in path.parts:
        continue

    module = ".".join(path.relative_to("src").with_suffix("").parts)

    if module.endswith("__init__"):
        module = module.rsplit(".", 1)[0]

    doc_path = API_DIR / f"{module}.md"

    nav[module] = doc_path.relative_to(API_DIR).as_posix()

    with mkdocs_gen_files.open(doc_path, "w") as f:
        f.write(f"# {module}\n\n")
        f.write(f"::: {module}\n")

with mkdocs_gen_files.open(API_DIR / "SUMMARY.md", "w") as f:
    f.writelines(nav.build_literate_nav())
