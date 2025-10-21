import os
import markdown2
from pathlib import Path

# Source folder (repo root)
SRC_DIR = Path(".")
# Output folder
BUILD_DIR = Path("build")

# GitHub Markdown CSS
GITHUB_CSS = "https://cdnjs.cloudflare.com/ajax/libs/github-markdown-css/5.2.0/github-markdown-light.min.css"

def ensure_build_path(path: Path):
    """Ensure the build folder exists."""
    path.mkdir(parents=True, exist_ok=True)

def generate_toc(md_files):
    """Generate simple TOC from a list of Markdown files."""
    toc = ["<h2>Table of Contents</h2>", "<ul>"]
    for f in md_files:
        name = f.stem.replace("_", " ").title()
        relative = f.relative_to(SRC_DIR).with_suffix(".html")
        toc.append(f'<li><a href="{relative}">{name}</a></li>')
    toc.append("</ul>")
    return "\n".join(toc)

def md_to_html(md_path: Path, out_path: Path, toc_html=""):
    """Convert a single Markdown file to HTML with TOC and styling."""
    with md_path.open("r", encoding="utf-8") as f:
        md_content = f.read()

    html_body = markdown2.markdown(md_content, extras=["fenced-code-blocks", "tables"])
    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{md_path.stem}</title>
<link rel="stylesheet" href="{GITHUB_CSS}">
<style>
body {{ max-width: 900px; margin: auto; padding: 2rem; }}
</style>
</head>
<body class="markdown-body">
{toc_html}
{html_body}
</body>
</html>"""

    ensure_build_path(out_path.parent)
    with out_path.open("w", encoding="utf-8") as f:
        f.write(full_html)

def main():
    # Walk through the repo and find all .md files (excluding .github and build)
    md_files = []
    for root, dirs, files in os.walk(SRC_DIR):
        # Skip build folder and .github
        if "build" in dirs:
            dirs.remove("build")
        if ".github" in dirs:
            dirs.remove(".github")

        for file in files:
            if file.endswith(".md"):
                md_files.append(Path(root) / file)

    # Process each Markdown file
    for md_file in md_files:
        # Determine relative folder path inside build/
        rel_folder = md_file.parent.relative_to(SRC_DIR)
        build_folder = BUILD_DIR / rel_folder

        # Collect all Markdown in this folder for TOC
        folder_md_files = [f for f in md_files if f.parent == md_file.parent]
        toc_html = generate_toc(folder_md_files)

        # Output HTML path
        out_file = build_folder / f"{md_file.stem}.html"
        md_to_html(md_file, out_file, toc_html)

    print(f"✅ Markdown converted and nested index.html generated in '{BUILD_DIR}'")

if __name__ == "__main__":
    main()
