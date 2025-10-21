# build_md_to_html_with_toc.py
import os
import markdown2
from pathlib import Path

SRC_DIR = Path(".")
BUILD_DIR = Path("build")
BUILD_DIR.mkdir(exist_ok=True)

# Markdown to HTML template
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/github-markdown-css/5.2.0/github-markdown-light.min.css">
<style>body {{max-width:900px; margin:auto; padding:2rem;}}</style>
</head>
<body class="markdown-body">
{content}
</body>
</html>
"""

for md_path in SRC_DIR.rglob("*.md"):
    if "build" in md_path.parts:
        continue
    rel_path = md_path.relative_to(SRC_DIR)
    out_path = BUILD_DIR / rel_path.with_suffix(".html")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with md_path.open("r", encoding="utf-8") as f:
        md_content = f.read()

    html_content = markdown2.markdown(md_content, extras=["toc", "fenced-code-blocks"])
    with out_path.open("w", encoding="utf-8") as f:
        f.write(HTML_TEMPLATE.format(title=md_path.stem, content=html_content))
