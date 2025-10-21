# build_md_to_html_with_nested_toc.py
import os
from pathlib import Path
import markdown2
import shutil

# --- CONFIG ---
SOURCE_DIR = Path(".")  # Root of your repo
OUTPUT_DIR = Path("build")  # Output folder
EXCLUDE_FOLDERS = [".github", "resources"]
EXCLUDE_FILES = []  # Add any files to skip

# --- CLEAN BUILD FOLDER ---
if OUTPUT_DIR.exists():
    shutil.rmtree(OUTPUT_DIR)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# --- TREE STRUCTURE ---
toc_tree = {}

# --- WALK SOURCE DIR ---
for root, dirs, files in os.walk(SOURCE_DIR):
    dirs[:] = [d for d in dirs if d not in EXCLUDE_FOLDERS]

    for file in files:
        if file.endswith(".md") and file not in EXCLUDE_FILES:
            md_path = Path(root) / file
            rel_path = md_path.relative_to(SOURCE_DIR)
            output_path = OUTPUT_DIR / rel_path.with_suffix(".html")
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Read Markdown content
            with open(md_path, "r", encoding="utf-8") as f:
                md_text = f.read()

            # Convert to HTML
            html_body = markdown2.markdown(md_text, extras=["fenced-code-blocks", "tables"])
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{file}</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 900px; margin: auto; padding: 2rem; }}
        pre {{ background: #f4f4f4; padding: 1rem; overflow-x: auto; }}
        code {{ background: #f4f4f4; padding: 0.2rem 0.4rem; }}
        table {{ border-collapse: collapse; margin: 1rem 0; }}
        th, td {{ border: 1px solid #ccc; padding: 0.5rem; }}
        a {{ text-decoration: none; color: #0366d6; }}
    </style>
</head>
<body>
{html_body}
</body>
</html>"""

            # Write HTML
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            # Build TOC tree
            parts = rel_path.parts
            subtree = toc_tree
            for part in parts[:-1]:
                subtree = subtree.setdefault(part, {})
            subtree[parts[-1].replace(".md", ".html")] = str(rel_path.with_suffix(".html"))

# --- FUNCTION TO RENDER NESTED UL ---
def render_toc(tree):
    html = "<ul>\n"
    for key, value in sorted(tree.items()):
        if isinstance(value, dict):
            html += f"<li>{key}\n{render_toc(value)}</li>\n"
        else:
            html += f'<li><a href="{value}">{key}</a></li>\n'
    html += "</ul>\n"
    return html

toc_html = "<h1>Table of Contents</h1>\n" + render_toc(toc_tree)

# --- WRITE INDEX.HTML ---
index_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Write It UP - Table of Contents</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 900px; margin: auto; padding: 2rem; }}
        a {{ text-decoration: none; color: #0366d6; }}
        ul {{ list-style-type: none; padding-left: 1rem; }}
        li {{ margin: 0.3rem 0; }}
    </style>
</head>
<body>
{toc_html}
</body>
</html>"""

with open(OUTPUT_DIR / "index.html", "w", encoding="utf-8") as f:
    f.write(index_content)

print(f"✅ Markdown converted and nested index.html generated in '{OUTPUT_DIR}'")
