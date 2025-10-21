import os
import markdown2
import shutil
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

def generate_main_toc(md_files):
    """Generate main TOC with folder structure from all Markdown files."""
    # Organize files by folder
    folders = {}
    for f in md_files:
        folder = f.parent.relative_to(SRC_DIR)
        if folder not in folders:
            folders[folder] = []
        folders[folder].append(f)
    
    toc = ["<h1>Write-Ups Index</h1>"]
    
    # Sort folders
    for folder in sorted(folders.keys()):
        if str(folder) == ".":
            folder_name = "Root"
        else:
            folder_name = str(folder).replace("\\", " / ").replace("/", " / ")
        
        toc.append(f"<h2>{folder_name}</h2>")
        toc.append("<ul>")
        
        for f in sorted(folders[folder]):
            # Use the original filename for display (cleaned up)
            name = f.stem
            
            # Create the path: folder/filename.html (preserve exact structure)
            # Convert to posix path for web URLs
            relative_path = f.relative_to(SRC_DIR).with_suffix(".html").as_posix()
            
            toc.append(f'<li><a href="{relative_path}">{name}</a></li>')
        
        toc.append("</ul>")
    
    return "\n".join(toc)

def md_to_html(md_path: Path, out_path: Path, back_to_index=True):
    """Convert a single Markdown file to HTML with styling."""
    try:
        with md_path.open("r", encoding="utf-8") as f:
            md_content = f.read()
    except UnicodeDecodeError:
        # Try with different encoding if UTF-8 fails
        with md_path.open("r", encoding="latin-1") as f:
            md_content = f.read()

    html_body = markdown2.markdown(md_content, extras=["fenced-code-blocks", "tables", "header-ids"])
    
    # Fix absolute image paths to be relative from the HTML file location
    # Calculate depth to go back to root
    depth = len(md_path.parent.relative_to(SRC_DIR).parts)
    root_prefix = "../" * depth if depth > 0 else "./"
    
    # Replace absolute paths like /resources/image.png with ../../resources/image.png
    import re
    html_body = re.sub(
        r'src="/resources/',
        f'src="{root_prefix}resources/',
        html_body
    )
    html_body = re.sub(
        r'src="/([^"]*\.(?:png|jpg|jpeg|gif|svg|webp))"',
        rf'src="{root_prefix}\1"',
        html_body,
        flags=re.IGNORECASE
    )
    
    # Calculate relative path back to index
    depth = len(md_path.parent.relative_to(SRC_DIR).parts)
    back_link = "../" * depth + "index.html" if depth > 0 else "index.html"
    
    back_nav = f'<div style="margin-bottom: 2rem;"><a href="{back_link}">← Back to Index</a></div>' if back_to_index else ""
    
    # Extract title from markdown (first # heading) or use filename
    title = md_path.stem
    lines = md_content.split('\n')
    for line in lines:
        if line.startswith('# '):
            title = line.replace('# ', '').strip()
            break
    
    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<link rel="stylesheet" href="{GITHUB_CSS}">
<style>
body {{ max-width: 900px; margin: auto; padding: 2rem; }}
a {{ color: #0969da; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
code {{ background: #f6f8fa; padding: 0.2em 0.4em; border-radius: 3px; }}
pre {{ background: #f6f8fa; padding: 1rem; border-radius: 6px; overflow-x: auto; }}
img {{ max-width: 100%; height: auto; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
th, td {{ border: 1px solid #d0d7de; padding: 0.5rem; text-align: left; }}
th {{ background: #f6f8fa; }}
</style>
</head>
<body class="markdown-body">
{back_nav}
{html_body}
</body>
</html>"""

    ensure_build_path(out_path.parent)
    with out_path.open("w", encoding="utf-8") as f:
        f.write(full_html)

def create_index_html(toc_html: str):
    """Create main index.html with full TOC."""
    index_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CTF Write-Ups Collection</title>
<link rel="stylesheet" href="{GITHUB_CSS}">
<style>
body {{ max-width: 1000px; margin: auto; padding: 2rem; }}
h1 {{ border-bottom: 2px solid #d0d7de; padding-bottom: 0.5rem; }}
h2 {{ margin-top: 2rem; color: #0969da; border-bottom: 1px solid #d0d7de; padding-bottom: 0.3rem; }}
ul {{ list-style: none; padding-left: 0; }}
li {{ padding: 0.5rem 0; border-bottom: 1px solid #f0f0f0; }}
a {{ color: #0969da; text-decoration: none; font-size: 1.1rem; }}
a:hover {{ text-decoration: underline; color: #0550ae; background: #f6f8fa; padding: 0.2rem; }}
</style>
</head>
<body class="markdown-body">
{toc_html}
<footer style="margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #d0d7de; color: #656d76; text-align: center;">
<p>CTF Write-Ups Collection | Generated with ❤️</p>
</footer>
</body>
</html>"""
    
    index_path = BUILD_DIR / "index.html"
    with index_path.open("w", encoding="utf-8") as f:
        f.write(index_html)

def main():
    # Create build directory
    ensure_build_path(BUILD_DIR)
    
    # Copy resources folder to build directory if it exists
    resources_src = SRC_DIR / "resources"
    resources_dst = BUILD_DIR / "resources"
    if resources_src.exists():
        if resources_dst.exists():
            shutil.rmtree(resources_dst)
        shutil.copytree(resources_src, resources_dst)
        print(f"✅ Copied resources folder to build directory")
    
    # Walk through the repo and find all .md files (excluding .github and build)
    md_files = []
    for root, dirs, files in os.walk(SRC_DIR):
        # Skip build folder and .github
        dirs[:] = [d for d in dirs if d not in ["build", ".github", ".git", "node_modules"]]

        for file in files:
            if file.endswith(".md") and file.lower() != "readme.md":
                md_files.append(Path(root) / file)

    if not md_files:
        print("❌ No markdown files found!")
        return

    print(f"Found {len(md_files)} Markdown files")

    # Generate main TOC
    toc_html = generate_main_toc(md_files)
    
    # Create main index.html
    create_index_html(toc_html)
    print(f"✅ Created main index.html")

    # Process each Markdown file
    for md_file in md_files:
        # Determine relative folder path inside build/
        rel_folder = md_file.parent.relative_to(SRC_DIR)
        build_folder = BUILD_DIR / rel_folder

        # Output HTML path (same structure, same filename, just .html extension)
        out_file = build_folder / f"{md_file.stem}.html"
        
        try:
            md_to_html(md_file, out_file)
            print(f"✅ Converted: {md_file.relative_to(SRC_DIR)}")
        except Exception as e:
            print(f"❌ Error converting {md_file}: {e}")

    print(f"\n✅ All Markdown files converted to HTML in '{BUILD_DIR}'")
    print(f"📁 Total files processed: {len(md_files)}")

if __name__ == "__main__":
    main()