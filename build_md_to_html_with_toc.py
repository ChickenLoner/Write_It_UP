import os
import markdown2
import shutil
import re
from pathlib import Path

SRC_DIR = Path(".")
BUILD_DIR = Path("build")
PORTFOLIO_URL = "https://chickenloner.github.io/"

# Platform detection: (keyword in folder path, accent color, emoji icon)
PLATFORMS = [
    ("cyberdefenders", "#3b82f6", "🛡️"),
    ("hackthebox",     "#a3e635", "⬡"),
    ("hacksmarter",    "#f59e0b", "⚡"),
    ("letsdefend",     "#10b981", "🔍"),
    ("security blue",  "#06b6d4", "💙"),
    ("tryhackme",      "#ef4444", "🚩"),
    ("memlabs",        "#8b5cf6", "🧠"),
    ("level effect",   "#f97316", "🏆"),
    ("unlisted",       "#a855f7", "📂"),
]

def get_platform_info(folder_str):
    fl = folder_str.lower()
    for keyword, color, icon in PLATFORMS:
        if keyword in fl:
            return color, icon
    return "#60a5fa", "📁"

def ensure_build_path(path):
    path.mkdir(parents=True, exist_ok=True)

# ─── Shared CSS ──────────────────────────────────────────────────────────────

COMMON_CSS = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:      #0f172a;
  --bg2:     #1e293b;
  --bg3:     #141f35;
  --border:  rgba(51, 65, 85, 0.8);
  --text:    #e2e8f0;
  --muted:   #94a3b8;
  --accent:  #3b82f6;
  --accent-l:#60a5fa;
  --cyan:    #06b6d4;
  --code-bg: #0d1117;
}

body {
  font-family: 'Inter', system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  line-height: 1.6;
}

a { color: var(--accent-l); text-decoration: none; }
a:hover { text-decoration: underline; color: #93c5fd; }

/* ── Nav ── */
nav {
  position: sticky; top: 0; z-index: 100;
  background: rgba(15, 23, 42, 0.85);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--border);
}
.nav-inner {
  max-width: 1100px; margin: 0 auto;
  padding: 0.75rem 2rem;
  display: flex; align-items: center; justify-content: space-between;
}
.nav-brand {
  display: flex; align-items: center; gap: 0.625rem;
  font-weight: 700; font-size: 1rem; color: var(--text);
  text-decoration: none;
}
.nav-brand:hover { text-decoration: none; color: var(--accent-l); }
.nav-avatar {
  width: 28px; height: 28px; border-radius: 50%;
  border: 2px solid rgba(96, 165, 250, 0.4);
}
.nav-links { display: flex; gap: 1.5rem; align-items: center; }
.nav-link {
  color: var(--muted); font-size: 0.875rem;
  transition: color 0.2s;
}
.nav-link:hover, .nav-link.active {
  color: var(--accent-l); text-decoration: none;
}
.nav-link.btn {
  background: rgba(59, 130, 246, 0.15);
  border: 1px solid rgba(59, 130, 246, 0.35);
  padding: 0.3rem 0.8rem; border-radius: 0.5rem;
  color: var(--accent-l);
}
.nav-link.btn:hover { background: rgba(59, 130, 246, 0.25); }

/* ── Footer ── */
footer {
  border-top: 1px solid var(--border);
  padding: 1.5rem 2rem;
  text-align: center;
  color: var(--muted);
  font-size: 0.8rem;
  margin-top: 1rem;
}
footer a { color: var(--muted); }
footer a:hover { color: var(--accent-l); text-decoration: none; }
"""

# ─── Shared HTML helpers ─────────────────────────────────────────────────────

def common_head(title, depth=0):
    return f"""<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title} · Chicken0248</title>
<link rel="icon" href="https://chickenloner.github.io/chicken0248.png" type="image/png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">"""

def common_nav(depth=0, active="write-ups"):
    root_prefix = "../" * depth if depth > 0 else "./"
    index_href = root_prefix + "index.html"
    wu_class = "nav-link active" if active == "write-ups" else "nav-link"
    return f"""<nav>
  <div class="nav-inner">
    <a href="{PORTFOLIO_URL}" class="nav-brand">
      <img src="https://chickenloner.github.io/chicken0248.png" alt="avatar" class="nav-avatar">
      Chicken0248
    </a>
    <div class="nav-links">
      <a href="{PORTFOLIO_URL}" class="nav-link">Portfolio</a>
      <a href="{index_href}" class="{wu_class}">Write-Ups</a>
      <a href="https://github.com/ChickenLoner/Write_It_UP" target="_blank" class="nav-link btn">GitHub</a>
    </div>
  </div>
</nav>"""

def common_footer(index_href=None):
    back = f'<a href="{index_href}">← All Write-Ups</a> &nbsp;·&nbsp; ' if index_href else ""
    return f"""<footer>
  {back}<a href="{PORTFOLIO_URL}">Portfolio</a>
  &nbsp;·&nbsp;
  <a href="https://github.com/ChickenLoner/Write_It_UP" target="_blank">GitHub</a>
</footer>"""

# ─── Index page ──────────────────────────────────────────────────────────────

INDEX_CSS = """
/* ── Hero ── */
.hero {
  background: linear-gradient(160deg, #0a1628 0%, #141f35 60%, #0f172a 100%);
  border-bottom: 1px solid var(--border);
  padding: 3.5rem 2rem 3rem;
  text-align: center;
  position: relative;
  overflow: hidden;
}
.hero::before {
  content: '';
  position: absolute; inset: 0;
  background-image: radial-gradient(circle at 1px 1px, rgba(96,165,250,0.07) 1px, transparent 0);
  background-size: 30px 30px;
  pointer-events: none;
}
.hero-inner { position: relative; }
.hero h1 {
  font-size: clamp(1.8rem, 5vw, 2.8rem);
  font-weight: 800;
  background: linear-gradient(135deg, #60a5fa 0%, #06b6d4 100%);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  background-clip: text;
  margin-bottom: 0.5rem;
  letter-spacing: -0.02em;
}
.hero p {
  color: var(--muted); font-size: 0.975rem;
  margin-bottom: 2.5rem;
}
.stats {
  display: flex; justify-content: center; gap: 4rem;
  margin-bottom: 2.5rem;
}
.stat { text-align: center; }
.stat-num {
  font-size: 2.25rem; font-weight: 800; display: block;
  background: linear-gradient(135deg, #60a5fa, #06b6d4);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  background-clip: text;
  line-height: 1.1;
}
.stat-label {
  font-size: 0.7rem; color: var(--muted);
  text-transform: uppercase; letter-spacing: 0.12em;
  margin-top: 0.25rem; display: block;
}

/* ── Search ── */
.search-wrap {
  max-width: 520px; margin: 0 auto;
  position: relative;
}
.search-input {
  width: 100%;
  padding: 0.75rem 1rem 0.75rem 2.875rem;
  background: rgba(30, 41, 59, 0.9);
  border: 1px solid var(--border);
  border-radius: 0.75rem;
  color: var(--text); font-size: 0.9rem;
  font-family: inherit;
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
}
.search-input::placeholder { color: var(--muted); }
.search-input:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15);
}
.search-icon {
  position: absolute; left: 1rem; top: 50%;
  transform: translateY(-50%);
  color: var(--muted); pointer-events: none;
  font-size: 0.95rem;
}

/* ── Container ── */
.container {
  max-width: 900px; margin: 0 auto;
  padding: 2rem 2rem 3rem;
}
.section-label {
  font-size: 0.7rem; font-weight: 600;
  color: var(--muted); text-transform: uppercase;
  letter-spacing: 0.12em; margin-bottom: 1rem;
}

/* ── Platform Cards ── */
.platform-card {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 0.75rem;
  margin-bottom: 0.625rem;
  overflow: hidden;
  transition: border-color 0.2s, box-shadow 0.2s;
}
.platform-card:hover {
  border-color: rgba(96, 165, 250, 0.3);
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.25);
}
.platform-card details > summary {
  list-style: none; cursor: pointer;
  padding: 0.9rem 1.25rem;
  display: flex; align-items: center; justify-content: space-between;
  border-left: 3px solid var(--c, #3b82f6);
  transition: background 0.15s;
  user-select: none;
  gap: 0.75rem;
}
.platform-card details > summary::-webkit-details-marker { display: none; }
.platform-card details > summary::marker { display: none; }
.platform-card details > summary:hover { background: rgba(255,255,255,0.03); }
.platform-card details[open] > summary {
  border-bottom: 1px solid var(--border);
}
.ph { display: flex; align-items: center; gap: 0.75rem; flex: 1; min-width: 0; }
.pico { font-size: 1.2rem; line-height: 1; flex-shrink: 0; }
.pname {
  font-weight: 600; font-size: 0.9rem; color: var(--text);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.ph-right { display: flex; align-items: center; gap: 0.625rem; flex-shrink: 0; }
.badge {
  font-size: 0.7rem; font-weight: 600; color: var(--muted);
  background: rgba(255,255,255,0.07);
  border: 1px solid var(--border);
  padding: 0.15rem 0.55rem; border-radius: 9999px;
  white-space: nowrap;
}
.chevron {
  color: var(--muted); font-size: 0.7rem;
  transition: transform 0.2s; display: inline-block;
  flex-shrink: 0;
}
.platform-card details[open] .chevron { transform: rotate(180deg); }

/* ── Write-up list ── */
.wlist {
  list-style: none; padding: 0.375rem 0;
  max-height: 420px; overflow-y: auto;
}
.wlist::-webkit-scrollbar { width: 4px; }
.wlist::-webkit-scrollbar-track { background: transparent; }
.wlist::-webkit-scrollbar-thumb { background: rgba(51,65,85,0.6); border-radius: 2px; }
.wi a {
  display: flex; align-items: center; gap: 0.625rem;
  padding: 0.45rem 1.25rem;
  color: var(--muted); font-size: 0.85rem;
  transition: background 0.12s, color 0.12s, padding-left 0.12s;
}
.wi a:hover {
  background: rgba(96, 165, 250, 0.08);
  color: var(--accent-l);
  padding-left: 1.625rem;
  text-decoration: none;
}
.wi-icon { font-size: 0.7rem; opacity: 0.35; flex-shrink: 0; }
.wi-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.wi.hidden { display: none; }
.platform-card.all-hidden { display: none; }

/* ── No results ── */
.no-results {
  text-align: center; padding: 4rem 2rem;
  color: var(--muted); display: none;
}
.no-results-icon { font-size: 3rem; margin-bottom: 1rem; }
"""

def generate_sections(md_files):
    folders = {}
    for f in md_files:
        folder = f.parent.relative_to(SRC_DIR)
        folders.setdefault(folder, []).append(f)

    sections = []
    for folder in sorted(folders.keys()):
        folder_str = str(folder)
        folder_name = "Root" if folder_str == "." else folder_str.replace(os.sep, " → ")
        color, icon = get_platform_info(folder_str)
        files = sorted(folders[folder], key=lambda x: x.stem)

        items = []
        for f in files:
            name = f.stem
            href = f.relative_to(SRC_DIR).with_suffix(".html").as_posix()
            items.append(
                f'<li class="wi" data-name="{name.lower()}">'
                f'<a href="{href}"><span class="wi-icon">◈</span>'
                f'<span class="wi-name">{name}</span></a></li>'
            )

        sections.append({
            "name": folder_name,
            "color": color,
            "icon": icon,
            "count": len(files),
            "items_html": "\n".join(items),
        })

    return sections, len(md_files)

def create_index_html(md_files):
    sections_data, total = generate_sections(md_files)
    platform_count = len(sections_data)

    cards_html = []
    for s in sections_data:
        cards_html.append(f"""<div class="platform-card">
  <details>
    <summary style="--c:{s['color']}">
      <div class="ph">
        <span class="pico">{s['icon']}</span>
        <span class="pname">{s['name']}</span>
      </div>
      <div class="ph-right">
        <span class="badge">{s['count']}</span>
        <span class="chevron">▼</span>
      </div>
    </summary>
    <ul class="wlist">
{s['items_html']}
    </ul>
  </details>
</div>""")

    cards_joined = "\n".join(cards_html)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
{common_head("Write-Ups Collection")}
<style>
{COMMON_CSS}
{INDEX_CSS}
</style>
</head>
<body>

{common_nav(0, "write-ups")}

<div class="hero">
  <div class="hero-inner">
    <h1>🔐 Write-Ups Collection</h1>
    <p>CTF challenges &amp; cybersecurity lab solutions by Chicken0248</p>

    <div class="stats">
      <div class="stat">
        <span class="stat-num">{total}</span>
        <span class="stat-label">Write-Ups</span>
      </div>
      <div class="stat">
        <span class="stat-num">{platform_count}</span>
        <span class="stat-label">Categories</span>
      </div>
    </div>

    <div class="search-wrap">
      <span class="search-icon">🔍</span>
      <input type="text" id="search" class="search-input"
             placeholder="Search write-ups..." autocomplete="off" spellcheck="false">
    </div>
  </div>
</div>

<div class="container">
  <p class="section-label">Browse by Platform</p>

{cards_joined}

  <div class="no-results" id="no-results">
    <div class="no-results-icon">🔎</div>
    <p>No write-ups match your search.</p>
  </div>
</div>

{common_footer()}

<script>
const input = document.getElementById('search');
const cards = document.querySelectorAll('.platform-card');
const noResults = document.getElementById('no-results');

input.addEventListener('input', function () {{
  const q = this.value.toLowerCase().trim();
  let anyVisible = false;

  cards.forEach(card => {{
    const items = card.querySelectorAll('.wi');
    let cardHasMatch = false;

    items.forEach(item => {{
      const show = !q || (item.dataset.name || '').includes(q);
      item.classList.toggle('hidden', !show);
      if (show) cardHasMatch = true;
    }});

    card.classList.toggle('all-hidden', !cardHasMatch);
    if (cardHasMatch) anyVisible = true;

    const details = card.querySelector('details');
    if (q && cardHasMatch) details.open = true;
    else if (!q) details.open = false;
  }});

  noResults.style.display = (anyVisible || !q) ? 'none' : 'block';
}});
</script>

</body>
</html>"""

    index_path = BUILD_DIR / "index.html"
    with index_path.open("w", encoding="utf-8") as f:
        f.write(html)
    print("✅ Created index.html")

# ─── Individual write-up pages ───────────────────────────────────────────────

ARTICLE_CSS = """
/* ── Breadcrumb ── */
.breadcrumb {
  max-width: 900px; margin: 0 auto;
  padding: 1.25rem 2rem 0;
  font-size: 0.8rem; color: var(--muted);
  display: flex; align-items: center; flex-wrap: wrap; gap: 0.25rem;
}
.breadcrumb a { color: var(--muted); }
.breadcrumb a:hover { color: var(--accent-l); text-decoration: none; }
.breadcrumb .sep { opacity: 0.4; margin: 0 0.1rem; }
.breadcrumb .current { color: var(--accent-l); }

/* ── Article wrapper ── */
.article-wrap {
  max-width: 900px; margin: 0 auto;
  padding: 1.75rem 2rem 4rem;
}

/* ── Markdown content ── */
.content { max-width: 100%; }

.content h1 {
  font-size: 2rem; font-weight: 800;
  color: var(--text); margin: 2rem 0 1rem;
  padding-bottom: 0.5rem;
  border-bottom: 2px solid var(--border);
  letter-spacing: -0.02em;
}
.content h2 {
  font-size: 1.4rem; font-weight: 700;
  color: var(--text); margin: 2rem 0 0.75rem;
  padding-bottom: 0.35rem;
  border-bottom: 1px solid var(--border);
}
.content h3 {
  font-size: 1.1rem; font-weight: 600;
  color: #93c5fd; margin: 1.5rem 0 0.5rem;
}
.content h4, .content h5, .content h6 {
  font-size: 0.95rem; font-weight: 600;
  color: var(--muted); margin: 1.25rem 0 0.4rem;
}
.content p {
  margin: 0.875rem 0; color: var(--text);
}
.content ul, .content ol {
  margin: 0.875rem 0; padding-left: 1.75rem;
}
.content li { margin: 0.3rem 0; }
.content li > ul, .content li > ol { margin: 0.2rem 0; }

.content blockquote {
  border-left: 3px solid var(--accent);
  background: rgba(59, 130, 246, 0.07);
  padding: 0.75rem 1.125rem;
  margin: 1.25rem 0;
  border-radius: 0 0.5rem 0.5rem 0;
  color: var(--muted);
}
.content blockquote p { margin: 0; color: var(--muted); }

.content code {
  font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
  font-size: 0.84em;
  background: rgba(30, 41, 59, 0.9);
  border: 1px solid var(--border);
  padding: 0.15em 0.45em;
  border-radius: 0.3rem;
  color: #a5f3fc;
}
.content pre {
  background: var(--code-bg);
  border: 1px solid var(--border);
  border-radius: 0.625rem;
  padding: 1.25rem 1.5rem;
  overflow-x: auto;
  margin: 1.25rem 0;
}
.content pre code {
  background: none; border: none;
  padding: 0; color: #e2e8f0;
  font-size: 0.875rem; line-height: 1.65;
}

.content table {
  width: 100%; border-collapse: collapse;
  margin: 1.25rem 0; font-size: 0.875rem;
  display: block; overflow-x: auto;
}
.content th {
  background: var(--bg2);
  color: var(--accent-l); font-weight: 600;
  padding: 0.625rem 0.875rem;
  border: 1px solid var(--border);
  text-align: left; white-space: nowrap;
}
.content td {
  padding: 0.5rem 0.875rem;
  border: 1px solid var(--border);
  color: var(--text); vertical-align: top;
}
.content tr:nth-child(even) td { background: rgba(30, 41, 59, 0.45); }

.content img {
  max-width: 100%; height: auto;
  border-radius: 0.5rem;
  border: 1px solid var(--border);
  display: block; margin: 1.5rem auto;
}
.content p > img:only-child { margin: 1.5rem auto; }

.content hr {
  border: none;
  border-top: 1px solid var(--border);
  margin: 2rem 0;
}
.content strong { color: #f1f5f9; font-weight: 600; }
.content em { color: #cbd5e1; }
.content del { color: var(--muted); }

.content a { color: var(--accent-l); }
.content a:hover { color: #93c5fd; }
"""

def md_to_html(md_path, out_path, back_to_index=True):
    try:
        with md_path.open("r", encoding="utf-8") as f:
            md_content = f.read()
    except UnicodeDecodeError:
        with md_path.open("r", encoding="latin-1") as f:
            md_content = f.read()

    html_body = markdown2.markdown(
        md_content,
        extras=["fenced-code-blocks", "tables", "header-ids", "strike"]
    )

    depth = len(md_path.parent.relative_to(SRC_DIR).parts)
    root_prefix = "../" * depth if depth > 0 else "./"

    # Fix image paths
    html_body = re.sub(r'src="/resources/', f'src="{root_prefix}resources/', html_body)
    html_body = re.sub(
        r'src="/([^"]*\.(?:png|jpg|jpeg|gif|svg|webp))"',
        rf'src="{root_prefix}\1"', html_body, flags=re.IGNORECASE
    )
    html_body = re.sub(r'src="(\.\./)+_resources/', f'src="{root_prefix}resources/', html_body)
    html_body = re.sub(r'src="_resources/', f'src="{root_prefix}resources/', html_body)

    index_href = root_prefix + "index.html"

    # Build breadcrumb
    parts = md_path.parent.relative_to(SRC_DIR).parts
    crumb_parts = [f'<a href="{PORTFOLIO_URL}">Portfolio</a>']
    crumb_parts.append(f'<a href="{index_href}">Write-Ups</a>')
    if parts:
        folder_label = " → ".join(parts)
        crumb_parts.append(f'<span class="current">{folder_label}</span>')

    breadcrumb_html = ' <span class="sep">/</span> '.join(crumb_parts)

    # Extract title
    title = md_path.stem
    for line in md_content.split("\n"):
        if line.startswith("# "):
            title = line[2:].strip()
            break

    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
{common_head(title, depth)}
<style>
{COMMON_CSS}
{ARTICLE_CSS}
</style>
</head>
<body>

{common_nav(depth, "write-ups")}

<div class="breadcrumb">
  {breadcrumb_html}
</div>

<div class="article-wrap">
  <article class="content">
    {html_body}
  </article>
</div>

{common_footer(index_href)}

</body>
</html>"""

    ensure_build_path(out_path.parent)
    with out_path.open("w", encoding="utf-8") as f:
        f.write(full_html)

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    ensure_build_path(BUILD_DIR)

    resources_src = SRC_DIR / "resources"
    resources_dst = BUILD_DIR / "resources"
    if resources_src.exists():
        if resources_dst.exists():
            shutil.rmtree(resources_dst)
        shutil.copytree(resources_src, resources_dst)
        print("✅ Copied resources folder")

    md_files = []
    for root, dirs, files in os.walk(SRC_DIR):
        dirs[:] = [d for d in dirs if d not in ["build", ".github", ".git", "node_modules"]]
        for file in files:
            if file.endswith(".md") and file.lower() != "readme.md":
                md_files.append(Path(root) / file)

    if not md_files:
        print("❌ No markdown files found!")
        return

    print(f"Found {len(md_files)} Markdown files")

    create_index_html(md_files)

    for md_file in md_files:
        rel_folder = md_file.parent.relative_to(SRC_DIR)
        out_file = BUILD_DIR / rel_folder / f"{md_file.stem}.html"
        try:
            md_to_html(md_file, out_file)
            print(f"✅ Converted: {md_file.relative_to(SRC_DIR)}")
        except Exception as e:
            print(f"❌ Error converting {md_file}: {e}")

    print(f"\n✅ Done! {len(md_files)} files processed")

if __name__ == "__main__":
    main()
