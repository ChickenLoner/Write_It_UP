"""
build_md_to_html_with_toc.py
─────────────────────────────────────────────────────────────────────────────
Converts every Markdown write-up in this repo into a styled SOC-themed HTML
page, plus a top-level index that groups them by platform.

Designed to drop into the existing GitHub Actions deploy:
  - Source tree (current dir):  HackTheBox/, Security Blue Team/, etc.
  - Output tree:                build/
  - Resources are copied from ./resources/ into build/resources/.

Theme:
  · Single dark "SOC operator" palette across index + write-ups
  · No nav bar / breadcrumb row — replaced with a single sticky status bar
    matching the achievements page (UPLINK · breadcrumb · sev chips · clock)
  · Index page: page-hero + stat grid + search + platform filter chips +
    collapsible platform panels rendered as card grids
  · Write-up page: platform-aware kicker, blockquote → case prompt,
    <details> → green collapsible answer, fenced code → language-labelled
    terminal block, screenshots get a soft striped fallback.
─────────────────────────────────────────────────────────────────────────────
"""

import os
import re
import shutil
import markdown2
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

SRC_DIR        = Path(".")
BUILD_DIR      = Path("build")
PORTFOLIO_URL  = "https://chicken0248.fyi/"
REPO_URL       = "https://github.com/ChickenLoner/Write_It_UP"
AVATAR_URL     = "https://chicken0248.fyi/chicken0248.png"
AUTHOR         = "Chicken0248"
KEYWORDS = ("CTF, write-up, cybersecurity, HackTheBox, TryHackMe, "
            "CyberDefenders, LetsDefend, Centri, BTLO, DFIR, "
            "blue team, digital forensics, incident response")

# ─────────────────────────────────────────────────────────────────────────────
# Platform detection
#   keyword(s) found in the folder path  →  platform descriptor
#   class:       body class & .pcard class used for the kicker / accent
#   icon:        glyph drawn in the platform icon tile
#   short:       human label used in topbar crumb + meta line
#   long:        full label used on the index panel header
#   kicker:      // <text>  rendered above the H1 on the write-up page
# ─────────────────────────────────────────────────────────────────────────────

PLATFORMS = [
    # (folder-substring tests,                       descriptor)
    (("hackthebox", "sherlock"), {
        "class": "p-htb-sherlock",
        "icon":  "⬡",
        "short": "HTB · SHERLOCK",
        "long":  "HTB Sherlocks",
        "kicker": "// HTB · SHERLOCK · DFIR CASE FILE",
        "sev":   "am",
    }),
    (("hackthebox", "machine"), {
        "class": "p-htb-machine",
        "icon":  "⬡",
        "short": "HTB · MACHINE",
        "long":  "HTB Machines",
        "kicker": "// HTB · MACHINE · OFFENSIVE",
        "sev":   "am",
    }),
    (("hackthebox",), {
        "class": "p-htb-machine",
        "icon":  "⬡",
        "short": "HTB",
        "long":  "HackTheBox",
        "kicker": "// HACKTHEBOX",
        "sev":   "am",
    }),
    (("btlo",), {
        "class": "p-btlo",
        "icon":  "⬤",
        "short": "BTLO",
        "long":  "Centri · Blue Team Labs Online",
        "kicker": "// BTLO · DFIR INVESTIGATION",
        "sev":   "rd",
    }),
    (("cyberdefenders",), {
        "class": "p-cd",
        "icon":  "◈",
        "short": "CYBERDEFENDERS",
        "long":  "CyberDefenders",
        "kicker": "// CYBERDEFENDERS · BLUE-TEAM LAB",
        "sev":   "cyan",
    }),
    (("letsdefend",), {
        "class": "p-ld",
        "icon":  "◉",
        "short": "LETSDEFEND",
        "long":  "LetsDefend",
        "kicker": "// LETSDEFEND · INVESTIGATION",
        "sev":   "green",
    }),
    (("tryhackme",), {
        "class": "p-thm",
        "icon":  "▲",
        "short": "TRYHACKME",
        "long":  "TryHackMe",
        "kicker": "// TRYHACKME · ROOM",
        "sev":   "rd",
    }),
    (("hacksmarter",), {
        "class": "p-hacksmarter",
        "icon":  "◆",
        "short": "HACKSMARTER",
        "long":  "HackSmarter.org",
        "kicker": "// HACKSMARTER",
        "sev":   "am",
    }),
    (("unlisted",), {
        "class": "p-unlisted",
        "icon":  "⬚",
        "short": "UNLISTED",
        "long":  "Unlisted Labs",
        "kicker": "// UNLISTED",
        "sev":   "vi",
    }),
]

DEFAULT_PLATFORM = {
    "class": "p-unlisted",
    "icon":  "◇",
    "short": "WRITE-UP",
    "long":  "Write-Up",
    "kicker": "// WRITE-UP",
    "sev":   "cyan",
}

def detect_platform(folder_str: str) -> dict:
    """Match folder path against keyword tuples. First match wins."""
    fl = folder_str.lower()
    for keywords, descriptor in PLATFORMS:
        if all(k in fl for k in keywords):
            return descriptor
    return DEFAULT_PLATFORM

# ─────────────────────────────────────────────────────────────────────────────
# CSS — SOC tokens + topbar (shared by index AND every write-up)
# ─────────────────────────────────────────────────────────────────────────────

TOKENS_CSS = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --soc-bg:#0d1117;     --soc-bg-1:#161b22;  --soc-bg-2:#1c2433;
  --soc-line:#253040;   --soc-line2:#374d6c;
  --soc-ink:#eef3ff;    --soc-ink2:#c4ceea;
  --soc-ink3:#8a9bbf;   --soc-ink4:#5e718a;
  --soc-cy:#22e1ff;     --soc-cy2:#06b8d9;
  --soc-am:#ffb547;     --soc-gn:#3ddc84;
  --soc-rd:#ff5577;     --soc-vi:#a78bfa;
  --kicker-text:"// WRITE-UP";
  --kicker-color:var(--soc-cy);
}
.p-htb-sherlock{--kicker-text:"// HTB · SHERLOCK · DFIR CASE FILE";--kicker-color:var(--soc-am)}
.p-htb-machine {--kicker-text:"// HTB · MACHINE · OFFENSIVE";       --kicker-color:#d97757}
.p-btlo        {--kicker-text:"// BTLO · DFIR INVESTIGATION";       --kicker-color:var(--soc-rd)}
.p-cd          {--kicker-text:"// CYBERDEFENDERS · BLUE-TEAM LAB";  --kicker-color:var(--soc-cy)}
.p-thm         {--kicker-text:"// TRYHACKME · ROOM";                --kicker-color:var(--soc-rd)}
.p-ld          {--kicker-text:"// LETSDEFEND · INVESTIGATION";      --kicker-color:var(--soc-gn)}
.p-hacksmarter {--kicker-text:"// HACKSMARTER";                     --kicker-color:var(--soc-am)}
.p-unlisted    {--kicker-text:"// UNLISTED";                        --kicker-color:var(--soc-vi)}

html,body{background:var(--soc-bg);color:var(--soc-ink);min-height:100vh}
body{
  font-family:'Inter',system-ui,-apple-system,sans-serif;
  -webkit-font-smoothing:antialiased;line-height:1.6;
  background:
    radial-gradient(1200px 600px at 100% -10%,rgba(34,225,255,.06),transparent 70%),
    radial-gradient(900px 500px at -10% 30%,rgba(167,139,250,.04),transparent 70%),
    var(--soc-bg);position:relative
}
body::before{
  content:'';position:fixed;inset:0;pointer-events:none;z-index:0;opacity:.38;
  background-image:
    linear-gradient(60deg,transparent 49.5%,rgba(34,225,255,.07) 50%,transparent 50.5%),
    linear-gradient(-60deg,transparent 49.5%,rgba(34,225,255,.07) 50%,transparent 50.5%),
    linear-gradient(0deg,transparent 49.5%,rgba(34,225,255,.04) 50%,transparent 50.5%);
  background-size:36px 62px;mask-image:radial-gradient(#000 30%,transparent 80%)
}
a{color:var(--soc-cy);text-decoration:none}
a:hover{color:#7df2ff;text-decoration:underline}
"""

TOPBAR_CSS = """
.soc-tb{position:sticky;top:0;z-index:50;background:rgba(7,11,20,.94);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);border-bottom:1px solid var(--soc-line)}
.soc-tb-row{display:flex;align-items:center;gap:14px;padding:9px 22px;font-size:12px;flex-wrap:wrap;max-width:1240px;margin:0 auto}
.soc-live{display:inline-flex;align-items:center;gap:6px;color:var(--soc-gn);font-weight:600;letter-spacing:.06em;font-family:'JetBrains Mono',monospace}
.soc-live::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--soc-gn);box-shadow:0 0 8px var(--soc-gn);animation:bp 1.6s infinite}
@keyframes bp{50%{opacity:.3}}
.soc-crumb{color:var(--soc-ink3);font-family:'JetBrains Mono',monospace;font-size:11px;display:inline-flex;align-items:center;gap:.4rem;flex-wrap:wrap}
.soc-crumb a{color:var(--soc-ink3);text-decoration:none;transition:.12s}
.soc-crumb a:hover{color:var(--soc-ink);text-decoration:none}
.soc-crumb b{color:var(--soc-ink2);font-weight:600}
.soc-crumb a b{color:var(--soc-ink2);font-weight:600}
.soc-crumb a:hover b{color:var(--soc-ink)}
.soc-crumb .here{color:var(--soc-cy);font-weight:700}
.soc-crumb .sep{color:var(--soc-ink4)}
.soc-clock{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--soc-ink3);margin-left:auto}

.sev{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:.1em;font-weight:700;text-transform:uppercase}
.sev .dot{width:6px;height:6px;border-radius:50%;background:currentcolor}
.sev.green{background:rgba(61,220,132,.12);color:var(--soc-gn);border:1px solid rgba(61,220,132,.3)}
.sev.cyan {background:rgba(34,225,255,.10);color:var(--soc-cy);border:1px solid rgba(34,225,255,.25)}
.sev.rd   {background:rgba(255,85,119,.10);color:var(--soc-rd);border:1px solid rgba(255,85,119,.3)}
.sev.am   {background:rgba(255,181,71,.10);color:var(--soc-am);border:1px solid rgba(255,181,71,.3)}
.sev.vi   {background:rgba(167,139,250,.10);color:var(--soc-vi);border:1px solid rgba(167,139,250,.3)}

.sev-link{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:4px;text-decoration:none;font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:.1em;font-weight:700;text-transform:uppercase;color:var(--soc-ink2);background:rgba(255,255,255,.02);border:1px solid var(--soc-line);transition:.15s}
.sev-link:hover{color:var(--soc-cy);border-color:rgba(34,225,255,.4);background:rgba(34,225,255,.06);text-decoration:none}
.sev-link .ar{font-size:.95em;opacity:.7;margin-left:1px}
.sev-link:hover .ar{opacity:1}
"""

# ─────────────────────────────────────────────────────────────────────────────
# CSS — Article (write-up page)
# ─────────────────────────────────────────────────────────────────────────────

ARTICLE_CSS = """
.article-wrap{max-width:900px;margin:0 auto;padding:1rem 1.5rem 3.5rem;position:relative;z-index:1}
.content{max-width:100%;font-size:15px;line-height:1.7}

/* ─── headings ─────────────────────────────────────────────── */
.content h1{
  font-size:2rem;font-weight:800;line-height:1.2;
  color:var(--soc-ink);letter-spacing:-.02em;
  margin:.75rem 0 .85rem;padding:0 0 .9rem;
  border-bottom:1px solid var(--soc-line);
  position:relative;text-wrap:balance
}
.content h1::before{
  content:var(--kicker-text);display:block;
  font-family:'JetBrains Mono',monospace;
  font-size:.7rem;font-weight:700;letter-spacing:.18em;
  color:var(--kicker-color);text-transform:uppercase;margin-bottom:.55rem
}
.content h1 a{color:inherit;border-bottom:none}
.content h1 a:hover{color:var(--soc-cy);text-decoration:none}
.content h1 a::after{
  content:"↗";display:inline-flex;align-items:center;justify-content:center;
  width:1.45em;height:1.45em;margin-left:.5em;
  border:1px solid rgba(34,225,255,.3);background:rgba(34,225,255,.06);
  border-radius:4px;color:var(--soc-cy);
  font-size:.55em;font-weight:700;vertical-align:.32em;
  font-family:'JetBrains Mono',monospace;transition:.15s
}
.content h1 a:hover::after{background:rgba(34,225,255,.15);border-color:var(--soc-cy);transform:translate(2px,-2px)}

.content h2{
  font-size:1.35rem;font-weight:700;color:var(--soc-ink);
  margin:2.4rem 0 .85rem;padding:0 0 .4rem;
  border-bottom:1px solid var(--soc-line);letter-spacing:-.01em
}
.content h2::before{
  content:"§ ";font-family:'JetBrains Mono',monospace;
  color:var(--kicker-color);font-weight:700;font-size:.95rem;opacity:.85
}
.content h3{
  font-size:1.05rem;font-weight:600;color:var(--soc-cy);
  margin:1.8rem 0 .55rem;font-family:'JetBrains Mono',monospace;letter-spacing:.02em
}
.content h3::before{content:"› ";color:var(--soc-ink4);font-weight:400}
.content h4,.content h5,.content h6{
  font-size:.9rem;font-weight:600;color:var(--soc-ink2);
  margin:1.3rem 0 .45rem;font-family:'JetBrains Mono',monospace;
  text-transform:uppercase;letter-spacing:.08em
}
.content h2[id]::after,.content h3[id]::after{
  content:" #";font-family:'JetBrains Mono',monospace;
  color:var(--soc-ink4);font-weight:400;opacity:0;margin-left:.4rem;
  font-size:.85em;transition:opacity .15s
}
.content h2:hover[id]::after,.content h3:hover[id]::after{opacity:.5}

/* ─── text & lists ─────────────────────────────────────────── */
.content p{margin:.85rem 0;color:var(--soc-ink2);text-wrap:pretty}
.content strong{color:var(--soc-ink);font-weight:600}
.content em{color:#dbe2f5}
.content del{color:var(--soc-ink4);text-decoration-color:var(--soc-ink4)}
.content ul,.content ol{margin:.9rem 0 1.1rem;padding-left:1.4rem;color:var(--soc-ink2)}
.content li{margin:.35rem 0;padding-left:.25rem}
.content ul li::marker{color:var(--soc-cy);font-size:.85em}
.content ol li::marker{color:var(--soc-cy);font-weight:700;font-family:'JetBrains Mono',monospace}

/* ─── links ────────────────────────────────────────────────── */
.content a{
  color:var(--soc-cy);
  border-bottom:1px dashed rgba(34,225,255,.35);transition:.15s
}
.content a:hover{color:#7df2ff;border-bottom-color:var(--soc-cy);text-decoration:none}

/* ─── blockquote (Q1) ...) ─────────────────────────────────── */
.content blockquote{
  margin:1.4rem 0 .9rem;padding:.85rem 1rem .85rem 1.1rem;
  background:linear-gradient(90deg,rgba(34,225,255,.06),rgba(34,225,255,.012) 70%,transparent);
  border:1px solid var(--soc-line);
  border-left:3px solid var(--soc-cy);border-radius:0 4px 4px 0
}
.content blockquote p{margin:0;color:var(--soc-ink);font-weight:500;font-size:.96rem;line-height:1.55}
.content blockquote p+p{margin-top:.45rem}
.content blockquote strong{color:#fff}
.content blockquote+blockquote{margin-top:.4rem}

/* ─── inline + block code ──────────────────────────────────── */
.content code{
  font-family:'JetBrains Mono',monospace;font-size:.85em;
  background:rgba(34,225,255,.06);
  border:1px solid rgba(34,225,255,.18);color:#a5f3fc;
  padding:.1em .42em;border-radius:3px
}
.content pre{
  background:#070b14;border:1px solid var(--soc-line);
  border-radius:5px;padding:1rem 1.15rem;margin:1.1rem 0;
  overflow-x:auto;position:relative
}
.content pre::before{
  content:"";position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,rgba(34,225,255,.25),transparent)
}
.content pre code{background:none;border:none;padding:0;color:#e2e8f0;font-size:.86rem;line-height:1.65;display:block}
.content pre code[class]:not([class=""])::before{
  content:attr(class);display:block;
  font-family:'JetBrains Mono',monospace;font-size:.62rem;
  letter-spacing:.16em;text-transform:uppercase;font-weight:700;
  color:var(--soc-ink4);margin-bottom:.65rem;padding-bottom:.55rem;
  border-bottom:1px dashed var(--soc-line)
}

/* ─── <details> answer reveal ──────────────────────────────── */
.content details{
  margin:.9rem 0 1.4rem;border:1px solid rgba(61,220,132,.3);
  border-radius:5px;overflow:hidden;
  background:linear-gradient(180deg,rgba(61,220,132,.05),rgba(61,220,132,.015));
  transition:border-color .15s
}
.content details[open]{border-color:rgba(61,220,132,.55)}
.content details summary{
  list-style:none;cursor:pointer;padding:.55rem .9rem;
  font-family:'JetBrains Mono',monospace;font-size:.72rem;
  font-weight:700;letter-spacing:.18em;text-transform:uppercase;
  color:var(--soc-gn);display:flex;align-items:center;gap:.55rem;
  user-select:none;transition:background .12s
}
.content details summary::-webkit-details-marker{display:none}
.content details summary::before{
  content:"▸";color:var(--soc-gn);font-size:.9rem;
  transition:transform .2s;display:inline-block
}
.content details[open] summary::before{transform:rotate(90deg)}
.content details summary:hover{background:rgba(61,220,132,.06)}
.content details summary::after{
  content:"";flex:1;height:1px;
  background:linear-gradient(90deg,rgba(61,220,132,.3),transparent)
}
.content details pre{
  margin:0;border:none;border-top:1px solid rgba(61,220,132,.2);
  border-radius:0;background:#070b14
}
.content details pre::before{background:linear-gradient(90deg,transparent,rgba(61,220,132,.35),transparent)}
.content details pre code{color:#d3f5e0}

/* ─── images ───────────────────────────────────────────────── */
.content img{
  display:block;max-width:100%;height:auto;margin:1.4rem auto;
  border:1px solid var(--soc-line);border-radius:5px;
  background:
    repeating-linear-gradient(-45deg,rgba(34,225,255,.04) 0 1px,transparent 1px 14px),
    linear-gradient(180deg,#101723,#0a0f18);
  min-height:140px;color:var(--soc-ink4);
  font-family:'JetBrains Mono',monospace;font-size:.72rem;
  text-align:center;font-style:italic;
  box-shadow:0 1px 0 rgba(255,255,255,.02),0 8px 24px rgba(0,0,0,.22)
}
.content img:hover{border-color:var(--soc-line2)}

/* ─── hr ───────────────────────────────────────────────────── */
.content hr{
  border:none;height:1px;margin:2.2rem 0;
  background:linear-gradient(90deg,transparent,var(--soc-line2),transparent);
  position:relative
}
.content hr::before{
  content:"⌖";position:absolute;left:50%;top:50%;
  transform:translate(-50%,-50%);background:var(--soc-bg);
  padding:0 .55rem;color:var(--soc-ink4);font-size:.7rem
}

/* ─── tables ───────────────────────────────────────────────── */
.content table{
  width:100%;border-collapse:collapse;margin:1.2rem 0;
  font-size:.86rem;display:block;overflow-x:auto;
  border:1px solid var(--soc-line);border-radius:5px
}
.content thead{background:var(--soc-bg-2)}
.content th{
  color:var(--soc-cy);text-align:left;padding:.6rem .85rem;
  border-bottom:1px solid var(--soc-line);
  font-family:'JetBrains Mono',monospace;font-size:.72rem;
  text-transform:uppercase;letter-spacing:.08em;font-weight:700;white-space:nowrap
}
.content td{padding:.5rem .85rem;border-bottom:1px solid var(--soc-line);color:var(--soc-ink2);vertical-align:top}
.content tr:last-child td{border-bottom:none}
.content tr:nth-child(even) td{background:rgba(255,255,255,.015)}

/* ─── footer ───────────────────────────────────────────────── */
footer.foot{
  border-top:1px solid var(--soc-line);
  padding:1.5rem;text-align:center;
  font-family:'JetBrains Mono',monospace;font-size:.72rem;color:var(--soc-ink4);
  margin-top:1.5rem;letter-spacing:.06em;position:relative;z-index:1
}
footer.foot a{color:var(--soc-ink3);text-decoration:none}
footer.foot a:hover{color:var(--soc-cy)}
footer.foot .sep{color:var(--soc-ink4);opacity:.5;margin:0 .55rem}

@media(max-width:640px){
  .content h1{font-size:1.55rem}
  .content h2{font-size:1.15rem}
  .article-wrap{padding:.5rem 1rem 2.5rem}
  .soc-tb-row{padding:8px 12px;gap:8px}
}
"""

# ─────────────────────────────────────────────────────────────────────────────
# CSS — Index page
# ─────────────────────────────────────────────────────────────────────────────

INDEX_CSS = """
.page{max-width:1240px;margin:0 auto;padding:24px 22px 80px;position:relative;z-index:1}

/* ─── PAGE HERO ─── */
.soc-page-hero{
  border:1px solid var(--soc-line2);border-radius:6px;overflow:hidden;margin-bottom:18px;
  background:linear-gradient(180deg,rgba(34,225,255,.04),transparent 40%),linear-gradient(180deg,var(--soc-bg-1),var(--soc-bg))
}
.soc-page-hero-strap{display:flex;align-items:center;gap:12px;padding:7px 18px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--soc-ink3);border-bottom:1px solid var(--soc-line);background:rgba(0,0,0,.25);flex-wrap:wrap}
.soc-page-hero-strap .seg b{color:var(--soc-ink2);font-weight:500}
.soc-page-hero-strap .seg .v{color:var(--soc-cy);font-weight:600}
.soc-page-hero-strap .seg .dim{color:var(--soc-ink4)}
.soc-page-hero-body{display:flex;align-items:center;gap:16px;padding:20px 22px}
.soc-page-hero-icon{
  width:48px;height:48px;border-radius:8px;display:grid;place-items:center;
  background:rgba(34,225,255,.1);border:1px solid rgba(34,225,255,.3);
  color:var(--soc-cy);font-size:22px;flex-shrink:0;font-weight:700
}
.soc-page-hero-title{font-size:24px;font-weight:800;color:var(--soc-ink);margin:0;letter-spacing:-.01em}
.soc-page-hero-sub{font-size:12.5px;color:var(--soc-ink3);font-family:'JetBrains Mono',monospace;margin:4px 0 0;letter-spacing:.02em}
.soc-stat-grid{display:grid;grid-template-columns:repeat(5,1fr);border-top:1px solid var(--soc-line)}
.soc-stat-cell{padding:14px 18px;border-right:1px solid var(--soc-line);background:rgba(255,255,255,.01)}
.soc-stat-cell:last-child{border-right:none}
.soc-stat-lbl{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--soc-ink3);letter-spacing:.14em;text-transform:uppercase;display:flex;align-items:center;gap:6px}
.soc-stat-lbl::before{content:"";width:6px;height:6px;border-radius:50%;background:var(--soc-cy)}
.soc-stat-cell.am .soc-stat-lbl::before{background:var(--soc-am)}
.soc-stat-cell.rd .soc-stat-lbl::before{background:var(--soc-rd)}
.soc-stat-cell.gn .soc-stat-lbl::before{background:var(--soc-gn)}
.soc-stat-cell.vi .soc-stat-lbl::before{background:var(--soc-vi)}
.soc-stat-val{font-size:24px;font-weight:700;letter-spacing:-.01em;margin-top:4px;font-variant-numeric:tabular-nums;color:var(--soc-ink)}
.soc-stat-val .unit{font-size:13px;color:var(--soc-ink3);font-weight:500;margin-left:3px}

/* ─── TOOLBAR ─── */
.toolbar{display:flex;align-items:center;gap:12px;margin:18px 0;flex-wrap:wrap}
.search-wrap{flex:1;min-width:260px;max-width:420px;position:relative;display:inline-flex;align-items:center}
.search-input{
  width:100%;padding:9px 14px 9px 36px;background:var(--soc-bg-1);
  border:1px solid var(--soc-line);border-radius:4px;color:var(--soc-ink);font-size:13px;
  font-family:'JetBrains Mono',monospace;outline:none;transition:.15s;letter-spacing:.02em
}
.search-input::placeholder{color:var(--soc-ink4);font-style:italic}
.search-input:focus{border-color:rgba(34,225,255,.5);box-shadow:0 0 0 3px rgba(34,225,255,.08)}
.search-icon{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--soc-ink4);pointer-events:none;font-family:'JetBrains Mono',monospace;font-size:14px}
.search-input:focus + .search-icon{color:var(--soc-cy)}
.filters{display:inline-flex;gap:6px;align-items:center;margin-left:auto;flex-wrap:wrap}
.fchip{
  display:inline-flex;align-items:center;gap:6px;padding:5px 11px;
  border:1px solid var(--soc-line);background:var(--soc-bg-1);border-radius:4px;
  font-family:'JetBrains Mono',monospace;font-size:10.5px;color:var(--soc-ink3);
  letter-spacing:.06em;font-weight:600;cursor:pointer;text-transform:uppercase;transition:.15s
}
.fchip:hover{color:var(--soc-ink2);border-color:var(--soc-line2)}
.fchip.active{color:var(--soc-cy);border-color:rgba(34,225,255,.4);background:rgba(34,225,255,.06)}
.fchip .cnt{padding:1px 6px;border-radius:3px;background:var(--soc-bg-2);color:var(--soc-ink4);font-size:9.5px}
.fchip.active .cnt{background:rgba(34,225,255,.15);color:var(--soc-cy)}
.fchip-label{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--soc-ink4);letter-spacing:.12em;text-transform:uppercase;padding:0 6px}
.tweak-toggle{
  display:inline-flex;align-items:center;gap:6px;padding:5px 11px;
  border:1px solid var(--soc-line);background:var(--soc-bg-1);border-radius:4px;
  font-family:'JetBrains Mono',monospace;font-size:10.5px;color:var(--soc-ink3);
  letter-spacing:.06em;font-weight:600;cursor:pointer;text-transform:uppercase;transition:.15s
}
.tweak-toggle:hover{color:var(--soc-cy);border-color:rgba(34,225,255,.35);background:rgba(34,225,255,.06)}
.tweak-toggle.active{color:var(--soc-cy);border-color:rgba(34,225,255,.5);background:rgba(34,225,255,.1)}

/* ─── PLATFORM PANELS ─── */
.platform-stack{display:flex;flex-direction:column;gap:12px}
.pcard{border:1px solid var(--soc-line);border-radius:6px;background:var(--soc-bg-1);overflow:hidden;transition:.15s}
.pcard[open]{border-color:rgba(34,225,255,.3)}
.pcard summary{
  list-style:none;cursor:pointer;padding:13px 18px;
  display:grid;grid-template-columns:auto 1fr auto;gap:14px;align-items:center;
  background:linear-gradient(90deg,rgba(34,225,255,.04),transparent 60%);
  transition:.12s;user-select:none
}
.pcard summary:hover{background:linear-gradient(90deg,rgba(34,225,255,.08),transparent 60%)}
.pcard[open] summary{border-bottom:1px solid var(--soc-line)}
.pcard summary::-webkit-details-marker{display:none}
.pcard .ph-icon{
  width:38px;height:38px;border-radius:6px;display:grid;place-items:center;flex-shrink:0;
  background:rgba(34,225,255,.08);border:1px solid rgba(34,225,255,.3);
  color:var(--soc-cy);font-size:18px;font-weight:700;font-family:'JetBrains Mono',monospace
}
.pcard .pname{font-size:14.5px;font-weight:700;color:var(--soc-ink);letter-spacing:-.005em}
.pcard .psub{font-family:'JetBrains Mono',monospace;font-size:10.5px;color:var(--soc-ink3);margin-top:2px;letter-spacing:.04em}
.pcard .ph-right{display:inline-flex;gap:8px;align-items:center;flex-shrink:0;flex-wrap:wrap;justify-content:flex-end}
.pcard .chev{width:24px;height:24px;display:grid;place-items:center;color:var(--soc-ink4);transition:transform .2s;font-family:'JetBrains Mono',monospace;font-size:14px}
.pcard[open] .chev{transform:rotate(180deg);color:var(--soc-cy)}

.pcard.p-htb-sherlock      .ph-icon{background:rgba(255,181,71,.08);border-color:rgba(255,181,71,.35);color:var(--soc-am)}
.pcard.p-htb-sherlock[open]{border-color:rgba(255,181,71,.35)}
.pcard.p-htb-machine       .ph-icon{background:rgba(217,119,87,.08);border-color:rgba(217,119,87,.4);color:#d97757}
.pcard.p-htb-machine[open] {border-color:rgba(217,119,87,.35)}
.pcard.p-btlo              .ph-icon{background:rgba(255,85,119,.08);border-color:rgba(255,85,119,.35);color:var(--soc-rd)}
.pcard.p-btlo[open]        {border-color:rgba(255,85,119,.35)}
.pcard.p-cd                .ph-icon{background:rgba(34,225,255,.08);border-color:rgba(34,225,255,.35);color:var(--soc-cy)}
.pcard.p-cd[open]          {border-color:rgba(34,225,255,.35)}
.pcard.p-ld                .ph-icon{background:rgba(61,220,132,.08);border-color:rgba(61,220,132,.35);color:var(--soc-gn)}
.pcard.p-ld[open]          {border-color:rgba(61,220,132,.35)}
.pcard.p-thm               .ph-icon{background:rgba(255,85,119,.08);border-color:rgba(255,85,119,.35);color:var(--soc-rd)}
.pcard.p-thm[open]         {border-color:rgba(255,85,119,.35)}
.pcard.p-hacksmarter       .ph-icon{background:rgba(255,181,71,.08);border-color:rgba(255,181,71,.35);color:var(--soc-am)}
.pcard.p-hacksmarter[open] {border-color:rgba(255,181,71,.35)}
.pcard.p-unlisted          .ph-icon{background:rgba(167,139,250,.08);border-color:rgba(167,139,250,.35);color:var(--soc-vi)}
.pcard.p-unlisted[open]    {border-color:rgba(167,139,250,.35)}

/* ─── WRITE-UP CARD GRID ─── */
.wlist{
  display:grid;grid-template-columns:repeat(auto-fill,minmax(var(--tw-card-min,260px),1fr));
  gap:10px;padding:14px;background:rgba(0,0,0,.18)
}
.wrow{
  position:relative;display:grid;grid-template-rows:auto auto;gap:6px;
  padding:12px 14px;
  background:linear-gradient(180deg,rgba(255,255,255,.025),rgba(255,255,255,.008));
  border:1px solid var(--soc-line);border-radius:5px;
  text-decoration:none;color:inherit;transition:.15s;overflow:hidden;min-height:84px
}
.wrow::before{content:"";position:absolute;top:0;left:0;bottom:0;width:2px;background:var(--soc-line2);transition:.15s}
.wrow:hover{
  background:linear-gradient(180deg,rgba(34,225,255,.07),rgba(34,225,255,.02));
  border-color:rgba(34,225,255,.3);text-decoration:none;transform:translateY(-1px);
  box-shadow:0 6px 18px rgba(0,0,0,.25)
}
.wrow:hover::before{background:var(--soc-cy);box-shadow:0 0 8px rgba(34,225,255,.5)}
.pcard.p-htb-sherlock .wrow:hover::before{background:var(--soc-am);box-shadow:0 0 8px rgba(255,181,71,.5)}
.pcard.p-htb-machine  .wrow:hover::before{background:#d97757;box-shadow:0 0 8px rgba(217,119,87,.5)}
.pcard.p-btlo         .wrow:hover::before{background:var(--soc-rd);box-shadow:0 0 8px rgba(255,85,119,.5)}
.pcard.p-cd           .wrow:hover::before{background:var(--soc-cy);box-shadow:0 0 8px rgba(34,225,255,.5)}
.pcard.p-ld           .wrow:hover::before{background:var(--soc-gn);box-shadow:0 0 8px rgba(61,220,132,.5)}
.pcard.p-thm          .wrow:hover::before{background:var(--soc-rd);box-shadow:0 0 8px rgba(255,85,119,.5)}
.pcard.p-hacksmarter  .wrow:hover::before{background:var(--soc-am);box-shadow:0 0 8px rgba(255,181,71,.5)}
.pcard.p-unlisted     .wrow:hover::before{background:var(--soc-vi);box-shadow:0 0 8px rgba(167,139,250,.5)}

.wrow .top{display:flex;align-items:center;gap:8px;font-family:'JetBrains Mono',monospace}
.wrow .ix{font-size:9.5px;font-weight:700;letter-spacing:.08em;color:var(--soc-ink4);padding:3px 7px;border:1px solid var(--soc-line);border-radius:3px;background:rgba(0,0,0,.35)}
.wrow:hover .ix{color:var(--soc-cy);border-color:rgba(34,225,255,.35);background:rgba(34,225,255,.06)}
.wrow .meta{font-size:9.5px;color:var(--soc-ink4);letter-spacing:.1em;text-transform:uppercase;display:inline-flex;align-items:center;gap:5px}
.wrow .meta .dot{width:4px;height:4px;border-radius:50%;background:var(--soc-ink4)}
.wrow .open-ic{
  margin-left:auto;font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700;
  color:var(--soc-ink4);width:22px;height:22px;border-radius:3px;display:grid;place-items:center;
  border:1px solid var(--soc-line);background:rgba(0,0,0,.2);transition:.15s
}
.wrow:hover .open-ic{color:var(--soc-cy);border-color:var(--soc-cy);background:rgba(34,225,255,.1);transform:translate(2px,-2px)}
.wrow .nm{
  font-size:13.5px;font-weight:600;color:var(--soc-ink);line-height:1.35;
  display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;
  overflow:hidden;text-overflow:ellipsis;letter-spacing:-.005em
}
.wrow:hover .nm{color:#fff}
.wrow.hidden,.pcard.all-hidden{display:none}

/* ─── No results ─── */
.no-results{text-align:center;padding:3rem 1rem;color:var(--soc-ink4);font-family:'JetBrains Mono',monospace;display:none;border:1px dashed var(--soc-line);border-radius:6px;margin-top:14px}
.no-results.show{display:block}
.no-results .glyph{font-size:36px;margin-bottom:.6rem;opacity:.5}
.no-results .lbl{font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--soc-ink3)}
.no-results .lbl .q{color:var(--soc-cy)}

/* ─── Index footer ─── */
.foot{margin-top:34px;padding:18px 4px;border-top:1px solid var(--soc-line);display:flex;justify-content:space-between;align-items:center;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--soc-ink4);flex-wrap:wrap;gap:10px}
.foot a{color:var(--soc-ink3);text-decoration:none}
.foot a:hover{color:var(--soc-cy)}
.foot .right{display:inline-flex;gap:16px;align-items:center}

/* ─── TWEAKABLE VARIANTS ─── */
body.tw-hide-meta  .wrow .meta{display:none}
body.tw-hide-index .wrow .ix{display:none}
body.tw-hide-index.tw-hide-meta .wrow .top{justify-content:flex-end}
body.tw-compact .wlist{grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:4px;padding:8px}
body.tw-compact .wrow{grid-template-rows:none;grid-template-columns:auto 1fr auto;align-items:center;gap:10px;padding:8px 12px;min-height:0}
body.tw-compact .wrow .top{display:contents}
body.tw-compact .wrow .meta{display:none}
body.tw-compact .wrow .nm{font-size:12.5px;font-weight:500;color:var(--soc-ink2);-webkit-line-clamp:1;line-clamp:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
body.tw-compact .wrow:hover .nm{color:var(--soc-ink)}
body.tw-compact .wrow .open-ic{margin-left:0;width:20px;height:20px;font-size:10px}
body.tw-accent-bold .wrow::before{background:var(--soc-line2);width:3px}
body.tw-accent-bold .pcard.p-htb-sherlock .wrow::before{background:rgba(255,181,71,.5)}
body.tw-accent-bold .pcard.p-htb-machine  .wrow::before{background:rgba(217,119,87,.5)}
body.tw-accent-bold .pcard.p-btlo         .wrow::before{background:rgba(255,85,119,.5)}
body.tw-accent-bold .pcard.p-cd           .wrow::before{background:rgba(34,225,255,.5)}
body.tw-accent-bold .pcard.p-ld           .wrow::before{background:rgba(61,220,132,.5)}
body.tw-accent-bold .pcard.p-thm          .wrow::before{background:rgba(255,85,119,.5)}
body.tw-accent-bold .pcard.p-hacksmarter  .wrow::before{background:rgba(255,181,71,.5)}
body.tw-accent-bold .pcard.p-unlisted     .wrow::before{background:rgba(167,139,250,.5)}

/* ─── TWEAKS PANEL ─── */
#tw-panel{
  position:fixed;bottom:18px;right:18px;z-index:200;width:280px;
  background:var(--soc-bg-1);border:1px solid var(--soc-line2);border-radius:6px;
  box-shadow:0 18px 50px rgba(0,0,0,.55),0 0 0 1px rgba(34,225,255,.06);
  font-family:'Inter',system-ui,sans-serif;display:none;flex-direction:column;
  max-height:calc(100vh - 36px);overflow:hidden
}
#tw-panel.show{display:flex;animation:tw-in .2s ease}
@keyframes tw-in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
#tw-panel header{
  display:flex;align-items:center;gap:8px;padding:10px 14px;
  border-bottom:1px solid var(--soc-line);
  background:linear-gradient(90deg,rgba(34,225,255,.06),transparent 70%);
  font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700;
  letter-spacing:.16em;text-transform:uppercase;color:var(--soc-cy)
}
#tw-panel header .dot{width:7px;height:7px;border-radius:50%;background:var(--soc-cy);box-shadow:0 0 6px var(--soc-cy)}
#tw-panel header .close{margin-left:auto;background:transparent;border:1px solid var(--soc-line);color:var(--soc-ink3);width:22px;height:22px;border-radius:3px;cursor:pointer;font-size:13px;display:grid;place-items:center;font-family:inherit;transition:.12s}
#tw-panel header .close:hover{color:var(--soc-rd);border-color:rgba(255,85,119,.4);background:rgba(255,85,119,.06)}
#tw-panel .body{padding:6px 0;overflow-y:auto}
#tw-panel .body::-webkit-scrollbar{width:4px}
#tw-panel .body::-webkit-scrollbar-thumb{background:var(--soc-line2);border-radius:2px}
.tw-row{padding:10px 14px;border-bottom:1px dashed var(--soc-line);display:flex;flex-direction:column;gap:8px}
.tw-row:last-child{border-bottom:none}
.tw-row .lbl{font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--soc-ink3);font-weight:700;display:flex;align-items:center;justify-content:space-between;gap:8px}
.tw-row .lbl .val{color:var(--soc-cy);font-weight:600;letter-spacing:.04em;text-transform:none}
.tw-seg{display:inline-flex;background:rgba(0,0,0,.3);border:1px solid var(--soc-line);border-radius:4px;padding:2px}
.tw-seg button{flex:1;padding:5px 10px;background:transparent;border:none;border-radius:3px;font-family:'JetBrains Mono',monospace;font-size:10.5px;font-weight:600;letter-spacing:.06em;color:var(--soc-ink3);cursor:pointer;transition:.12s;text-transform:uppercase}
.tw-seg button:hover{color:var(--soc-ink2)}
.tw-seg button.active{background:rgba(34,225,255,.12);color:var(--soc-cy);box-shadow:inset 0 0 0 1px rgba(34,225,255,.25)}
.tw-toggle{display:inline-flex;align-items:center;gap:0;width:42px;height:22px;background:rgba(0,0,0,.4);border:1px solid var(--soc-line);border-radius:99px;cursor:pointer;position:relative;transition:.15s}
.tw-toggle::after{content:"";position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:var(--soc-ink4);transition:.18s}
.tw-toggle[aria-checked="true"]{background:rgba(34,225,255,.15);border-color:rgba(34,225,255,.4)}
.tw-toggle[aria-checked="true"]::after{left:22px;background:var(--soc-cy);box-shadow:0 0 6px rgba(34,225,255,.6)}
.tw-slider{-webkit-appearance:none;width:100%;background:transparent;height:18px;cursor:pointer}
.tw-slider::-webkit-slider-runnable-track{height:4px;background:linear-gradient(90deg,var(--soc-cy) 0 var(--tw-fill,50%),var(--soc-line) var(--tw-fill,50%) 100%);border-radius:99px}
.tw-slider::-moz-range-track{height:4px;background:var(--soc-line);border-radius:99px}
.tw-slider::-moz-range-progress{height:4px;background:var(--soc-cy);border-radius:99px}
.tw-slider::-webkit-slider-thumb{-webkit-appearance:none;width:14px;height:14px;border-radius:50%;background:var(--soc-cy);box-shadow:0 0 6px rgba(34,225,255,.5);margin-top:-5px;cursor:grab}
.tw-slider::-moz-range-thumb{width:14px;height:14px;border-radius:50%;background:var(--soc-cy);border:none;box-shadow:0 0 6px rgba(34,225,255,.5);cursor:grab}
.tw-foot{padding:10px 14px;border-top:1px solid var(--soc-line);background:rgba(0,0,0,.2);display:flex;justify-content:space-between;align-items:center;font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:.1em;color:var(--soc-ink4);text-transform:uppercase}
.tw-reset{padding:5px 10px;border:1px solid var(--soc-line);background:rgba(0,0,0,.3);color:var(--soc-ink3);border-radius:3px;cursor:pointer;font-family:inherit;font-size:10px;letter-spacing:.1em;font-weight:700;text-transform:uppercase;transition:.12s}
.tw-reset:hover{color:var(--soc-rd);border-color:rgba(255,85,119,.4);background:rgba(255,85,119,.06)}

@media(max-width:820px){
  .soc-stat-grid{grid-template-columns:repeat(2,1fr)}
  .soc-stat-cell{border-right:none;border-bottom:1px solid var(--soc-line)}
  .pcard .ph-right{display:none}
  .wlist{grid-template-columns:1fr;padding:10px;gap:8px}
  .wrow{min-height:auto}
  .toolbar{flex-direction:column;align-items:stretch}
  .filters{margin-left:0}
  .search-wrap{max-width:none}
  #tw-panel{left:12px;right:12px;width:auto;bottom:12px}
}
"""

# ─────────────────────────────────────────────────────────────────────────────
# Shared HTML pieces
# ─────────────────────────────────────────────────────────────────────────────

def common_head(title: str, description: str = "") -> str:
    full_title = f"{title} · {AUTHOR}"
    og_image = f"{PORTFOLIO_URL.rstrip('/')}/chicken0248.png"
    return f"""<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="{description}">
<meta name="keywords" content="{KEYWORDS}">
<meta name="author" content="{AUTHOR}">
<meta property="og:type" content="website">
<meta property="og:title" content="{full_title}">
<meta property="og:description" content="{description}">
<meta property="og:image" content="{og_image}">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="{full_title}">
<meta name="twitter:description" content="{description}">
<title>{full_title}</title>
<link rel="icon" href="{AVATAR_URL}" type="image/png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">"""


def topbar(crumb_html: str, badges_html: str, clock_label: str = "") -> str:
    clock = f'<span class="soc-clock">{clock_label}</span>' if clock_label else ""
    return f"""<div class="soc-tb">
  <div class="soc-tb-row">
    <span class="soc-live">UPLINK</span>
    <span class="soc-crumb">
      {crumb_html}
    </span>
    {badges_html}
    {clock}
  </div>
</div>"""


def article_footer(index_href: str) -> str:
    return f"""<footer class="foot">
  <a href="{index_href}">← All Write-Ups</a>
  <span class="sep">·</span>
  <a href="{PORTFOLIO_URL}">Portfolio ↗</a>
  <span class="sep">·</span>
  <a href="{REPO_URL}" target="_blank">GitHub ↗</a>
</footer>"""

# ─────────────────────────────────────────────────────────────────────────────
# Write-up page generation
# ─────────────────────────────────────────────────────────────────────────────

def ensure_build_path(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def rewrite_image_paths(html_body: str, root_prefix: str) -> str:
    """The MD files use various /resources/ schemes — normalize them all."""
    html_body = re.sub(r'src="/resources/', f'src="{root_prefix}resources/', html_body)
    html_body = re.sub(
        r'src="/([^"]*\.(?:png|jpg|jpeg|gif|svg|webp))"',
        rf'src="{root_prefix}\1"', html_body, flags=re.IGNORECASE
    )
    html_body = re.sub(r'src="(\.\./)+_resources/', f'src="{root_prefix}resources/', html_body)
    html_body = re.sub(r'src="_resources/', f'src="{root_prefix}resources/', html_body)
    return html_body


def md_to_html(md_path: Path, out_path: Path):
    """Render one markdown write-up to a styled HTML file."""
    # 1. Read markdown
    try:
        md_content = md_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        md_content = md_path.read_text(encoding="latin-1")

    # 2. Convert to HTML body
    html_body = markdown2.markdown(
        md_content,
        extras=["fenced-code-blocks", "tables", "header-ids", "strike"]
    )

    # 3. Path fix-ups
    parts = md_path.parent.relative_to(SRC_DIR).parts
    depth = len(parts)
    root_prefix = "../" * depth if depth > 0 else "./"
    html_body = rewrite_image_paths(html_body, root_prefix)

    index_href = root_prefix + "index.html"

    # 4. Title from first H1 in markdown
    title = _strip_platform_prefix(md_path.stem)
    for line in md_content.splitlines():
        if line.startswith("# "):
            title = line[2:].strip()
            # strip a leading link e.g. "[Foo](url)"
            link_match = re.match(r"\[([^\]]+)\]\([^)]+\)\s*$", title)
            if link_match:
                title = link_match.group(1)
            # strip [Platform Write-up] prefix if present in H1
            title = _strip_platform_prefix(title)
            break

    # 5. Detect platform from folder
    folder_str = "/".join(parts)
    plat = detect_platform(folder_str)

    # 6. Build topbar crumb
    crumb_parts = [f'<a href="{PORTFOLIO_URL}">SOC</a>',
                   '<span class="sep">/</span>',
                   f'<a href="{index_href}"><b>WRITE-UPS</b></a>',
                   '<span class="sep">/</span>',
                   f'<b>{plat["short"]}</b>',
                   '<span class="sep">/</span>',
                   f'<b class="here">{_escape_attr(title).upper()}</b>']
    crumb_html = " ".join(crumb_parts)

    badges_html = (
        f'<span class="sev cyan"><span class="dot"></span>TLP:CLEAR</span> '
        f'<span class="sev {plat["sev"]}"><span class="dot"></span>{plat["short"]}</span> '
        f'<span class="sev green"><span class="dot"></span>SOLVED</span> '
        f'<a class="sev-link" href="{REPO_URL}" target="_blank">GITHUB <span class="ar">↗</span></a>'
    )

    today = datetime.utcnow().strftime("%Y-%m-%d")
    clock_label = f"CASE · {today}"

    description = f"Write-up for {title} — a {plat['long']} challenge solution by {AUTHOR}."

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
{common_head(title, description=description)}
<style>{TOKENS_CSS}{TOPBAR_CSS}{ARTICLE_CSS}</style>
</head>
<body class="{plat['class']}">

{topbar(crumb_html, badges_html, clock_label)}

<div class="article-wrap">
  <article class="content">
{html_body}
  </article>
</div>

{article_footer(index_href)}

</body>
</html>
"""

    ensure_build_path(out_path.parent)
    out_path.write_text(page, encoding="utf-8")


def _escape_attr(s: str) -> str:
    return s.replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')


def _strip_platform_prefix(name: str) -> str:
    """Remove leading [Platform Write-up] bracket from display names."""
    return re.sub(r'^\[[^\]]*\]\s*', '', name)

# ─────────────────────────────────────────────────────────────────────────────
# Index page generation
# ─────────────────────────────────────────────────────────────────────────────

def _platform_group_key(md_path: Path) -> str:
    """Two markdown files belong in the same panel iff this key matches.
       We use the full folder relative path so 'HTB Sherlocks' and
       'HTB Machines' (which share parent 'HackTheBox') stay separate."""
    return str(md_path.parent.relative_to(SRC_DIR)).replace("\\", "/")


def _panel_breadcrumb(folder_str: str) -> str:
    if folder_str in (".", ""):
        return "Root"
    return folder_str.replace("/", " → ")


def _panel_html(group_folder: str, md_files: list) -> str:
    plat = detect_platform(group_folder)
    klass = plat["class"]
    icon = plat["icon"]
    long_name = plat["long"]
    short_label = plat["short"]
    sev_class = plat["sev"]

    breadcrumb = _panel_breadcrumb(group_folder)
    count = len(md_files)

    rows_html = []
    for i, md_path in enumerate(sorted(md_files, key=lambda p: p.stem), start=1):
        name = _strip_platform_prefix(md_path.stem)
        href = str(md_path.relative_to(SRC_DIR).with_suffix(".html")).replace("\\", "/")
        # encode spaces and # in href so browsers don't choke
        href_safe = href.replace(" ", "%20").replace("#", "%23").replace("[", "%5B").replace("]", "%5D")
        rows_html.append(f"""
        <a class="wrow" href="{href_safe}" data-name="{name.lower()}">
          <div class="top">
            <span class="ix">#{i:03d}</span>
            <span class="meta"><span class="dot"></span>{short_label}</span>
            <span class="open-ic">↗</span>
          </div>
          <div class="nm">{name}</div>
        </a>""")

    return f"""<details class="pcard {klass}" data-platform="{klass}">
  <summary>
    <div class="ph-icon">{icon}</div>
    <div>
      <div class="pname">{long_name}</div>
      <div class="psub">{breadcrumb}</div>
    </div>
    <div class="ph-right">
      <span class="sev {sev_class}"><span class="dot"></span>{short_label} · {count}</span>
      <span class="chev">▾</span>
    </div>
  </summary>
  <div class="wlist">{''.join(rows_html)}
  </div>
</details>"""


def create_index_html(md_files: list):
    # group by folder
    groups: dict[str, list] = {}
    for f in md_files:
        groups.setdefault(_platform_group_key(f), []).append(f)

    # ── per-platform-class counts (aggregated across folders with same class)
    class_counts: dict[str, int] = {}
    class_label: dict[str, str] = {}     # human label for filter chip
    for folder, files in groups.items():
        plat = detect_platform(folder)
        c = plat["class"]
        class_counts[c] = class_counts.get(c, 0) + len(files)
        class_label.setdefault(c, plat["long"])

    total = len(md_files)
    platform_count = len(class_counts)

    # ── filter chips (only for platforms that actually exist, sorted by count desc)
    chips = ['<button class="fchip active" data-filter="all">All <span class="cnt">' + str(total) + '</span></button>']
    for c, n in sorted(class_counts.items(), key=lambda kv: -kv[1]):
        chips.append(f'<button class="fchip" data-filter="{c}">{class_label[c]} <span class="cnt">{n}</span></button>')
    chips_html = "\n      ".join(chips)

    # ── stat grid (Total + top 3 biggest platforms + platform count) = 5 cells
    sorted_classes = sorted(class_counts.items(), key=lambda kv: -kv[1])
    accent_for = {
        "p-htb-sherlock":"am", "p-htb-machine":"am",
        "p-btlo":"rd", "p-cd":"cyan", "p-ld":"gn",
        "p-thm":"rd", "p-hacksmarter":"am", "p-unlisted":"vi",
    }
    stat_cells = [f"""
      <div class="soc-stat-cell">
        <div class="soc-stat-lbl">Total write-ups</div>
        <div class="soc-stat-val">{total}<span class="unit">entries</span></div>
      </div>"""]
    for c, n in sorted_classes[:3]:
        accent = accent_for.get(c, "cyan").replace("cyan", "")
        accent_class = f" {accent}" if accent else ""
        stat_cells.append(f"""
      <div class="soc-stat-cell{accent_class}">
        <div class="soc-stat-lbl">{class_label[c]}</div>
        <div class="soc-stat-val">{n}</div>
      </div>""")
    # pad up to 4 platform-content cells (Total + 3 platforms) before the final Platforms count cell
    while len(stat_cells) < 4:
        stat_cells.append("""
      <div class="soc-stat-cell">
        <div class="soc-stat-lbl">—</div>
        <div class="soc-stat-val">—</div>
      </div>""")
    stat_cells.append(f"""
      <div class="soc-stat-cell vi">
        <div class="soc-stat-lbl">Platforms</div>
        <div class="soc-stat-val">{platform_count}</div>
      </div>""")
    stats_html = "".join(stat_cells)

    # ── platform panels, sorted by count desc
    panel_blocks = []
    for folder, files in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        panel_blocks.append(_panel_html(folder, files))
    panels_html = "\n\n    ".join(panel_blocks)

    # ── topbar
    crumb_html = (
        f'<a href="{PORTFOLIO_URL}">SOC</a>'
        ' <span class="sep">/</span> '
        '<b class="here">WRITE-UPS</b>'
    )
    badges_html = (
        '<span class="sev cyan"><span class="dot"></span>TLP:CLEAR</span> '
        '<span class="sev green"><span class="dot"></span>OPERATIONAL</span> '
        f'<a class="sev-link" href="{PORTFOLIO_URL}">PORTFOLIO <span class="ar">↗</span></a> '
        f'<a class="sev-link" href="{REPO_URL}" target="_blank">GITHUB <span class="ar">↗</span></a>'
    )
    today = datetime.utcnow().strftime("%Y-%m-%d")
    clock_label = f"LAST.SYNC · {today}"

    description = (
        f"CTF challenges & cybersecurity lab solutions by {AUTHOR}. "
        f"Browse {total} write-ups across {platform_count} platforms."
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
{common_head("Write-Ups Collection", description=description)}
<style>{TOKENS_CSS}{TOPBAR_CSS}{INDEX_CSS}</style>
</head>
<body>

{topbar(crumb_html, badges_html, clock_label)}

<main class="page">

  <section class="soc-page-hero">
    <div class="soc-page-hero-strap">
      <div class="seg"><b>portfolio</b><span class="dim">/</span><span class="v">write_ups</span></div>
      <div class="seg"><b>indexed</b> <span class="v">{total}</span></div>
      <div class="seg"><b>platforms</b> <span class="v">{platform_count}</span></div>
      <div class="seg" style="margin-left:auto"><b>last_sync</b> <span class="v">{today}</span></div>
    </div>
    <div class="soc-page-hero-body">
      <div class="soc-page-hero-icon">⌖</div>
      <div>
        <h1 class="soc-page-hero-title">Write-Ups Collection</h1>
        <p class="soc-page-hero-sub">CTF challenges &amp; cybersecurity lab solutions — documented, reproducible, verifiable on source</p>
      </div>
    </div>
    <div class="soc-stat-grid">{stats_html}
    </div>
  </section>

  <div class="toolbar">
    <div class="search-wrap">
      <input id="search" class="search-input" type="text" placeholder="grep write-ups..." autocomplete="off" spellcheck="false">
      <span class="search-icon">⌕</span>
    </div>
    <div class="filters" id="filters">
      <span class="fchip-label">Platform</span>
      {chips_html}
      <button class="tweak-toggle" id="tw-open">⚙ Tweaks</button>
    </div>
  </div>

  <div class="platform-stack" id="stack">
    {panels_html}
  </div>

  <div class="no-results" id="no-results">
    <div class="glyph">⌕</div>
    <div class="lbl">no write-ups matched your query · <span class="q" id="nrq"></span></div>
  </div>

  <footer class="foot">
    <span>// chicken0248 · soc.refined · auto-generated index</span>
    <span class="right">
      <a href="{PORTFOLIO_URL}" target="_blank">Portfolio ↗</a>
      <a href="{REPO_URL}" target="_blank">GitHub ↗</a>
    </span>
  </footer>

</main>

{_index_scripts()}

</body>
</html>
"""

    (BUILD_DIR / "index.html").write_text(html, encoding="utf-8")
    print("✅ Created index.html")


def _index_scripts() -> str:
    # NOTE: Inside a regular Python str (not f-string), `${...}` and ``${'`'}` are JS,
    # not template substitutions. Keep this raw.
    return r"""
<!-- ─── Tweaks panel ─── -->
<div id="tw-panel" role="dialog" aria-label="Tweaks">
  <header>
    <span class="dot"></span>
    <span>Tweaks</span>
    <button class="close" id="tw-close" title="Close">✕</button>
  </header>
  <div class="body">
    <div class="tw-row">
      <div class="lbl"><span>Layout</span><span class="val" data-bind="view">Cards</span></div>
      <div class="tw-seg" data-tw="view">
        <button data-val="cards">Cards</button>
        <button data-val="compact">Compact</button>
      </div>
    </div>
    <div class="tw-row">
      <div class="lbl"><span>Card width</span><span class="val" data-bind="cardMin">260 px</span></div>
      <input type="range" class="tw-slider" data-tw="cardMin" min="200" max="400" step="10">
    </div>
    <div class="tw-row">
      <div class="lbl"><span>Show platform meta</span></div>
      <div class="tw-toggle" data-tw="showMeta" role="switch" tabindex="0"></div>
    </div>
    <div class="tw-row">
      <div class="lbl"><span>Show index chip</span></div>
      <div class="tw-toggle" data-tw="showIndex" role="switch" tabindex="0"></div>
    </div>
    <div class="tw-row">
      <div class="lbl"><span>Accent</span><span class="val" data-bind="accent">Subtle</span></div>
      <div class="tw-seg" data-tw="accent">
        <button data-val="subtle">Subtle</button>
        <button data-val="bold">Bold</button>
      </div>
    </div>
    <div class="tw-row">
      <div class="lbl"><span>Panels start</span><span class="val" data-bind="startOpen">First only</span></div>
      <div class="tw-seg" data-tw="startOpen">
        <button data-val="first">First only</button>
        <button data-val="all">All</button>
        <button data-val="none">Collapsed</button>
      </div>
    </div>
    <div class="tw-row">
      <div class="lbl"><span>Sort</span><span class="val" data-bind="sort">A → Z</span></div>
      <div class="tw-seg" data-tw="sort">
        <button data-val="az">A → Z</button>
        <button data-val="za">Z → A</button>
        <button data-val="orig">Original</button>
      </div>
    </div>
  </div>
  <div class="tw-foot">
    <span>// SOC · customise view</span>
    <button class="tw-reset" id="tw-reset">↻ Reset</button>
  </div>
</div>

<script>
(function(){
  /* ─── Search + filter ─── */
  const input  = document.getElementById('search');
  const cards  = document.querySelectorAll('.pcard');
  const noRes  = document.getElementById('no-results');
  const nrq    = document.getElementById('nrq');
  const fchips = document.querySelectorAll('.fchip');
  let activeFilter = 'all';

  function applyFilter(){
    const q = input.value.toLowerCase().trim();
    let anyVisible = false;
    cards.forEach(card => {
      const platOk = (activeFilter === 'all') || card.dataset.platform === activeFilter;
      if(!platOk){ card.classList.add('all-hidden'); return; }
      const rows = card.querySelectorAll('.wrow');
      let cardHasMatch = false;
      rows.forEach(r => {
        const name = (r.dataset.name || '').toLowerCase();
        const show = !q || name.includes(q);
        r.classList.toggle('hidden', !show);
        if(show) cardHasMatch = true;
      });
      card.classList.toggle('all-hidden', !cardHasMatch);
      if(cardHasMatch) anyVisible = true;
      if(q && cardHasMatch) card.open = true;
    });
    noRes.classList.toggle('show', !anyVisible && (!!q || activeFilter !== 'all'));
    nrq.textContent = q ? ('"' + input.value.trim() + '"') : (activeFilter !== 'all' ? ('filter: ' + activeFilter) : '');
  }
  input.addEventListener('input', applyFilter);
  fchips.forEach(c => c.addEventListener('click', () => {
    fchips.forEach(x => x.classList.remove('active'));
    c.classList.add('active');
    activeFilter = c.dataset.filter;
    applyFilter();
  }));

  /* ─── Tweaks ─── */
  const DEFAULTS = {
    "view":"cards","cardMin":260,"showMeta":true,"showIndex":true,
    "accent":"subtle","startOpen":"first","sort":"az"
  };
  const LS = 'writeup-index-tweaks';
  let state = Object.assign({}, DEFAULTS);
  try{ const saved = JSON.parse(localStorage.getItem(LS)||'null'); if(saved) state = Object.assign(state, saved); }catch(e){}

  const panel = document.getElementById('tw-panel');
  const VIEW_LABELS = {cards:'Cards', compact:'Compact'};
  const ACCENT_LABELS = {subtle:'Subtle', bold:'Bold'};
  const START_LABELS = {first:'First only', all:'All', none:'Collapsed'};
  const SORT_LABELS = {az:'A → Z', za:'Z → A', orig:'Original'};

  document.querySelectorAll('.wlist').forEach(list => { list._origOrder = Array.from(list.children); });

  function applySort(mode){
    document.querySelectorAll('.wlist').forEach(list => {
      const items = Array.from(list.children);
      let sorted;
      if(mode === 'az')      sorted = items.slice().sort((a,b)=>(a.dataset.name||'').localeCompare(b.dataset.name||''));
      else if(mode === 'za') sorted = items.slice().sort((a,b)=>(b.dataset.name||'').localeCompare(a.dataset.name||''));
      else                   sorted = list._origOrder.filter(n=>items.indexOf(n) !== -1);
      sorted.forEach(n => list.appendChild(n));
    });
  }

  function applyTweaks(){
    const body = document.body;
    body.classList.toggle('tw-compact',     state.view === 'compact');
    body.classList.toggle('tw-hide-meta',  !state.showMeta);
    body.classList.toggle('tw-hide-index', !state.showIndex);
    body.classList.toggle('tw-accent-bold', state.accent === 'bold');
    body.style.setProperty('--tw-card-min', state.cardMin + 'px');

    const panels = document.querySelectorAll('.pcard');
    if(state.startOpen === 'all')   panels.forEach(p => p.open = true);
    else if(state.startOpen === 'none') panels.forEach(p => p.open = false);
    else panels.forEach((p,i) => p.open = (i === 0));

    applySort(state.sort);

    panel.querySelectorAll('[data-bind]').forEach(el => {
      const k = el.dataset.bind;
      if(k === 'view')          el.textContent = VIEW_LABELS[state.view];
      else if(k === 'cardMin')  el.textContent = state.cardMin + ' px';
      else if(k === 'accent')   el.textContent = ACCENT_LABELS[state.accent];
      else if(k === 'startOpen')el.textContent = START_LABELS[state.startOpen];
      else if(k === 'sort')     el.textContent = SORT_LABELS[state.sort];
    });
    panel.querySelectorAll('.tw-seg').forEach(seg => {
      const k = seg.dataset.tw;
      seg.querySelectorAll('button').forEach(b => b.classList.toggle('active', b.dataset.val === state[k]));
    });
    panel.querySelectorAll('.tw-toggle').forEach(t => {
      t.setAttribute('aria-checked', state[t.dataset.tw] ? 'true' : 'false');
    });
    const sl = panel.querySelector('[data-tw="cardMin"]');
    if(sl){
      sl.value = state.cardMin;
      const pct = ((state.cardMin - sl.min) / (sl.max - sl.min)) * 100;
      sl.style.setProperty('--tw-fill', pct + '%');
    }
  }

  function persist(key, val){
    state[key] = val;
    try{ localStorage.setItem(LS, JSON.stringify(state)); }catch(e){}
    applyTweaks();
  }

  panel.querySelectorAll('.tw-seg').forEach(seg => {
    seg.addEventListener('click', e => {
      const btn = e.target.closest('button[data-val]');
      if(!btn) return;
      persist(seg.dataset.tw, btn.dataset.val);
    });
  });
  panel.querySelectorAll('.tw-toggle').forEach(t => {
    const fire = () => persist(t.dataset.tw, !state[t.dataset.tw]);
    t.addEventListener('click', fire);
    t.addEventListener('keydown', e => { if(e.key === ' ' || e.key === 'Enter'){ e.preventDefault(); fire(); }});
  });
  panel.querySelector('[data-tw="cardMin"]').addEventListener('input', e => persist('cardMin', parseInt(e.target.value,10)));
  document.getElementById('tw-reset').addEventListener('click', () => {
    state = Object.assign({}, DEFAULTS);
    try{ localStorage.removeItem(LS); }catch(e){}
    applyTweaks();
  });
  const twOpen = document.getElementById('tw-open');
  const twClose = document.getElementById('tw-close');
  twOpen.addEventListener('click', () => { panel.classList.toggle('show'); twOpen.classList.toggle('active'); });
  twClose.addEventListener('click', () => { panel.classList.remove('show'); twOpen.classList.remove('active'); });

  applyTweaks();
})();
</script>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ensure_build_path(BUILD_DIR)

    # Copy resources/ once
    resources_src = SRC_DIR / "resources"
    resources_dst = BUILD_DIR / "resources"
    if resources_src.exists():
        if resources_dst.exists():
            shutil.rmtree(resources_dst)
        shutil.copytree(resources_src, resources_dst)
        print("✅ Copied resources folder")

    # Collect markdown files (skip readmes + build/.git/etc.)
    md_files: list[Path] = []
    for root, dirs, files in os.walk(SRC_DIR):
        dirs[:] = [d for d in dirs if d not in ("build", ".github", ".git", "node_modules", ".venv", "__pycache__", "re-design")]
        for fn in files:
            if fn.endswith(".md") and fn.lower() != "readme.md":
                md_files.append(Path(root) / fn)

    if not md_files:
        print("❌ No markdown files found!")
        return
    print(f"Found {len(md_files)} markdown files")

    # Index
    create_index_html(md_files)

    # Per-write-up pages
    for md_file in md_files:
        rel_folder = md_file.parent.relative_to(SRC_DIR)
        out_file = BUILD_DIR / rel_folder / f"{md_file.stem}.html"
        try:
            md_to_html(md_file, out_file)
            print(f"✅ {md_file.relative_to(SRC_DIR)}")
        except Exception as e:
            print(f"❌ {md_file}: {e}")

    print(f"\n✅ Done — {len(md_files)} files written to {BUILD_DIR}/")


if __name__ == "__main__":
    main()
