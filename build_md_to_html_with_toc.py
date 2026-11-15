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
import sys
import json
import html
import shutil
import hashlib
import markdown2
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

SRC_DIR        = Path(".")
BUILD_DIR      = Path("build")
PORTFOLIO_URL  = "https://chicken0248.fyi/"
REPO_URL       = "https://github.com/ChickenLoner/Write_It_UP"
AVATAR_URL     = "https://chicken0248.fyi/chicken0248.png"
AUTHOR         = "Chicken0248"
SITE_URL       = "https://writeups.chicken0248.fyi"
KEYWORDS = ("CTF, write-up, cybersecurity, HackTheBox, TryHackMe, "
            "CyberDefenders, LetsDefend, Centri, BTLO, DFIR, "
            "blue team, digital forensics, incident response")

# Folders never walked for write-ups, and markdown filenames that are repo
# documentation rather than write-ups (CLAUDE.md was leaking onto the site).
SKIP_DIRS  = {"build", ".github", ".git", "node_modules", ".venv",
              "__pycache__", "re-design", "resources", "tools"}
SKIP_NAMES = {"readme.md", "claude.md", "license.md", "licence.md",
              "contributing.md", "changelog.md", "code_of_conduct.md",
              "security.md", "agents.md"}

# ─────────────────────────────────────────────────────────────────────────────
# Platform detection
#   keyword(s) found in the folder path  →  platform descriptor
#   class:       body class & .pcard class used for the kicker / accent
#   icon:        glyph drawn in the platform icon tile (used when there is no logo)
#   logo:        optional file in assets/platforms/ shown instead of the glyph
#   short:       human label used in topbar crumb + meta line
#   long:        full label used on the index panel header
#   kicker:      // <text>  rendered above the H1 on the write-up page
# ─────────────────────────────────────────────────────────────────────────────

PLATFORMS = [
    # (folder-substring tests,                       descriptor)
    (("hackthebox", "sherlock"), {
        "class": "p-htb-sherlock",
        "icon":  "⬡",
        "logo":  "htb.svg",
        "short": "HTB · SHERLOCK",
        "long":  "HTB Sherlocks",
        "kicker": "// HTB · SHERLOCK · DFIR CASE FILE",
        "sev":   "am",
    }),
    (("hackthebox", "machine"), {
        "class": "p-htb-machine",
        "icon":  "⬡",
        "logo":  "htb.svg",
        "short": "HTB · MACHINE",
        "long":  "HTB Machines",
        "kicker": "// HTB · MACHINE · OFFENSIVE",
        "sev":   "am",
    }),
    (("hackthebox",), {
        "class": "p-htb-machine",
        "icon":  "⬡",
        "logo":  "htb.svg",
        "short": "HTB",
        "long":  "HackTheBox",
        "kicker": "// HACKTHEBOX",
        "sev":   "am",
    }),
    (("btlo",), {
        "class": "p-btlo",
        "icon":  "⬤",
        "logo":  "btlo.webp",
        "short": "BTLO",
        "long":  "Centri · Blue Team Labs Online",
        "kicker": "// BTLO · DFIR INVESTIGATION",
        "sev":   "rd",
    }),
    (("cyberdefenders",), {
        "class": "p-cd",
        "icon":  "◈",
        "logo":  "cd.svg",
        "short": "CYBERDEFENDERS",
        "long":  "CyberDefenders",
        "kicker": "// CYBERDEFENDERS · BLUE-TEAM LAB",
        "sev":   "cyan",
    }),
    (("letsdefend",), {
        "class": "p-ld",
        "icon":  "◉",
        "logo":  "letsdefend.svg",
        "short": "LETSDEFEND",
        "long":  "LetsDefend",
        "kicker": "// LETSDEFEND · INVESTIGATION",
        "sev":   "green",
    }),
    (("tryhackme",), {
        "class": "p-thm",
        "icon":  "▲",
        "logo":  "tryhackme.webp",
        "short": "TRYHACKME",
        "long":  "TryHackMe",
        "kicker": "// TRYHACKME · ROOM",
        "sev":   "rd",
    }),
    (("hacksmarter",), {
        "class": "p-hacksmarter",
        "icon":  "◆",
        "logo":  "hacksmarter.webp",
        "short": "HACKSMARTER",
        "long":  "HackSmarter.org",
        "kicker": "// HACKSMARTER",
        "sev":   "am",
    }),
    # Collections inside the Unlisted Labs folder that have a brand (and logo) of
    # their own. Each is a full platform: own class, counts, chips and colours.
    # Must come before the generic entry below.
    (("unlisted", "memlabs"), {
        "class": "p-memlabs",
        "icon":  "⬚",
        "logo":  "memlabs.webp",
        "short": "MEMLABS",
        "long":  "MemLabs",
        "kicker": "// MEMLABS · MEMORY FORENSICS",
        "sev":   "vi",
    }),
    (("unlisted", "level effect"), {
        "class": "p-leveleffect",
        "icon":  "⬚",
        "logo":  "leveleffect.webp",
        "short": "LEVEL EFFECT",
        "long":  "Level Effect",
        "kicker": "// LEVEL EFFECT · CTF",
        "sev":   "vi",
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
  --tb-bg:rgba(13,17,23,.94);
  --link-hover:#7df2ff;
  --code-inline:#a5f3fc;
  --code-inline-bg:rgba(34,225,255,.06);
  --em-ink:#dbe2f5;
  --strong-q:#fff;
  --machine-kicker:#d97757;
  --plat-pink:#f472b6;
}
/* light palette — "SIEM console", IBM Carbon g10; identical values to the
   portfolio's html[data-theme="light"] (themes/soc.css, I1 block) */
html[data-theme="light"]{
  --soc-bg:#f4f4f4;     --soc-bg-1:#ffffff;  --soc-bg-2:#f4f4f4;
  --soc-line:#e0e0e0;   --soc-line2:#c6c6c6;
  --soc-ink:#161616;    --soc-ink2:#393939;
  --soc-ink3:#525252;   --soc-ink4:#6f6f6f;
  --soc-cy:#0f62fe;     --soc-cy2:#0043ce;
  --soc-am:#8e6a00;     --soc-gn:#198038;
  --soc-rd:#da1e28;     --soc-vi:#8a3ffc;
  --tb-bg:#ffffff;
  --link-hover:#0043ce;
  --code-inline:#0043ce;
  --code-inline-bg:rgba(15,98,254,.06);
  --em-ink:var(--soc-ink);
  --strong-q:var(--soc-ink);
  --machine-kicker:#ba4e00;
  --plat-pink:#d02670;
  color-scheme:light;
}
.p-htb-sherlock{--kicker-text:"// HTB · SHERLOCK · DFIR CASE FILE";--kicker-color:var(--soc-am)}
.p-htb-machine {--kicker-text:"// HTB · MACHINE · OFFENSIVE";       --kicker-color:var(--machine-kicker)}
.p-btlo        {--kicker-text:"// BTLO · DFIR INVESTIGATION";       --kicker-color:var(--soc-rd)}
.p-cd          {--kicker-text:"// CYBERDEFENDERS · BLUE-TEAM LAB";  --kicker-color:var(--soc-cy)}
.p-thm         {--kicker-text:"// TRYHACKME · ROOM";                --kicker-color:var(--soc-rd)}
.p-ld          {--kicker-text:"// LETSDEFEND · INVESTIGATION";      --kicker-color:var(--soc-gn)}
.p-hacksmarter {--kicker-text:"// HACKSMARTER";                     --kicker-color:var(--soc-am)}
.p-unlisted    {--kicker-text:"// UNLISTED";                        --kicker-color:var(--soc-vi)}
.p-memlabs    {--kicker-text:"// MEMLABS · MEMORY FORENSICS";                        --kicker-color:var(--soc-vi)}
.p-leveleffect    {--kicker-text:"// LEVEL EFFECT · CTF";                        --kicker-color:var(--soc-vi)}

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
a:hover{color:var(--link-hover);text-decoration:underline}
[data-theme="light"] body{background:var(--soc-bg)}
[data-theme="light"] body::before{display:none}
[data-theme="light"] .soc-tb{backdrop-filter:none;-webkit-backdrop-filter:none}
"""

TOPBAR_CSS = """
.soc-tb{position:sticky;top:0;z-index:50;background:var(--tb-bg);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);border-bottom:1px solid var(--soc-line)}
.soc-tb-row{display:flex;align-items:center;gap:14px;padding:9px 22px;font-size:12px;min-height:44px}
.soc-live{display:inline-flex;align-items:center;gap:6px;color:var(--soc-ink);font-weight:700;letter-spacing:.06em;font-family:'JetBrains Mono',monospace;flex-shrink:0;text-decoration:none}
.soc-live:hover{color:var(--soc-cy);text-decoration:none}
.soc-live::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--soc-gn);box-shadow:0 0 8px var(--soc-gn);animation:bp 1.6s infinite}
@keyframes bp{50%{opacity:.3}}
.soc-crumb{color:var(--soc-ink3);font-family:'JetBrains Mono',monospace;font-size:11px;display:block;flex:1 1 auto;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;letter-spacing:.03em}
.soc-crumb .sep{margin:0 .3rem}
.soc-crumb a{color:var(--soc-ink3);text-decoration:none;transition:.12s}
.soc-crumb a:hover{color:var(--soc-ink);text-decoration:none}
.soc-crumb b{color:var(--soc-ink2);font-weight:600}
.soc-crumb a b{color:var(--soc-ink2);font-weight:600}
.soc-crumb a:hover b{color:var(--soc-ink)}
.soc-crumb .here{color:var(--soc-cy);font-weight:700}
.soc-crumb .sep{color:var(--soc-ink4)}
.soc-clock{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--soc-ink3);white-space:nowrap;font-variant-numeric:tabular-nums}
.soc-tb-right{margin-left:auto;display:flex;align-items:center;gap:10px;flex-shrink:0}
.soc-tb-badges{display:flex;align-items:center;gap:8px}

/* theme switch: same markup + behaviour as the portfolio's ThemeToggle */
.soc-theme-btn{display:inline-flex;align-items:center;gap:8px;padding:5px 11px 5px 8px;border-radius:99px;border:1px solid var(--soc-line2);background:var(--soc-bg-2);color:var(--soc-ink2);font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:.08em;font-weight:600;text-transform:uppercase;cursor:pointer;transition:border-color .18s,color .18s,background .18s;flex-shrink:0;height:28px;line-height:1}
.soc-theme-btn:hover{border-color:var(--soc-cy);color:var(--soc-cy)}
.soc-theme-btn .soc-tb-track{position:relative;width:30px;height:14px;border-radius:99px;background:rgba(34,225,255,.18);border:1px solid var(--soc-line2);flex-shrink:0;transition:background .25s,border-color .25s}
.soc-theme-btn .soc-tb-knob{position:absolute;top:1px;left:1px;width:10px;height:10px;border-radius:50%;background:var(--soc-cy);box-shadow:0 0 8px var(--soc-cy);transition:transform .25s cubic-bezier(.5,.1,.25,1.3),background .25s}
.soc-theme-btn .soc-tb-ico{font-size:13px;line-height:1}
.soc-theme-btn .soc-tb-dark{display:inline}
.soc-theme-btn .soc-tb-light{display:none}
[data-theme="light"] .soc-theme-btn{background:var(--soc-bg-1);border-color:var(--soc-line)}
[data-theme="light"] .soc-theme-btn .soc-tb-track{background:rgba(15,98,254,.15)}
[data-theme="light"] .soc-theme-btn .soc-tb-knob{transform:translateX(16px);box-shadow:0 0 0 2px rgba(15,98,254,.18)}
[data-theme="light"] .soc-theme-btn .soc-tb-dark{display:none}
[data-theme="light"] .soc-theme-btn .soc-tb-light{display:inline}

/* answers switch — same pill as the theme switch, green when answers are shown */
.wu-ans-btn{display:inline-flex;align-items:center;gap:8px;padding:5px 11px;border-radius:99px;border:1px solid var(--soc-line2);background:var(--soc-bg-2);color:var(--soc-ink2);font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:.08em;font-weight:600;cursor:pointer;transition:border-color .18s,color .18s;flex-shrink:0;height:28px;line-height:1}
.wu-ans-btn:hover{border-color:var(--soc-gn);color:var(--soc-gn)}
.wu-ans-btn .wu-ans-lbl{color:var(--soc-ink3)}
.wu-ans-btn .soc-tb-track{position:relative;width:30px;height:14px;border-radius:99px;background:rgba(138,155,191,.18);border:1px solid var(--soc-line2);flex-shrink:0;transition:background .25s}
.wu-ans-btn .soc-tb-knob{position:absolute;top:1px;left:1px;width:10px;height:10px;border-radius:50%;background:var(--soc-ink4);transition:transform .25s cubic-bezier(.5,.1,.25,1.3),background .25s}
.wu-ans-btn .wu-ans-on,.wu-ans-btn .wu-ans-short{display:none}
[data-answers="shown"] .wu-ans-btn{color:var(--soc-gn)}
[data-answers="shown"] .wu-ans-btn .soc-tb-track{background:rgba(61,220,132,.18)}
[data-answers="shown"] .wu-ans-btn .soc-tb-knob{transform:translateX(16px);background:var(--soc-gn);box-shadow:0 0 8px var(--soc-gn)}
[data-answers="shown"] .wu-ans-btn .wu-ans-on{display:inline}
[data-answers="shown"] .wu-ans-btn .wu-ans-off{display:none}
[data-theme="light"] .wu-ans-btn{background:var(--soc-bg-1);border-color:var(--soc-line)}
[data-theme="light"][data-answers="shown"] .wu-ans-btn .soc-tb-knob{box-shadow:0 0 0 2px rgba(25,128,56,.18)}

/* the portfolio hides crumb, badges and clock on phones; UPLINK stays as the home link */
@media(max-width:1100px){.soc-tb-badges .sev-link,.soc-tb-badges .sev.green{display:none}}
@media(max-width:1279px){.wu-ans-btn~.soc-clock,.soc-tb-right:has(.wu-ans-btn) .soc-clock{display:none}}
@media(max-width:767px){
  .soc-crumb,.soc-tb-badges,.soc-clock{display:none}
  .soc-tb-row{padding:8px 16px}
  .wu-ans-btn .wu-ans-full{display:none}
  .wu-ans-btn .wu-ans-short{display:inline}
  .wu-ans-btn{gap:6px;padding:5px 9px}
}

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
# CSS — light theme, Carbon conventions (shared by every page)
# Mirrors the portfolio's I1/D1 blocks in themes/soc.css: square corners, no
# shadows or glows, 2px blue focus outline, Carbon tag tints for status chips,
# neutral grey tags, white panels with borders instead of shadows.
# Uses html[data-theme] so it outranks the per-page dark rules.
# ─────────────────────────────────────────────────────────────────────────────

LIGHT_CARBON_CSS = """
html[data-theme="light"] *:not(img):not(.soc-theme-btn):not(.soc-theme-btn *):not(.wu-ans-btn):not(.wu-ans-btn *):not(.dot){border-radius:0 !important}
html[data-theme="light"] *,html[data-theme="light"] *::before,html[data-theme="light"] *::after{box-shadow:none !important;text-shadow:none !important}
html[data-theme="light"] .content img{box-shadow:none !important}
html[data-theme="light"] :focus-visible{outline:2px solid var(--soc-cy);outline-offset:1px}
html[data-theme="light"] .soc-live::before{animation:none}

/* status chips: Carbon tag tints (very light fill + matching border) */
html[data-theme="light"] .sev.green{background:#defbe6;border-color:#a7f0ba}
html[data-theme="light"] .sev.cyan {background:#edf5ff;border-color:#a6c8ff}
html[data-theme="light"] .sev.am   {background:#fcf4d6;border-color:#f1c21b}
html[data-theme="light"] .sev.rd   {background:#fff1f1;border-color:#ffb3b8}
html[data-theme="light"] .sev.vi   {background:#f6f2ff;border-color:#d4bbff}
html[data-theme="light"] .sev-link{background:var(--soc-bg-1);border-color:var(--soc-line2);color:var(--soc-ink2)}
html[data-theme="light"] .sev-link:hover{background:#edf5ff;border-color:var(--soc-cy);color:var(--soc-cy)}

/* difficulty pills (article info box + index cards): same tag tints */
html[data-theme="light"] :is(.wu-diff,.wrow .diff).d-very-easy{color:var(--soc-cy);background:#edf5ff;border-color:#a6c8ff}
html[data-theme="light"] :is(.wu-diff,.wrow .diff).d-easy{color:var(--soc-gn);background:#defbe6;border-color:#a7f0ba}
html[data-theme="light"] :is(.wu-diff,.wrow .diff).d-medium{color:var(--soc-am);background:#fcf4d6;border-color:#f1c21b}
html[data-theme="light"] :is(.wu-diff,.wrow .diff).d-hard{color:var(--soc-rd);background:#fff1f1;border-color:#ffb3b8}
html[data-theme="light"] :is(.wu-diff,.wrow .diff).d-insane{color:var(--soc-vi);background:#f6f2ff;border-color:#d4bbff}

/* tags: neutral chips, colour is reserved for state */
html[data-theme="light"] :is(.wu-tag,.wrow .tag){background:var(--soc-bg-2);border-color:var(--soc-line);color:var(--soc-ink2)}

/* panels: white on the grey page, separated by borders */
html[data-theme="light"] :is(.wu-meta,.pcard,.wrow){background:var(--soc-bg-1)}
html[data-theme="light"] .wrow .banner{background:var(--soc-bg-1) !important}
html[data-theme="light"] .pcard summary,html[data-theme="light"] .pcard summary:hover{background:var(--soc-bg-1)}
html[data-theme="light"] .pcard summary:hover{background:var(--soc-bg-2)}
/* accent boxes: the one Carbon blue instead of the dark theme's cyan */
html[data-theme="light"] :is(.pcard .ph-icon,.pcard.p-cd .ph-icon){background:#edf5ff;border-color:#a6c8ff;color:var(--soc-cy)}
html[data-theme="light"] .pcard.p-cd .wrow::before,html[data-theme="light"] .wrow:hover::before{background:var(--soc-cy)}
html[data-theme="light"] :is(.pcard[open],.pcard.p-cd[open]){border-color:var(--soc-line2)}
html[data-theme="light"] :is(.search-input,.fchip){background-color:var(--soc-bg-1)}

/* article: question boxes are white cards with a blue left rule (portfolio callouts);
   answers get a green rule; code + answer bodies stay dark (terminal output) */
html[data-theme="light"] .content blockquote{background:var(--soc-bg-1);border-color:var(--soc-line);border-left-color:var(--soc-cy)}
html[data-theme="light"] .content details{background:var(--soc-bg-1);border-color:var(--soc-line);border-left:3px solid var(--soc-gn)}
html[data-theme="light"] .content details summary::after{background:linear-gradient(90deg,rgba(25,128,56,.35),transparent)}
html[data-theme="light"] .content code{border-color:rgba(15,98,254,.18)}
html[data-theme="light"] .content pre code{color:#e2e8f0}
html[data-theme="light"] .content h1 a::after{background:#edf5ff;border-color:#a6c8ff}
html[data-theme="light"] .content th{color:var(--soc-ink2)}
html[data-theme="light"] .content thead{background:var(--soc-bg-2)}
html[data-theme="light"] .soc-read-track>i,html[data-theme="light"] .soc-read-bar>i{box-shadow:none}
html[data-theme="light"] .wu-toc-item.is-active::before{box-shadow:none}
"""

# ─────────────────────────────────────────────────────────────────────────────
# CSS — Article (write-up page)
# ─────────────────────────────────────────────────────────────────────────────

ARTICLE_CSS = """
.content{max-width:100%;font-size:15px;line-height:1.7;min-width:0}
.content [id]{scroll-margin-top:72px}

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

.wu-body{counter-reset:wsec}
.content h2{
  display:flex;align-items:center;gap:11px;
  font-size:1.2rem;font-weight:700;color:var(--soc-ink);line-height:1.3;
  margin:2.6rem 0 1rem;padding:0 0 .75rem;
  border-bottom:1px solid var(--soc-line);letter-spacing:-.01em
}
.wu-body>h2:first-child{margin-top:.4rem}
.content h2:not([id^="table-of-contents"]){counter-increment:wsec}
.content h2::before{
  content:counter(wsec,decimal-leading-zero);flex-shrink:0;
  display:inline-grid;place-items:center;width:32px;height:32px;border-radius:6px;
  background:rgba(34,225,255,.1);border:1px solid rgba(34,225,255,.25);
  font-family:'JetBrains Mono',monospace;font-size:11.5px;font-weight:700;
  color:var(--soc-cy);letter-spacing:0
}
.content h2[id^="table-of-contents"]::before{content:"≡";font-size:15px}
[data-theme="light"] .content h2::before{background:rgba(15,98,254,.08);border-color:rgba(15,98,254,.25)}
.content h3{
  font-size:1rem;font-weight:700;color:var(--soc-ink2);line-height:1.4;
  margin:1.9rem 0 .7rem;padding-left:10px;border-left:3px solid var(--soc-cy)
}
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
.content em{color:var(--em-ink)}
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
.content a:hover{color:var(--link-hover);border-bottom-color:var(--soc-cy);text-decoration:none}

/* ─── blockquote (Q1) ...) ─────────────────────────────────── */
.content blockquote{
  margin:1.4rem 0 .9rem;padding:.85rem 1rem .85rem 1.1rem;
  background:linear-gradient(90deg,rgba(34,225,255,.06),rgba(34,225,255,.012) 70%,transparent);
  border:1px solid var(--soc-line);
  border-left:3px solid var(--soc-cy);border-radius:0 4px 4px 0
}
.content blockquote p{margin:0;color:var(--soc-ink);font-weight:500;font-size:.96rem;line-height:1.55}
.content blockquote p+p{margin-top:.45rem}
.content blockquote strong{color:var(--strong-q)}
.content blockquote+blockquote{margin-top:.4rem}

/* ─── inline + block code ──────────────────────────────────── */
.content code{
  font-family:'JetBrains Mono',monospace;font-size:.85em;
  background:var(--code-inline-bg);
  border:1px solid rgba(34,225,255,.18);color:var(--code-inline);
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

/* ─── light theme: code + answer blocks stay dark (terminal output), the rest follows the page */
[data-theme="light"] .content pre{border-color:#1c2433}
[data-theme="light"] .content pre code[class]:not([class=""])::before{color:#8a9bbf;border-bottom-color:#253040}
[data-theme="light"] .content img{background:var(--soc-bg-2);box-shadow:0 1px 2px rgba(12,23,41,.06),0 8px 22px rgba(12,23,41,.07)}
[data-theme="light"] .content blockquote{background:linear-gradient(90deg,rgba(15,98,254,.07),rgba(15,98,254,.015) 70%,transparent);border-color:var(--soc-line);border-left-color:var(--soc-cy)}
[data-theme="light"] .content details{background:linear-gradient(180deg,rgba(25,128,56,.06),rgba(25,128,56,.015));border-color:rgba(25,128,56,.3)}
[data-theme="light"] .content tr:nth-child(even) td{background:rgba(12,23,41,.02)}

/* ═══ Article shell — mirrors the portfolio's .soc-article ═══════════════
   <1280px : one reading column (max 900px); the info box sits under the title.
   ≥1280px : sticky TOC rail on the left + article.
   ≥1440px : TOC | article | sticky info rail (meta + reading progress).
   The rail replaces Joplin's inline "Table of Contents", so that list is
   hidden whenever the rail is on screen and kept on tablets / phones. */
.soc-article{max-width:900px;margin:0 auto;padding:26px 22px 56px;position:relative;z-index:1}
.wu-head h1{margin-top:0}
.wu-dek{font-size:14.5px;line-height:1.6;color:var(--soc-ink3);margin:-.2rem 0 1.25rem;max-width:80ch;text-wrap:pretty}

.wu-meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px 18px;background:var(--soc-bg-1);border:1px solid var(--soc-line);border-radius:6px;padding:16px 18px;margin:0 0 26px}
.wu-meta-lbl{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--soc-ink3);text-transform:uppercase;letter-spacing:.14em;margin-bottom:4px}
.wu-meta-val{font-size:13.5px;font-weight:600;color:var(--soc-ink);line-height:1.35}
.wu-meta-link{font-size:13.5px;font-weight:600;color:var(--soc-cy)}
.wu-meta-wide{grid-column:1/-1}
.wu-tags{display:flex;flex-wrap:wrap;gap:5px;margin-top:2px}
.wu-tag{font-family:'JetBrains Mono',monospace;font-size:10.5px;color:var(--soc-ink3);padding:2px 7px;border:1px solid var(--soc-line);border-radius:3px;background:var(--soc-bg-2)}
.wu-diff{display:inline-block;font-family:'JetBrains Mono',monospace;font-size:10.5px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;padding:3px 8px;border-radius:3px;border:1px solid var(--soc-line);color:var(--soc-ink3)}
.wu-diff.d-very-easy{color:var(--soc-cy);border-color:rgba(34,225,255,.35);background:rgba(34,225,255,.08)}
.wu-diff.d-easy{color:var(--soc-gn);border-color:rgba(61,220,132,.35);background:rgba(61,220,132,.08)}
.wu-diff.d-medium{color:var(--soc-am);border-color:rgba(255,181,71,.35);background:rgba(255,181,71,.08)}
.wu-diff.d-hard{color:var(--soc-rd);border-color:rgba(255,85,119,.35);background:rgba(255,85,119,.08)}
.wu-diff.d-insane{color:var(--soc-vi);border-color:rgba(167,139,250,.35);background:rgba(167,139,250,.08)}

.wu-toc{display:none}
.wu-toc-title{font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:600;letter-spacing:.16em;text-transform:uppercase;color:var(--soc-ink3);margin-bottom:10px;padding-left:10px}
.wu-toc-item{position:relative;display:flex;gap:8px;align-items:baseline;padding:6px 10px;border-radius:4px;color:var(--soc-ink3);font-size:12.5px;line-height:1.4;text-decoration:none;transition:color .15s,background .15s}
.wu-toc-item:hover{background:rgba(34,225,255,.05);color:var(--soc-cy);text-decoration:none}
.wu-toc-q .wu-toc-item span:last-child{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.wu-toc-q .wu-toc-num{width:26px}
/* questions nested under their heading: Q-number column, two-line clamp */
.wu-toc-item.q{padding:4px 10px 4px 22px;font-size:11.5px}
.wu-toc-item.q .wu-toc-num{width:26px}
.wu-toc-item.q span:last-child{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.wu-toc-q .wu-toc-item.q{padding:6px 10px;font-size:12.5px}
.wu-toc-item.sub{padding:4px 10px 4px 38px;font-size:11.5px}
.wu-toc-num{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--soc-ink4);width:20px;flex-shrink:0}
.wu-toc-item.is-active{color:var(--soc-cy);background:rgba(34,225,255,.07)}
.wu-toc-item.is-active .wu-toc-num{color:var(--soc-cy)}
.wu-toc-item.is-active::before{content:"";position:absolute;left:-15px;top:6px;bottom:6px;width:2px;border-radius:2px;background:var(--soc-cy);box-shadow:0 0 8px rgba(34,225,255,.6)}
[data-theme="light"] .wu-toc-item.is-active{background:rgba(15,98,254,.08)}

@media(min-width:1280px){
  .soc-article.has-toc{
    max-width:none;display:grid;grid-template-columns:minmax(230px,.3fr) minmax(0,1fr);
    column-gap:40px;padding:28px 22px 56px
  }
  .soc-article.has-toc>*{grid-column:2}
  .soc-article.has-toc>.wu-head,.soc-article.has-toc>.wu-meta{grid-column:1/-1}
  .soc-article.has-toc>.wu-toc{
    display:block;grid-column:1;grid-row:3/span 300;align-self:start;
    position:sticky;top:76px;max-height:calc(100vh - 96px);overflow:auto;
    border-left:1px solid var(--soc-line);padding:4px 4px 4px 14px;scrollbar-width:thin
  }
  .soc-article.has-toc>.wu-body{grid-row:3}
  .has-toc .content h2[id^="table-of-contents"],
  .has-toc .content h2[id^="table-of-contents"]+ul{display:none}
}
@media(min-width:1440px){
  .soc-article.has-toc{grid-template-columns:minmax(230px,.3fr) minmax(0,1fr) minmax(260px,.3fr);column-gap:44px}
  .soc-article.has-toc>.wu-toc{grid-row:2/span 300}
  .soc-article.has-toc>.wu-body{grid-row:2}
  .soc-article.has-toc>.wu-meta{
    grid-column:3;grid-row:2/span 300;align-self:start;position:sticky;top:76px;
    margin:0;grid-template-columns:1fr;gap:16px;padding:18px 20px
  }
}
@media(min-width:1800px){.soc-article{zoom:1.125}}
@media(min-width:2300px){.soc-article{zoom:1.25}}
@media(min-width:3000px){.soc-article{zoom:1.5}}

/* reading progress: card in the info rail ≥1440px, thin bar under the topbar below that */
.soc-read-card{display:none}
.soc-read-bar{position:fixed;left:0;right:0;top:44px;height:2px;z-index:49;pointer-events:none}
.soc-read-bar>i{display:block;height:100%;width:0;background:var(--soc-cy);box-shadow:0 0 8px rgba(34,225,255,.6)}
@media(min-width:1440px){
  .has-toc~.soc-read-bar{display:none}
  .has-toc .soc-read-card{display:block;grid-column:1/-1;border-top:1px solid var(--soc-line);padding-top:16px;margin-top:2px}
}
.soc-read-head{display:flex;justify-content:space-between;align-items:baseline;font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:.16em;color:var(--soc-ink3);text-transform:uppercase}
.soc-read-pct{color:var(--soc-cy);font-size:12px;letter-spacing:.04em}
.soc-read-track{height:4px;border-radius:4px;background:var(--soc-line);margin:10px 0 12px;overflow:hidden}
.soc-read-track>i{display:block;height:100%;width:0;border-radius:4px;background:var(--soc-cy);box-shadow:0 0 8px rgba(34,225,255,.5)}
.soc-read-now{font-size:13px;line-height:1.4;color:var(--soc-ink);min-height:1.4em;overflow:hidden;text-overflow:ellipsis;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
.soc-read-now span{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--soc-cy);margin-right:6px}
.soc-read-links{display:flex;justify-content:space-between;gap:10px;margin-top:14px;font-family:'JetBrains Mono',monospace;font-size:11px}
.soc-read-links a,.soc-read-links button{color:var(--soc-ink3);text-decoration:none;background:none;border:none;padding:0;cursor:pointer;font:inherit}
.soc-read-links a:hover,.soc-read-links button:hover{color:var(--soc-cy);text-decoration:none}

@media(max-width:767px){
  .soc-article{padding:18px 16px 40px}
  .content h1{font-size:1.55rem}
  .content h2{font-size:1.08rem;gap:9px}
  .content h2::before{width:28px;height:28px;font-size:10.5px}
  .wu-meta{grid-template-columns:1fr 1fr;padding:14px}
  .soc-read-bar{top:44px}
}
"""

# ─────────────────────────────────────────────────────────────────────────────
# CSS — Index page
# ─────────────────────────────────────────────────────────────────────────────

INDEX_CSS = """
/* fluid like the portfolio's .soc-main: no fixed cap, 22px gutters that line up
   with the topbar; very large monitors scale up instead of stretching rows */
.page{width:100%;margin:0 auto;padding:24px 22px 80px;position:relative;z-index:1}
@media(min-width:1800px){.page{zoom:1.125}}
@media(min-width:2300px){.page{zoom:1.25}}
@media(min-width:3000px){.page{zoom:1.5}}


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
.dfilters{margin-left:0;margin-top:2px}
.dchip{
  display:inline-flex;align-items:center;gap:6px;padding:5px 11px;
  border:1px solid var(--soc-line);background:var(--soc-bg-1);border-radius:4px;
  font-family:'JetBrains Mono',monospace;font-size:10.5px;color:var(--soc-ink3);
  letter-spacing:.06em;font-weight:600;cursor:pointer;text-transform:uppercase;transition:.15s
}
.dchip:hover{color:var(--soc-ink2);border-color:var(--soc-line2)}
.dchip .cnt{padding:1px 6px;border-radius:3px;background:var(--soc-bg-2);color:var(--soc-ink4);font-size:9.5px}
.dchip.active{color:var(--soc-cy);border-color:rgba(34,225,255,.4);background:rgba(34,225,255,.06)}
.dchip.active .cnt{background:rgba(34,225,255,.15);color:var(--soc-cy)}
.dchip.d-very-easy.active,.dchip.d-easy.active{color:var(--soc-gn);border-color:rgba(61,220,132,.45);background:rgba(61,220,132,.08)}
.dchip.d-medium.active{color:var(--soc-am);border-color:rgba(255,181,71,.45);background:rgba(255,181,71,.08)}
.dchip.d-hard.active{color:var(--soc-rd);border-color:rgba(255,85,119,.45);background:rgba(255,85,119,.08)}
.dchip.d-insane.active{color:var(--soc-vi);border-color:rgba(167,139,250,.45);background:rgba(167,139,250,.08)}
.tweak-toggle{
  position:fixed;bottom:18px;right:18px;z-index:150;
  display:inline-flex;align-items:center;gap:7px;padding:10px 16px;
  border:1px solid rgba(34,225,255,.45);background:rgba(34,225,255,.12);border-radius:99px;
  font-family:'JetBrains Mono',monospace;font-size:11.5px;color:var(--soc-cy);
  letter-spacing:.08em;font-weight:700;cursor:pointer;text-transform:uppercase;transition:.15s;
  box-shadow:0 6px 20px rgba(0,0,0,.4),0 0 0 1px rgba(34,225,255,.08);backdrop-filter:blur(6px)
}
.tweak-toggle:hover{color:#fff;border-color:var(--soc-cy);background:rgba(34,225,255,.2);transform:translateY(-1px)}
.tweak-toggle.active{color:#fff;border-color:var(--soc-cy);background:rgba(34,225,255,.28)}
.tweak-toggle.hidden-by-panel{opacity:0;pointer-events:none}

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
.pcard.p-memlabs          .ph-icon{background:rgba(167,139,250,.08);border-color:rgba(167,139,250,.35);color:var(--soc-vi)}
.pcard.p-leveleffect          .ph-icon{background:rgba(167,139,250,.08);border-color:rgba(167,139,250,.35);color:var(--soc-vi)}
/* Platform logo chip. Logos are drawn for dark backgrounds (white wordmarks), so
   the chip stays dark in the light theme too. */
.pcard .ph-icon.has-logo,
html[data-theme="light"] .pcard .ph-icon.has-logo{
  width:auto;min-width:38px;padding:0 10px;background:#0b1220;border-color:rgba(255,255,255,.16)
}
/* Fixed height + object-fit, not height:auto: an SVG with only a viewBox (LetsDefend's)
   has no intrinsic size and would collapse. contain keeps very wide logos undistorted. */
.pcard .ph-logo{display:block;height:24px;width:auto;max-width:136px;object-fit:contain}
.pcard.p-unlisted[open]    {border-color:rgba(167,139,250,.35)}
.pcard.p-memlabs[open]    {border-color:rgba(167,139,250,.35)}
.pcard.p-leveleffect[open]    {border-color:rgba(167,139,250,.35)}

/* ─── WRITE-UP CARD LIST (1 per row · banner + body) ─── */
.wlist{
  display:grid;grid-template-columns:1fr;
  gap:10px;padding:14px;background:rgba(0,0,0,.18)
}
.wrow{
  position:relative;display:block;
  background:var(--soc-bg-1);
  border:1px solid var(--soc-line);border-radius:6px;
  text-decoration:none;color:inherit;transition:.15s;overflow:hidden
}
.wrow::before{content:"";position:absolute;top:0;left:0;bottom:0;width:3px;background:var(--soc-line2);transition:.15s;z-index:1}
.wrow:hover{
  border-color:rgba(34,225,255,.3);text-decoration:none;transform:translateY(-1px);
  box-shadow:0 6px 18px rgba(0,0,0,.28)
}
.wrow:hover::before{background:var(--soc-cy);box-shadow:0 0 8px rgba(34,225,255,.5)}
.pcard.p-htb-sherlock .wrow::before{background:rgba(255,181,71,.55)}
.pcard.p-htb-machine  .wrow::before{background:rgba(217,119,87,.55)}
.pcard.p-btlo         .wrow::before{background:rgba(255,85,119,.55)}
.pcard.p-cd           .wrow::before{background:rgba(34,225,255,.5)}
.pcard.p-ld           .wrow::before{background:rgba(61,220,132,.5)}
.pcard.p-thm          .wrow::before{background:rgba(255,85,119,.55)}
.pcard.p-hacksmarter  .wrow::before{background:rgba(255,181,71,.55)}
.pcard.p-unlisted     .wrow::before{background:rgba(167,139,250,.55)}
.pcard.p-memlabs     .wrow::before{background:rgba(167,139,250,.55)}
.pcard.p-leveleffect     .wrow::before{background:rgba(167,139,250,.55)}
.pcard.p-htb-sherlock .wrow:hover::before{background:var(--soc-am);box-shadow:0 0 8px rgba(255,181,71,.5)}
.pcard.p-htb-machine  .wrow:hover::before{background:#d97757;box-shadow:0 0 8px rgba(217,119,87,.5)}
.pcard.p-btlo         .wrow:hover::before{background:var(--soc-rd);box-shadow:0 0 8px rgba(255,85,119,.5)}
.pcard.p-cd           .wrow:hover::before{background:var(--soc-cy);box-shadow:0 0 8px rgba(34,225,255,.5)}
.pcard.p-ld           .wrow:hover::before{background:var(--soc-gn);box-shadow:0 0 8px rgba(61,220,132,.5)}
.pcard.p-thm          .wrow:hover::before{background:var(--soc-rd);box-shadow:0 0 8px rgba(255,85,119,.5)}
.pcard.p-hacksmarter  .wrow:hover::before{background:var(--soc-am);box-shadow:0 0 8px rgba(255,181,71,.5)}
.pcard.p-unlisted     .wrow:hover::before{background:var(--soc-vi);box-shadow:0 0 8px rgba(167,139,250,.5)}
.pcard.p-memlabs     .wrow:hover::before{background:var(--soc-vi);box-shadow:0 0 8px rgba(167,139,250,.5)}
.pcard.p-leveleffect     .wrow:hover::before{background:var(--soc-vi);box-shadow:0 0 8px rgba(167,139,250,.5)}

/* banner = cover strip: index · platform · difficulty + big name */
.wrow .banner{padding:12px 16px 13px;border-bottom:1px solid var(--soc-line);background:linear-gradient(180deg,rgba(255,255,255,.035),rgba(255,255,255,.006))}
.pcard.p-htb-sherlock .wrow .banner{background:linear-gradient(180deg,rgba(255,181,71,.09),transparent 90%)}
.pcard.p-htb-machine  .wrow .banner{background:linear-gradient(180deg,rgba(217,119,87,.09),transparent 90%)}
.pcard.p-btlo         .wrow .banner{background:linear-gradient(180deg,rgba(255,85,119,.09),transparent 90%)}
.pcard.p-cd           .wrow .banner{background:linear-gradient(180deg,rgba(34,225,255,.08),transparent 90%)}
.pcard.p-ld           .wrow .banner{background:linear-gradient(180deg,rgba(61,220,132,.08),transparent 90%)}
.pcard.p-thm          .wrow .banner{background:linear-gradient(180deg,rgba(255,85,119,.09),transparent 90%)}
.pcard.p-hacksmarter  .wrow .banner{background:linear-gradient(180deg,rgba(255,181,71,.09),transparent 90%)}
.pcard.p-unlisted     .wrow .banner{background:linear-gradient(180deg,rgba(167,139,250,.09),transparent 90%)}
.pcard.p-memlabs     .wrow .banner{background:linear-gradient(180deg,rgba(167,139,250,.09),transparent 90%)}
.pcard.p-leveleffect     .wrow .banner{background:linear-gradient(180deg,rgba(167,139,250,.09),transparent 90%)}
.wrow .bhead{display:flex;align-items:center;gap:8px;font-family:'JetBrains Mono',monospace}
.wrow .bright{margin-left:auto;display:inline-flex;align-items:center;gap:8px;flex-shrink:0}
.wrow .ix{font-size:9.5px;font-weight:700;letter-spacing:.08em;color:var(--soc-ink4);padding:3px 7px;border:1px solid var(--soc-line);border-radius:3px;background:rgba(0,0,0,.35)}
.wrow:hover .ix{color:var(--soc-cy);border-color:rgba(34,225,255,.35);background:rgba(34,225,255,.06)}
.wrow .meta{font-size:9.5px;color:var(--soc-ink4);letter-spacing:.1em;text-transform:uppercase;display:inline-flex;align-items:center;gap:5px}
.wrow .meta .dot{width:4px;height:4px;border-radius:50%;background:var(--soc-ink4)}
.wrow .open-ic{
  font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700;
  color:var(--soc-ink4);width:22px;height:22px;border-radius:3px;display:grid;place-items:center;
  border:1px solid var(--soc-line);background:rgba(0,0,0,.2);transition:.15s
}
.wrow:hover .open-ic{color:var(--soc-cy);border-color:var(--soc-cy);background:rgba(34,225,255,.1);transform:translate(2px,-2px)}
.wrow .nm{
  font-size:17px;font-weight:700;color:var(--soc-ink);line-height:1.25;margin-top:8px;
  letter-spacing:-.01em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap
}
.wrow:hover .nm{color:#fff}
.wrow .body{padding:11px 16px 13px;display:flex;flex-direction:column;gap:7px}
.wrow .body:empty{display:none}
.wrow:hover .nm{color:#fff}
.wrow .diff{font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;padding:4px 9px;border-radius:3px;border:1px solid var(--soc-line);color:var(--soc-ink3);line-height:1;white-space:nowrap}
.wrow .diff.d-very-easy,.wrow .diff.d-easy{color:var(--soc-gn);border-color:rgba(61,220,132,.4);background:rgba(61,220,132,.08)}
.wrow .diff.d-medium{color:var(--soc-am);border-color:rgba(255,181,71,.4);background:rgba(255,181,71,.08)}
.wrow .diff.d-hard{color:var(--soc-rd);border-color:rgba(255,85,119,.4);background:rgba(255,85,119,.08)}
.wrow .diff.d-insane{color:var(--soc-vi);border-color:rgba(167,139,250,.4);background:rgba(167,139,250,.08)}
.wrow .cat{font-family:'JetBrains Mono',monospace;font-size:9.5px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--soc-ink3)}
.wrow:hover .cat{color:var(--soc-cy)}
.wrow .sum{font-size:11.5px;line-height:1.45;color:var(--soc-ink3);display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.wrow:hover .sum{color:var(--soc-ink2)}
.wrow .tags{display:flex;flex-wrap:wrap;gap:4px;padding-top:1px}
.wrow .tag{font-family:'JetBrains Mono',monospace;font-size:9px;letter-spacing:.02em;color:var(--soc-ink4);padding:2px 6px;border:1px solid var(--soc-line);border-radius:3px;background:rgba(0,0,0,.25);white-space:nowrap}
.wrow:hover .tag{border-color:var(--soc-line2);color:var(--soc-ink3)}
/* !important: the Rows / Grid views set .wrow's display with higher specificity,
   which used to leave filtered-out rows visible in those views */
.wrow.hidden,.pcard.all-hidden{display:none !important}

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
/* compact = collapse each card to a single line: index · name · open */
/* ── ROWS: one dense line per write-up (index · name · diff · category · tags) ── */
body.tw-rows .wlist{grid-template-columns:1fr;gap:0;padding:0;background:transparent}
body.tw-rows .wrow{display:flex;align-items:center;gap:12px;padding:7px 14px 7px 16px;border:none;border-bottom:1px solid var(--soc-line);border-radius:0}
body.tw-rows .wrow:hover{transform:none;box-shadow:none;background:rgba(34,225,255,.05)}
body.tw-rows .wrow .banner,body.tw-rows .wrow .bhead,body.tw-rows .wrow .bright,body.tw-rows .wrow .body{display:contents}
body.tw-rows .wrow .meta,body.tw-rows .wrow .sum{display:none}
body.tw-rows .wrow .ix{order:1;flex:0 0 auto}
body.tw-rows .wrow .diff{order:2;flex:0 0 auto;min-width:74px;text-align:center;font-size:9px;padding:3px 6px}
body.tw-rows .wrow .nm{order:3;margin-top:0;font-size:13px;font-weight:600;line-height:1.2;flex:0 1 auto;min-width:0;max-width:min(46vw,440px);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
body.tw-rows .wrow .cat{order:4;flex:0 1 auto;max-width:180px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:9px}
body.tw-rows .wrow .tags{order:5;flex:0 1 auto;max-width:min(30vw,340px);flex-wrap:nowrap;overflow:hidden;padding-top:0;-webkit-mask-image:linear-gradient(90deg,#000 86%,transparent);mask-image:linear-gradient(90deg,#000 86%,transparent)}
body.tw-rows .wrow .body{padding:0}
body.tw-rows .wrow .open-ic{order:6;flex:0 0 auto;margin-left:auto;width:20px;height:20px;font-size:10px}

/* ── GRID: 3-up mini cards (banner + category + tags, no summary) ── */
body.tw-grid .wlist{grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:8px}
body.tw-grid .wrow .banner{padding:10px 12px 11px}
body.tw-grid .wrow .nm{font-size:14px;margin-top:6px;white-space:normal;line-height:1.25;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
body.tw-grid .wrow .body{padding:9px 12px 11px}
body.tw-grid .wrow .sum{display:none}
body.tw-accent-bold .wrow::before{background:var(--soc-line2);width:3px}
body.tw-accent-bold .pcard.p-htb-sherlock .wrow::before{background:rgba(255,181,71,.5)}
body.tw-accent-bold .pcard.p-htb-machine  .wrow::before{background:rgba(217,119,87,.5)}
body.tw-accent-bold .pcard.p-btlo         .wrow::before{background:rgba(255,85,119,.5)}
body.tw-accent-bold .pcard.p-cd           .wrow::before{background:rgba(34,225,255,.5)}
body.tw-accent-bold .pcard.p-ld           .wrow::before{background:rgba(61,220,132,.5)}
body.tw-accent-bold .pcard.p-thm          .wrow::before{background:rgba(255,85,119,.5)}
body.tw-accent-bold .pcard.p-hacksmarter  .wrow::before{background:rgba(255,181,71,.5)}
body.tw-accent-bold .pcard.p-unlisted     .wrow::before{background:rgba(167,139,250,.5)}
body.tw-accent-bold .pcard.p-memlabs     .wrow::before{background:rgba(167,139,250,.5)}
body.tw-accent-bold .pcard.p-leveleffect     .wrow::before{background:rgba(167,139,250,.5)}

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

/* ─── light theme: swap the dark-only black/white overlays for palette surfaces ─── */
[data-theme="light"] .wlist{background:var(--soc-bg-2)}
[data-theme="light"] .wrow .banner{background:linear-gradient(180deg,rgba(15,98,254,.04),transparent)}
[data-theme="light"] .wrow .ix,[data-theme="light"] .wrow .tag,
[data-theme="light"] .wrow .open-ic,[data-theme="light"] .tw-seg,
[data-theme="light"] .tw-foot,[data-theme="light"] .tw-reset{background:var(--soc-bg-2)}
[data-theme="light"] .tw-toggle{background:var(--soc-line)}
[data-theme="light"] .wrow:hover .nm{color:var(--soc-cy2)}
[data-theme="light"] .tweak-toggle{box-shadow:0 6px 20px rgba(12,23,41,.12)}
[data-theme="light"] .tweak-toggle:hover,[data-theme="light"] .tweak-toggle.active{color:var(--soc-cy2)}
[data-theme="light"] #tw-panel{box-shadow:0 18px 50px rgba(12,23,41,.18)}

@media(max-width:820px){
  .pcard .ph-right{display:none}
  .wlist{grid-template-columns:1fr;padding:10px;gap:8px}
  .wrow{min-height:auto}
  .toolbar{flex-direction:column;align-items:stretch}
  .filters{margin-left:0}
  .search-wrap{max-width:none}
  #tw-panel{left:12px;right:12px;width:auto;bottom:12px}
}

/* ═══ Responsive pass ═══════════════════════════════════════════════════
   Tablet: 5 stat cells fill two full rows (3 + 2) instead of leaving a gap.
   Phone: compact hero, stats as one swipeable row, each filter group as one
   swipeable row, icon-only Tweaks button — first card moves from ~1.6
   screens down to the first screen. */
@media(max-width:767px){
  .page{padding:14px 16px 72px}
  .toolbar{gap:8px;margin:12px 0 14px}
  .search-wrap{min-width:0}
  .toolbar{display:block}
  .search-wrap{display:flex;max-width:none;margin-bottom:10px}
  .filters,.dfilters{display:flex;box-sizing:border-box;width:calc(100% + 32px);max-width:none;min-width:0;flex-wrap:nowrap;overflow-x:auto;scrollbar-width:none;margin:0 -16px 6px;padding:2px 16px;
    -webkit-mask-image:linear-gradient(90deg,#000 88%,transparent);mask-image:linear-gradient(90deg,#000 88%,transparent)}
  .filters::-webkit-scrollbar{display:none}
  .fchip,.dchip,.fchip-label{flex-shrink:0}
  .fchip-label{padding:0 4px 0 0}
  .tweak-toggle{width:42px;height:42px;padding:0;justify-content:center;font-size:0;bottom:14px;right:14px;border-radius:50%}
  .tweak-toggle::before{content:"⚙";font-size:17px;letter-spacing:0}
  .pcard summary{padding:11px 12px;gap:10px}
  .pcard summary>*{min-width:0}
  .pcard .ph-icon{width:32px;height:32px}
  .pcard .ph-icon.has-logo{width:auto;min-width:32px;padding:0 8px}
  .pcard .ph-logo{height:20px;max-width:96px}
  .pcard .psub{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .wlist{padding:8px;gap:8px}
  .wrow .banner{padding:10px 12px 11px}
  .wrow .body{padding:9px 12px 11px}
}
/* ═══ HOME — modelled on the portfolio home page ════════════════════════
   Colours come from theme variables (color-mix for tints) so the same rules
   serve the dark console and the Carbon light theme. */
.hm-hero{border:1px solid var(--soc-line2);border-radius:6px;overflow:hidden;margin-bottom:40px;
  background:linear-gradient(180deg,color-mix(in srgb,var(--soc-cy) 4%,transparent),transparent 40%),var(--soc-bg-1)}
.hm-strap{display:flex;align-items:center;gap:16px;padding:8px 18px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--soc-ink3);border-bottom:1px solid var(--soc-line);background:color-mix(in srgb,var(--soc-bg) 55%,transparent);white-space:nowrap;overflow:hidden}
.hm-strap b{color:var(--soc-ink2);font-weight:500}
.hm-strap .v{color:var(--soc-cy);font-weight:600}
.hm-strap .dim{color:var(--soc-ink4)}
.hm-strap-r{margin-left:auto}
.hm-id{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:22px;align-items:center;padding:20px 22px}
.hm-av{width:84px;height:84px;padding:5px;border:1px solid var(--soc-line2);border-radius:10px;background:var(--soc-bg-2);position:relative}
.hm-av::before,.hm-av::after{content:"";position:absolute;width:14px;height:14px;border:2px solid var(--soc-cy)}
.hm-av::before{top:-1px;left:-1px;border-right:none;border-bottom:none}
.hm-av::after{bottom:-1px;right:-1px;border-left:none;border-top:none}
.hm-av img{width:100%;height:100%;object-fit:cover;border-radius:6px;display:block}
.hm-title{font-size:30px;font-weight:800;letter-spacing:-.02em;color:var(--soc-ink);line-height:1.15;margin:0}
/* topics never break mid-name; every item carries its separator on the left,
   and the inner row is pulled left by that width so the separator at the start
   of a wrapped line falls outside the clipped box */
.hm-sub{font-family:'JetBrains Mono',monospace;font-size:12.5px;color:var(--soc-ink3);margin:6px 0 12px;letter-spacing:.02em;overflow:hidden}
.hm-sub-in{display:flex;flex-wrap:wrap;row-gap:2px;margin-left:-1.6em}
.hm-sub-in>span{white-space:nowrap;position:relative;padding-left:1.6em}
.hm-sub-in>span::before{content:"·";position:absolute;left:.55em;color:var(--soc-ink4)}
.hm-sub-in>.hm-sub-tail::before{content:"—";left:.5em}
.hm-chips{display:flex;flex-wrap:wrap;gap:8px}
.hm-kv{display:grid;grid-template-columns:auto auto;gap:6px 16px;margin:0;font-family:'JetBrains Mono',monospace;font-size:11.5px;align-self:start}
.hm-kv dt{color:var(--soc-ink4);letter-spacing:.08em;text-align:right}
.hm-kv dd{margin:0;color:var(--soc-ink);font-weight:600;max-width:240px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hm-kv dd a{color:var(--soc-cy)}
.hm-stats{display:grid;grid-template-columns:repeat(4,1fr);border-top:1px solid var(--soc-line)}
.hm-stat{padding:16px 20px;border-right:1px solid var(--soc-line);min-width:0}
.hm-stat:last-child{border-right:none}
.hm-stat-lbl{display:flex;align-items:center;gap:7px;font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--soc-ink3)}
.hm-stat-lbl::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--soc-cy)}
.hm-stat.am .hm-stat-lbl::before{background:var(--soc-am)}
.hm-stat.vi .hm-stat-lbl::before{background:var(--soc-vi)}
.hm-stat.gn .hm-stat-lbl::before{background:var(--soc-gn)}
.hm-stat-val{font-size:28px;font-weight:700;color:var(--soc-ink);margin:6px 0 10px;font-variant-numeric:tabular-nums;line-height:1}
.hm-stat-sub{font-family:'JetBrains Mono',monospace;font-size:10.5px;color:var(--soc-ink3);margin-top:8px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hm-bar{display:flex;gap:2px;height:5px;border-radius:3px;overflow:hidden;background:var(--soc-line)}
.hm-bar i{display:block;height:100%;min-width:3px}

/* section header: cyan tick · spaced caps · dim right-hand path */
.hm-sec{display:flex;align-items:baseline;gap:12px;margin:0 0 16px;padding-left:12px;border-left:3px solid var(--soc-cy)}
.hm-sec-t{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:700;letter-spacing:.22em;text-transform:uppercase;color:var(--soc-ink)}
.hm-sec-r{margin-left:auto;font-family:'JetBrains Mono',monospace;font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--soc-ink4);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}
.hm-sec-all{margin-top:48px;scroll-margin-top:64px}

.hm-split{display:grid;grid-template-columns:minmax(0,1.45fr) minmax(0,1fr);gap:28px;margin-bottom:48px}
.hm-col{min-width:0;display:flex;flex-direction:column}
.hm-feed{border:1px solid var(--soc-line);border-radius:6px;background:var(--soc-bg-1);overflow:hidden;flex:1;display:flex;flex-direction:column}
.hm-feed-row{flex:1;display:grid;grid-template-columns:104px minmax(0,1fr) auto;gap:16px;align-items:center;padding:11px 16px;border-bottom:1px solid var(--soc-line);color:inherit;text-decoration:none;transition:background .12s}
.hm-feed-row:last-child{border-bottom:none}
.hm-feed-row:hover{background:color-mix(in srgb,var(--soc-cy) 5%,transparent);text-decoration:none}
.hm-feed-tag{justify-content:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:9.5px}
.hm-feed-txt{display:flex;flex-direction:column;min-width:0}
.hm-feed-nm{font-size:14.5px;font-weight:600;color:var(--soc-ink);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hm-feed-row:hover .hm-feed-nm{color:var(--soc-cy)}
.hm-feed-sub{font-family:'JetBrains Mono',monospace;font-size:10.5px;color:var(--soc-ink3);margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hm-feed-plat{display:none}
.hm-feed-btn{font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:700;letter-spacing:.12em;color:var(--soc-cy);padding:5px 10px;border:1px solid color-mix(in srgb,var(--soc-cy) 45%,transparent);border-radius:3px;white-space:nowrap}
.hm-feed-row:hover .hm-feed-btn{background:color-mix(in srgb,var(--soc-cy) 12%,transparent)}

.hm-cov{border:1px solid var(--soc-line);border-left:3px solid var(--soc-cy);border-radius:6px;background:var(--soc-bg-1);padding:16px 18px;flex:1}
.hm-cov-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:12px}
.hm-cov-head2{margin:18px 0 10px}
.hm-cov-kicker{font-family:'JetBrains Mono',monospace;font-size:10.5px;font-weight:700;letter-spacing:.16em;color:var(--soc-cy)}
.hm-cov-row{display:grid;grid-template-columns:minmax(0,240px) minmax(0,1fr) 34px;gap:12px;align-items:center;padding:6px 0}
.hm-cov-nm{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--soc-ink2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hm-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.hm-cov-track{height:6px;border-radius:3px;background:var(--soc-line);overflow:hidden}
.hm-cov-track i{display:block;height:100%;border-radius:3px}
.hm-cov-n{font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--soc-ink);text-align:right;font-variant-numeric:tabular-nums}
.hm-dchips{display:flex;flex-wrap:wrap;gap:6px}
.hm-dchip{font-family:'JetBrains Mono',monospace;font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;padding:4px 9px;border:1px solid var(--soc-line);border-radius:3px;color:var(--soc-ink3)}
.hm-dchip b{color:var(--soc-ink);margin-left:4px}
.hm-dchip.d-very-easy{color:var(--soc-cy)}.hm-dchip.d-easy{color:var(--soc-gn)}.hm-dchip.d-medium{color:var(--soc-am)}.hm-dchip.d-hard{color:var(--soc-rd)}.hm-dchip.d-insane{color:var(--soc-vi)}

/* category matrix */
.hm-dom{margin-bottom:30px}
.hm-dom-h{display:flex;align-items:center;gap:12px;margin-bottom:12px;padding-left:12px;border-left:3px solid var(--dom)}
.hm-dom-t{font-family:'JetBrains Mono',monospace;font-size:11.5px;font-weight:700;letter-spacing:.2em;color:var(--dom);white-space:nowrap}
.hm-dom-tag{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--soc-ink3);white-space:nowrap}
.hm-dom-line{flex:1;height:1px;background:var(--soc-line);min-width:20px}
.hm-dom-n{font-family:'JetBrains Mono',monospace;font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--soc-ink4);white-space:nowrap}
.hm-dom.d0{--dom:var(--soc-cy)}.hm-dom.d1{--dom:var(--soc-gn)}.hm-dom.d2{--dom:var(--soc-vi)}.hm-dom.d3{--dom:var(--soc-rd)}
.hm-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px}
.hm-card{display:flex;flex-direction:column;gap:12px;text-align:left;font:inherit;color:inherit;cursor:pointer;
  padding:15px 16px 13px;border:1px solid var(--soc-line);border-top:2px solid color-mix(in srgb,var(--dom) 60%,transparent);border-radius:6px;background:var(--soc-bg-1);transition:border-color .15s,transform .15s}
.hm-card:hover{border-color:var(--dom);transform:translateY(-1px)}
.hm-card:focus-visible{outline:2px solid var(--dom);outline-offset:2px}
.hm-card-h{display:flex;align-items:center;gap:10px}
.hm-code{font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:700;letter-spacing:.08em;color:var(--dom);padding:3px 7px;border:1px solid color-mix(in srgb,var(--dom) 45%,transparent);background:color-mix(in srgb,var(--dom) 10%,transparent);border-radius:3px;white-space:nowrap}
.hm-card-t{font-size:15px;font-weight:700;color:var(--soc-ink);flex:1;min-width:0}
.hm-card-n{font-family:'JetBrains Mono',monospace;font-size:18px;font-weight:700;color:var(--soc-ink);font-variant-numeric:tabular-nums}
.hm-ev{display:flex;flex-wrap:wrap;gap:10px;align-items:baseline;padding-top:9px;border-top:1px solid var(--soc-line);font-family:'JetBrains Mono',monospace;font-size:10.5px;color:var(--soc-ink3)}
.hm-ev b{color:var(--soc-ink);font-weight:600}
.hm-ev-l{letter-spacing:.16em;color:var(--soc-ink4)}
.hm-minis{display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-top:10px}
.hm-minis-l{font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--soc-ink4);margin-right:4px}
.hm-mini{font:inherit;font-family:'JetBrains Mono',monospace;font-size:10.5px;color:var(--soc-ink3);padding:4px 9px;border:1px solid var(--soc-line);border-radius:3px;background:var(--soc-bg-1);cursor:pointer}
.hm-mini b{color:var(--soc-ink);margin-left:4px}
.hm-mini:hover{color:var(--dom);border-color:var(--dom)}
:is(.hm-card,.hm-mini).is-on{border-color:var(--dom);background:color-mix(in srgb,var(--dom) 8%,var(--soc-bg-1))}

/* active category pill in the toolbar */
.catpill{display:none;align-items:center;gap:8px;font:inherit;font-family:'JetBrains Mono',monospace;font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;font-weight:600;padding:5px 11px;border:1px solid var(--soc-cy);border-radius:4px;color:var(--soc-cy);background:color-mix(in srgb,var(--soc-cy) 8%,transparent);cursor:pointer}
.catpill.show{display:inline-flex}
.catpill .x{font-size:13px;line-height:1}

@media(max-width:1279px){
  .hm-split{grid-template-columns:1fr}
}
@media(max-width:1023px){
  .hm-id{grid-template-columns:auto minmax(0,1fr)}
  .hm-kv{grid-column:1/-1;grid-template-columns:repeat(4,auto);justify-content:start;gap:4px 12px;padding-top:12px;border-top:1px dashed var(--soc-line)}
  .hm-kv dt{text-align:left}
  .hm-stats{grid-template-columns:repeat(2,1fr)}
  .hm-stat:nth-child(2){border-right:none}
  .hm-stat:nth-child(-n+2){border-bottom:1px solid var(--soc-line)}
}
@media(max-width:767px){
  .hm-hero{margin-bottom:20px}
  .hm-strap{padding:6px 14px;gap:12px;font-size:10.5px}
  .hm-strap .seg:nth-child(n+3){display:none}
  .hm-id{gap:14px;padding:16px}
  .hm-av{width:58px;height:58px;padding:4px}
  .hm-title{font-size:21px}
  .hm-sub{font-size:11px;margin:4px 0 10px;row-gap:3px}
  .hm-chips .sev:nth-child(3){display:none}
  .hm-kv{display:none}
  .hm-sub .hm-sub-tail{display:none}
  .hm-feed-btn{padding:4px 8px;font-size:9.5px}
  .hm-stat{padding:12px 14px}
  .hm-stat-val{font-size:22px;margin:4px 0 8px}
  .hm-split{gap:20px;margin-bottom:26px}
  .hm-sec-r{display:none}
  /* phones: one text column; platform moves into the sub line, the whole row is the link */
  .hm-feed-row{grid-template-columns:minmax(0,1fr);padding:11px 14px}
  .hm-feed-tag,.hm-feed-btn{display:none}
  .hm-feed-plat{display:inline;color:var(--soc-ink2)}
  .hm-cov{padding:14px}
  .hm-cov-row{grid-template-columns:minmax(0,130px) minmax(0,1fr) 30px;gap:10px}
  .hm-dom-tag,.hm-dom-line{display:none}
  body.tw-rows .wrow .cat,body.tw-rows .wrow .tags{display:none}
  body.tw-rows .wrow .nm{max-width:none;flex:1 1 auto}
  .hm-dom-n{margin-left:auto}
  /* compact matrix on phones: 2-up, title + count + difficulty bar only */
  .hm-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
  .hm-card{padding:11px 12px 12px;gap:9px}
  .hm-card:hover{transform:none}
  .hm-code,.hm-ev{display:none}
  .hm-card-h{align-items:flex-start;gap:8px}
  .hm-card-t{font-size:13px;line-height:1.3}
  .hm-card-n{font-size:15px}
}
"""

# ─────────────────────────────────────────────────────────────────────────────
# JS — theme switch, UTC clock, TOC scroll-spy, reading progress
# Plain-JS port of the portfolio's themes/soc-theme.js + soc-nav.js. Uses the
# same 'soc-theme' localStorage key; each domain still remembers its own choice
# because storage is per-origin.
# ─────────────────────────────────────────────────────────────────────────────

# Inline in <head> so data-theme is set before first paint (no flash).
THEME_INIT_JS = ("<script>try{var d=document.documentElement;"
                 "d.setAttribute('data-theme',localStorage.getItem('soc-theme')||'dark');"
                 "d.setAttribute('data-answers',localStorage.getItem('wu-answers')||'hidden')"
                 "}catch(e){}</script>")

# Runs right after the article is parsed, before first paint, so a reader who
# chose "shown" never sees the answers flash closed. <details> can only be
# opened from script — CSS cannot force it.
OPEN_ANSWERS_JS = ("<script>if(document.documentElement.getAttribute('data-answers')==='shown')"
                   "[].forEach.call(document.querySelectorAll('.wu-body details'),"
                   "function(d){d.open=true})</script>")

SITE_JS = r"""(function(){
  var KEY='soc-theme', root=document.documentElement;
  function get(){try{return localStorage.getItem(KEY)||'dark'}catch(e){return 'dark'}}
  function set(t){try{localStorage.setItem(KEY,t)}catch(e){} root.setAttribute('data-theme',t)}
  document.addEventListener('click',function(e){
    if(e.target.closest && e.target.closest('.soc-theme-btn')) set(get()==='dark'?'light':'dark');
  });

  /* answers switch: remembered site-wide, sets the starting state of every
     answer block; each block can still be opened / closed on its own */
  var AKEY='wu-answers';
  function aget(){try{return localStorage.getItem(AKEY)||'hidden'}catch(e){return 'hidden'}}
  document.addEventListener('click',function(e){
    if(!(e.target.closest && e.target.closest('.wu-ans-btn'))) return;
    var next=aget()==='shown'?'hidden':'shown';
    try{localStorage.setItem(AKEY,next)}catch(e){}
    root.setAttribute('data-answers',next);
    var ds=document.querySelectorAll('.wu-body details');
    for(var i=0;i<ds.length;i++) ds[i].open=(next==='shown');
  });

  /* live UTC clock, same format as the portfolio's SocClock */
  var clocks=document.querySelectorAll('[data-clock]');
  function p2(n){return (n<10?'0':'')+n}
  function tick(){
    var d=new Date(), s=d.getUTCFullYear()+'-'+p2(d.getUTCMonth()+1)+'-'+p2(d.getUTCDate())+
      ' · '+p2(d.getUTCHours())+':'+p2(d.getUTCMinutes())+':'+p2(d.getUTCSeconds())+'Z';
    for(var i=0;i<clocks.length;i++) clocks[i].textContent=s;
  }
  if(clocks.length){tick();setInterval(tick,1000)}

  var art=document.querySelector('.soc-article'); if(!art) return;
  var body=art.querySelector('.wu-body'); if(!body) return;
  var toc=art.querySelector('.wu-toc');
  var items=[].slice.call(art.querySelectorAll('.wu-toc a[href^="#"]')).map(function(a){
    var id=decodeURIComponent(a.getAttribute('href').slice(1));
    return {a:a, el:document.getElementById(id)};
  }).filter(function(x){return x.el});

  var bar=document.createElement('div'); bar.className='soc-read-bar'; bar.innerHTML='<i></i>';
  art.parentNode.insertBefore(bar, art.nextSibling);
  var tb=document.querySelector('.soc-tb');
  var barFill=bar.firstChild, pct=art.querySelector('.soc-read-pct'),
      track=art.querySelector('.soc-read-track > i'), now=art.querySelector('.soc-read-now');
  var top=art.querySelector('[data-top]');
  if(top) top.addEventListener('click',function(){window.scrollTo({top:0,behavior:'smooth'})});

  var active=null, queued=false;
  function update(){
    queued=false;
    if(tb) bar.style.top=tb.getBoundingClientRect().height+'px';
    var r=body.getBoundingClientRect(), span=r.height-window.innerHeight;
    var f=span>0?Math.min(1,Math.max(0,-r.top/span)):1;
    var w=(f*100).toFixed(1)+'%';
    barFill.style.width=w; if(track) track.style.width=w;
    if(pct) pct.textContent=Math.round(f*100)+'%';
    var cur=null;
    for(var i=0;i<items.length;i++){ if(items[i].el.getBoundingClientRect().top<Math.max(120,window.innerHeight*0.3)) cur=items[i]; else break; }
    if(!cur && items.length) cur=items[0];
    if(cur!==active){
      if(active) active.a.classList.remove('is-active');
      active=cur;
      if(cur){
        cur.a.classList.add('is-active');
        if(now) now.innerHTML=cur.a.innerHTML;
        if(toc && toc.scrollHeight>toc.clientHeight){
          var o=cur.a.offsetTop;
          if(o<toc.scrollTop+20||o>toc.scrollTop+toc.clientHeight-40) toc.scrollTop=o-toc.clientHeight/2;
        }
      }
    }
  }
  function q(){if(!queued){queued=true;requestAnimationFrame(update)}}
  window.addEventListener('scroll',q,{passive:true});
  window.addEventListener('resize',q);
  update();
})();
"""

ANSWERS_BTN = ('<button class="wu-ans-btn" type="button" aria-label="Show or hide all answers by default" '
               'title="Start every write-up with answers shown or hidden">'
               '<span class="wu-ans-lbl"><span class="wu-ans-full">ANSWERS</span><span class="wu-ans-short">ANS</span></span>'
               '<span class="soc-tb-track"><span class="soc-tb-knob"></span></span>'
               '<span class="wu-ans-state"><span class="wu-ans-off">HIDDEN</span>'
               '<span class="wu-ans-on">SHOWN</span></span></button>')

THEME_BTN = ('<button class="soc-theme-btn" type="button" aria-label="Toggle light / dark theme">'
             '<span class="soc-tb-ico soc-tb-dark">☀︎</span><span class="soc-tb-ico soc-tb-light">☽</span>'
             '<span class="soc-tb-track"><span class="soc-tb-knob"></span></span>'
             '<span class="soc-tb-label"><span class="soc-tb-dark">LIGHT</span>'
             '<span class="soc-tb-light">DARK</span></span></button>')

# ─────────────────────────────────────────────────────────────────────────────
# Shared HTML pieces
# ─────────────────────────────────────────────────────────────────────────────

# ── Shared stylesheets ───────────────────────────────────────────────────────
# The CSS used to be inlined into all ~360 pages (~13.5 KB per write-up page,
# ~29 KB on the index). Emitting it once under build/assets/ lets the browser
# cache it across the whole site; the ?v= hash busts the cache on change.
_ASSET_HREFS: dict[str, str] = {}

PLATFORM_LOGO_SRC = SRC_DIR / "assets" / "platforms"
_PLATFORM_LOGOS: dict[str, tuple[str, int, int]] = {}      # file -> (href, width, height)

def _logo_size(path: Path) -> tuple[int, int]:
    """Natural size, so the <img> can reserve its box before the file loads."""
    if path.suffix.lower() == ".svg":
        head = path.read_text(encoding="utf-8", errors="replace")[:600]
        m = re.search(r'viewBox="[\d.\-]+[ ,]+[\d.\-]+[ ,]+([\d.]+)[ ,]+([\d.]+)"', head)
        if m:
            return round(float(m.group(1))), round(float(m.group(2)))
        return 0, 0
    try:
        from PIL import Image
        with Image.open(path) as im:
            return im.size
    except Exception:
        return 0, 0


def write_platform_logos() -> None:
    """Copy assets/platforms/* to build/assets/platforms/ (content-hashed URLs)."""
    global _PLATFORM_LOGOS
    _PLATFORM_LOGOS = {}
    if not PLATFORM_LOGO_SRC.is_dir():
        return
    dest = BUILD_DIR / "assets" / "platforms"
    ensure_build_path(dest)
    for src in sorted(PLATFORM_LOGO_SRC.iterdir()):
        if src.suffix.lower() not in (".svg", ".webp", ".png"):
            continue
        shutil.copy2(src, dest / src.name)
        digest = hashlib.sha1(src.read_bytes()).hexdigest()[:8]
        w, h = _logo_size(src)
        _PLATFORM_LOGOS[src.name] = (f"assets/platforms/{src.name}?v={digest}", w, h)


def write_assets() -> dict[str, str]:
    """Write shared CSS bundles and return {name: 'assets/x.css?v=hash'}."""
    global _ASSET_HREFS
    bundles = {
        "base":    TOKENS_CSS + TOPBAR_CSS + LIGHT_CARBON_CSS,
        "article": ARTICLE_CSS,
        "index":   INDEX_CSS,
    }
    assets_dir = BUILD_DIR / "assets"
    ensure_build_path(assets_dir)
    hrefs = {}
    for name, css in bundles.items():
        digest = hashlib.sha1(css.encode("utf-8")).hexdigest()[:8]
        (assets_dir / f"{name}.css").write_text(css, encoding="utf-8")
        hrefs[name] = f"assets/{name}.css?v={digest}"
    digest = hashlib.sha1(SITE_JS.encode("utf-8")).hexdigest()[:8]
    (assets_dir / "site.js").write_text(SITE_JS, encoding="utf-8")
    hrefs["site.js"] = f"assets/site.js?v={digest}"
    write_platform_logos()
    _ASSET_HREFS = hrefs
    return hrefs


def css_links(root_prefix: str, *names: str) -> str:
    """Stylesheets plus the theme bootstrap and the shared site script —
       every page calls this, so every page gets the theme switch."""
    links = [THEME_INIT_JS]
    links += [f'<link rel="stylesheet" href="{root_prefix}{_ASSET_HREFS[n]}">' for n in names]
    links.append(f'<script src="{root_prefix}{_ASSET_HREFS["site.js"]}" defer></script>')
    return "\n".join(links)


def common_head(title: str, description: str = "") -> str:
    title = html.escape(title, quote=True)
    description = html.escape(description, quote=True)
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


CRUMB_ROOT = (f'<a href="{PORTFOLIO_URL}">SOC</a> <span class="sep">/</span> '
              f'<a href="{PORTFOLIO_URL}">OPERATOR.PROFILE</a> <span class="sep">/</span> ')


def topbar(crumb_html: str, badges_html: str, clock_label: str = "", controls: str = "") -> str:
    """Same anatomy as the portfolio topbar: UPLINK (home link) · crumb ·
       badges · live UTC clock · theme switch. clock_label is only the no-JS
       fallback; site.js replaces it with the ticking clock."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return f"""<div class="soc-tb">
  <div class="soc-tb-row">
    <a class="soc-live" href="{PORTFOLIO_URL}" title="chicken0248.fyi">UPLINK</a>
    <span class="soc-crumb">{CRUMB_ROOT}{crumb_html}</span>
    <div class="soc-tb-right">
      <span class="soc-tb-badges">{badges_html}</span>
      <span class="soc-clock" data-clock>{clock_label or today}</span>
      {controls}{THEME_BTN}
    </div>
  </div>
</div>"""


def article_footer(index_href: str) -> str:
    return f"""<footer class="foot">
  <a href="{index_href}">← All Write-Ups</a>
  <span class="sep">·</span>
  <a href="{PORTFOLIO_URL}">Portfolio ↗</a>
  <span class="sep">·</span>
  <a href="{REPO_URL}" target="_blank" rel="noopener noreferrer">GitHub ↗</a>
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
    # Write-ups are screenshot-heavy (20-60 images each); defer offscreen loads.
    html_body = html_body.replace('<img ', '<img loading="lazy" decoding="async" ')
    return html_body


_RES_REF_RE = re.compile(r'(?:src|href)="(?:\.{1,2}/)*resources/([^"?#]+)')

def collect_resource_refs(html_body: str, sink: set):
    """Record which files under resources/ a rendered page actually needs."""
    for m in _RES_REF_RE.finditer(html_body):
        sink.add(m.group(1))


# Block-level tags the write-ups wrap content in. Inline tags (<b>, <span>…)
# are left alone — markdown already processes their contents.
#
# <details>/<summary> are deliberately absent: markdown2 does not treat them as
# block tags, so the attribute was never consumed and leaked into the page as
# literal markdown="1". Their contents are answer blocks (<pre><code>), which
# must stay literal anyway. See _unwrap_details_paragraphs for the other half.
_BLOCK_TAG_RE = re.compile(
    r'<(div|center|blockquote|td|th)\b(?![^>]*\bmarkdown\s*=)([^>]*?)(/?)>',
    re.IGNORECASE)

_DETAILS_OPEN_P_RE  = re.compile(
    r'<p>(<details\b[^>]*>\s*<summary\b[^>]*>.*?</summary>)</p>', re.DOTALL)
_DETAILS_CLOSE_P_RE = re.compile(r'<p>\s*(</details>)\s*</p>')

def _unwrap_details_paragraphs(html_body: str) -> str:
    """markdown2 sees <details>/<summary> as inline HTML, so it wraps the
       opening pair and the closing tag in stray <p>…</p>. Browsers repair it
       silently, but it leaves an empty paragraph and invalid nesting."""
    html_body = _DETAILS_OPEN_P_RE.sub(r'\1', html_body)
    return _DETAILS_CLOSE_P_RE.sub(r'\1', html_body)

_DETAILS_BEFORE_RE = re.compile(r'(?<=[^\n])\n(?=[ \t]*<details\b)')
_DETAILS_AFTER_RE  = re.compile(r'(</details>[ \t]*)\n(?=[^\n])')

def _space_details(md: str) -> str:
    """Put a blank line before and after every <details> block.

       Without it markdown2 folds the tag into the neighbouring paragraph (or,
       after a "> question" line, into the blockquote), leaving stray <p> tags
       and — for a blockquote — the answer rendered inside the question box.
       Fenced code is left untouched."""
    parts = re.split(r'(^```.*?^```)', md, flags=re.MULTILINE | re.DOTALL)
    for i in range(0, len(parts), 2):                  # even = outside a fence
        parts[i] = _DETAILS_AFTER_RE.sub(r'\1\n\n',
                    _DETAILS_BEFORE_RE.sub('\n\n', parts[i]))
    return "".join(parts)


def _enable_markdown_in_blocks(md: str) -> str:
    """Tag raw block-level HTML so markdown2 processes the markdown inside it.

       Code fences are left untouched — a <div> shown as example code must stay
       literal."""
    parts = re.split(r'(^```.*?^```)', md, flags=re.MULTILINE | re.DOTALL)
    out = []
    for i, part in enumerate(parts):
        if i % 2 == 1:                       # inside a fenced block
            out.append(part)
        else:
            out.append(_BLOCK_TAG_RE.sub(r'<\1\2 markdown="1"\3>', part))
    return "".join(out)


# Joplin stamps exports with two lines near the top, then a rule:
#     Created: 18/05/2024 14:06
#     Last Updated: 04/06/2024 08:30
#     * * *
# On the page they read as a stray paragraph, so they are lifted out of the
# body and shown in the info box instead. Dates are DD/MM/YYYY.
_STAMP_RE = re.compile(
    r'^Created:[ \t]*(?P<c>[^\n]*)\n(?:Last Updated:[ \t]*(?P<u>[^\n]*)\n)?'
    r'(?:[ \t]*(?:\* \* \*|\*\*\*|---)[ \t]*\n)?', re.MULTILINE)
_DMY_RE = re.compile(r'(\d{1,2})/(\d{1,2})/(\d{4})')


def _iso(stamp: str) -> str:
    m = _DMY_RE.search(stamp or "")
    return f"{m.group(3)}-{int(m.group(2)):02d}-{int(m.group(1)):02d}" if m else ""


# CyberDefenders write-ups quote the platform's own labels right after it:
#     >Category: Endpoint Forensics
#     >Tags: Disk, Linux, FTK, T1496
#     * * *
# Same treatment: lifted into the info box as "Lab category" / "Lab tags".
_LABMETA_RE = re.compile(
    r'^>[ \t]*Category:[ \t]*(?P<c>[^\n]*)\n>[ \t]*Tags:[ \t]*(?P<t>[^\n]*)\n'
    r'(?:[ \t]*(?:\* \* \*|\*\*\*|---)[ \t]*\n)?', re.MULTILINE)


def _top_of(md: str, lines: int = 12) -> int:
    end = 0
    for _ in range(lines):
        nl = md.find("\n", end)
        if nl < 0:
            return len(md)
        end = nl + 1
    return end


def _split_lab_meta(md: str) -> tuple[str, dict]:
    m = _LABMETA_RE.search(md, 0, _top_of(md) + 400)
    if not m or m.start() > _top_of(md):
        return md, {}
    tags = [t.strip() for t in m.group("t").split(",") if t.strip()]
    return md[:m.start()] + md[m.end():], {"lab_category": m.group("c").strip(), "lab_tags": tags}


def _split_stamp(md: str) -> tuple[str, dict]:
    """Remove the Joplin Created/Last Updated block if it sits in the first
       few lines; return the markdown and {'created', 'updated'} ISO dates."""
    head_end = 0
    for _ in range(10):                      # only look near the top
        nl = md.find("\n", head_end)
        if nl < 0:
            break
        head_end = nl + 1
    m = _STAMP_RE.search(md, 0, head_end + 200)
    if not m or m.start() > head_end:
        return md, {}
    return md[:m.start()] + md[m.end():], {"created": _iso(m.group("c")),
                                           "updated": _iso(m.group("u"))}


def md_to_html(md_path: Path, out_path: Path, res_sink: set | None = None):
    """Render one markdown write-up to a styled HTML file."""
    # 1. Read markdown
    try:
        md_content = md_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        md_content = md_path.read_text(encoding="latin-1")

    # 2. Convert to HTML body
    #
    # Joplin exports centre screenshots by wrapping them in raw HTML, e.g.
    #     <div align=center>
    #     ![shot.png](/resources/shot.png)
    #     </div>
    # Markdown leaves the contents of a block-level HTML tag alone, so those
    # images were emitted as literal "![shot.png](...)" text on the page — 205
    # of them across 56 write-ups. markdown2 will process the contents when the
    # tag carries markdown="1", so inject that and enable the extra.
    md_body, stamp = _split_stamp(md_content)
    md_body, lab_meta = _split_lab_meta(md_body)
    stamp.update(lab_meta)
    html_body = markdown2.markdown(
        _enable_markdown_in_blocks(_space_details(md_body)),
        extras=["fenced-code-blocks", "tables", "header-ids", "strike",
                "markdown-in-html"]
    )
    html_body = _unwrap_details_paragraphs(html_body)

    # 3. Path fix-ups
    parts = md_path.parent.relative_to(SRC_DIR).parts
    depth = len(parts)
    root_prefix = "../" * depth if depth > 0 else "./"
    html_body = rewrite_image_paths(html_body, root_prefix)
    if res_sink is not None:
        collect_resource_refs(html_body, res_sink)

    # Cloudflare Pages serves foo.html at /foo and 308-redirects /foo.html to
    # it, so linking with the extension costs a redirect on every click. Link
    # to the canonical extension-less form instead. "/" is the index.
    index_href = "/"

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
    crumb_parts = [f'<a href="{index_href}"><b>WRITE-UPS</b></a>',
                   '<span class="sep">/</span>',
                   f'<b>{plat["short"]}</b>',
                   '<span class="sep">/</span>',
                   f'<b class="here">{html.escape(title.upper())}</b>']
    crumb_html = " ".join(crumb_parts)

    badges_html = (
        f'<span class="sev cyan"><span class="dot"></span>TLP:CLEAR</span> '
        f'<span class="sev {plat["sev"]}"><span class="dot"></span>{plat["short"]}</span> '
        f'<span class="sev green"><span class="dot"></span>SOLVED</span> '
        f'<a class="sev-link" href="{REPO_URL}" target="_blank" rel="noopener noreferrer">GITHUB <span class="ar">↗</span></a>'
    )

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    clock_label = f"CASE · {today}"

    description = f"Write-up for {title} — a {plat['long']} challenge solution by {AUTHOR}."

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
{common_head(title, description=description)}
{css_links(root_prefix, "base", "article")}
</head>
<body class="{plat['class']}">

{topbar(crumb_html, badges_html, clock_label, ANSWERS_BTN if "<details" in html_body else "")}

{article_shell(html_body, title, plat, _meta_for(md_path), index_href, stamp, steps="LetsDefend Alert" in folder_str)}
{OPEN_ANSWERS_JS if "<details" in html_body else ""}

{article_footer(index_href)}

</body>
</html>
"""

    ensure_build_path(out_path.parent)
    out_path.write_text(page, encoding="utf-8")


_H1_RE      = re.compile(r'<h1\b[^>]*>.*?</h1>', re.DOTALL)
_H1_LINK_RE = re.compile(r'<a\b[^>]*\bhref="([^"]+)"')
_HEAD_RE    = re.compile(r'<h([23])\b[^>]*\bid="([^"]+)"[^>]*>(.*?)</h\1>', re.DOTALL)


def _plain(fragment: str) -> str:
    """Heading HTML → escaped plain text for the TOC."""
    return html.escape(html.unescape(re.sub(r'<[^>]+>', '', fragment)).strip())


_QPREFIX_RE = re.compile(r'^(?:Q(?:uestion)?\s*(\d+)|Task\s*(\d+))\s*[:.)\-]?\s*', re.IGNORECASE)

# One pass over the body in document order: h2/h3 headings and blockquotes.
_TOC_WALK_RE = re.compile(
    r'<h(?P<lv>[23])\b[^>]*\bid="(?P<id>[^"]+)"[^>]*>(?P<h>.*?)</h(?P=lv)>'
    r'|<blockquote>(?P<bq>\s*<p>(?P<q>.*?)</p>)', re.DOTALL)


def _build_toc(html_body: str, steps: bool = False) -> tuple[str, str]:
    """Rail TOC for a write-up, in document order: numbered h2s, h3s, and the
       lab's questions nested under the heading they sit in.

       Q&A labs put each question in a blockquote rather than a heading. A
       blockquote counts as a question when it starts with Q1 / Question 1 /
       Task 1 or ends with "?". With `steps` (LetsDefend alert playbooks, whose
       steps are blockquotes like "Collect Data"), every blockquote after the
       first heading counts, labelled S1, S2…. Questions get id="q-N" so the
       rail can link to them and the scroll-spy can track them.

       h2 numbers match the CSS counter on h2 (Joplin's own "Table of Contents"
       heading is skipped by both). Pages with almost no headings get a
       questions-only rail. Returns ("", body) when neither is useful."""
    items, n_h2, n_h, n_q = [], 0, 0, 0
    seen_heading = False
    tag = "S" if steps else "Q"

    def visit(m):
        nonlocal n_h2, n_h, n_q, seen_heading
        if m.group("lv"):
            hid = m.group("id")
            if hid.startswith("table-of-contents"):
                return m.group(0)
            text = _plain(m.group("h"))
            if not text:
                return m.group(0)
            seen_heading = True
            n_h += 1
            if m.group("lv") == "2":
                n_h2 += 1
                items.append(("h2", f'<a class="wu-toc-item" href="#{hid}"><span class="wu-toc-num">{n_h2:02d}.</span><span>{text}</span></a>'))
            else:
                items.append(("h3", f'<a class="wu-toc-item sub" href="#{hid}"><span>{text}</span></a>'))
            return m.group(0)
        text = html.unescape(re.sub(r'<[^>]+>', '', m.group("q"))).strip()
        is_q = bool(_QPREFIX_RE.match(text)) or text.endswith("?") or (steps and seen_heading)
        if not is_q or not text:
            return m.group(0)
        n_q += 1
        label = html.escape(_QPREFIX_RE.sub("", text, count=1) or text)
        items.append(("q", f'<a class="wu-toc-item q" href="#q-{n_q}"><span class="wu-toc-num">{tag}{n_q}</span><span>{label}</span></a>'))
        return f'<blockquote id="q-{n_q}">{m.group("bq")}'

    new_body = _TOC_WALK_RE.sub(visit, html_body)

    if n_h2 >= 2 or n_h >= 3:                      # headings, questions nested
        title, cls, entries = "// Table of contents", "wu-toc", [e for _, e in items]
    elif n_q >= 3:                                 # questions only
        title = "// Steps" if steps else "// Questions"
        cls, entries = "wu-toc wu-toc-q", [e for k, e in items if k == "q"]
    else:
        return "", html_body
    if n_q == 0:
        new_body = html_body
    return (f'<nav class="{cls}" aria-label="Table of contents">\n'
            f'    <div class="wu-toc-title">{title}</div>\n    '
            + "\n    ".join(entries) + "\n  </nav>"), new_body


def article_shell(html_body: str, title: str, plat: dict, meta: dict, index_href: str,
                  stamp: dict | None = None, steps: bool = False) -> str:
    """Header + info box + TOC rail + body, in the order the CSS grid expects
       (head > meta > toc > body) — the same shape as the portfolio's
       .soc-article (cover > meta > toc > sections)."""
    m = _H1_RE.search(html_body)
    if m:
        h1 = m.group(0)
        html_body = html_body[:m.start()] + html_body[m.end():]
    else:
        h1 = f"<h1>{html.escape(title)}</h1>"
    link = _H1_LINK_RE.search(h1)

    dek = (meta.get("summary") or "").strip()
    head = ('<header class="content wu-head">\n' + h1 +
            (f'\n<p class="wu-dek">{html.escape(dek)}</p>' if dek else "") + "\n</header>")

    def cell(label, value, cls=""):
        return f'<div class="{cls}"><div class="wu-meta-lbl">{label}</div>{value}</div>'

    cells = [cell("Author", f'<div class="wu-meta-val">{AUTHOR}</div>'),
             cell("Platform", f'<div class="wu-meta-val">{html.escape(plat["long"])}</div>')]
    diff = meta.get("difficulty") or ""
    if diff and diff != "Unknown":
        cells.append(cell("Difficulty",
                          f'<span class="wu-diff d-{_diff_slug(diff)}">{html.escape(diff)}</span>'))
    stamp = stamp or {}
    if stamp.get("created"):
        cells.append(cell("Written", f'<div class="wu-meta-val">{stamp["created"]}</div>'))
    if stamp.get("updated") and stamp["updated"] != stamp.get("created"):
        cells.append(cell("Updated", f'<div class="wu-meta-val">{stamp["updated"]}</div>'))
    if meta.get("category"):
        cells.append(cell("Category", f'<div class="wu-meta-val">{html.escape(meta["category"])}</div>'))
    if link:
        cells.append(cell("Lab", f'<a class="wu-meta-link" href="{link.group(1)}" target="_blank" '
                                 f'rel="noopener noreferrer">Open on platform ↗</a>'))
    lab_cat = stamp.get("lab_category", "")
    if lab_cat and lab_cat.lower() != (meta.get("category") or "").lower():
        cells.append(cell("Lab category", f'<div class="wu-meta-val">{html.escape(lab_cat)}</div>'))
    if meta.get("tags"):
        chips = "".join(f'<span class="wu-tag">{html.escape(t)}</span>' for t in meta["tags"])
        cells.append(cell("Tags", f'<div class="wu-tags">{chips}</div>', "wu-meta-wide"))
    seen = {t.lower() for t in (meta.get("tags") or [])}
    lab_tags = [t for t in stamp.get("lab_tags", []) if t.lower() not in seen]
    if lab_tags:
        chips = "".join(f'<span class="wu-tag">{html.escape(t)}</span>' for t in lab_tags)
        cells.append(cell("Lab tags", f'<div class="wu-tags">{chips}</div>', "wu-meta-wide"))
    cells.append('<div class="soc-read-card">'
                 '<div class="soc-read-head">Reading progress <span class="soc-read-pct">0%</span></div>'
                 '<div class="soc-read-track"><i></i></div>'
                 '<div class="soc-read-now"></div>'
                 '<div class="soc-read-links"><button type="button" data-top>↑ Back to top</button>'
                 f'<a href="{index_href}">← All write-ups</a></div></div>')
    meta_html = '<aside class="wu-meta">\n    ' + "\n    ".join(cells) + "\n  </aside>"

    toc, html_body = _build_toc(html_body, steps)
    cls = "soc-article has-toc" if toc else "soc-article"
    return f"""<main class="{cls}">
  {head}
  {meta_html}
  {toc}
  <article class="content wu-body">
{html_body}
  </article>
</main>"""


def _escape_attr(s: str) -> str:
    return s.replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')


def _strip_platform_prefix(name: str) -> str:
    """Remove leading [Platform Write-up] bracket from display names."""
    return re.sub(r'^\[[^\]]*\]\s*', '', name)


# ── Sidecar metadata (difficulty / category / tags / summary) ────────────────
# writeups_meta.json is keyed by each md file's posix path relative to SRC_DIR.
# Generated once and curated by hand; missing entries degrade gracefully.
_META_CACHE = None

def _load_meta() -> dict:
    global _META_CACHE
    if _META_CACHE is None:
        p = SRC_DIR / "writeups_meta.json"
        try:
            _META_CACHE = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            _META_CACHE = {}
    return _META_CACHE

def _meta_for(md_path: Path) -> dict:
    key = md_path.relative_to(SRC_DIR).as_posix()
    return _load_meta().get(key, {})

def _diff_slug(diff: str) -> str:
    return re.sub(r'[^a-z]+', '-', (diff or '').lower()).strip('-')

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
    # Branded collections stored under Unlisted Labs are platforms in their own
    # right, so do not present them as living "inside" Unlisted.
    if detect_platform(folder_str)["class"] in ("p-memlabs", "p-leveleffect"):
        folder_str = folder_str.split("/", 1)[1] if "/" in folder_str else folder_str
    return folder_str.replace("/", " → ")


def _panel_html(group_folder: str, md_files: list) -> str:
    plat = detect_platform(group_folder)
    klass = plat["class"]
    icon = plat["icon"]
    logo = _PLATFORM_LOGOS.get(plat.get("logo", ""))
    if logo:
        href, lw, lh = logo
        size = f' width="{lw}" height="{lh}"' if lw and lh else ""
        # alt="" — the platform name is printed right beside it.
        icon_html = (f'<div class="ph-icon has-logo"><img class="ph-logo" src="{href}" alt=""'
                     f'{size} decoding="async"></div>')
    else:
        icon_html = f'<div class="ph-icon">{icon}</div>'
    long_name = plat["long"]
    short_label = plat["short"]
    sev_class = plat["sev"]

    breadcrumb = _panel_breadcrumb(group_folder)
    count = len(md_files)

    rows_html = []
    for i, md_path in enumerate(sorted(md_files, key=lambda p: p.stem), start=1):
        name = _strip_platform_prefix(md_path.stem)
        # Extension-less: Cloudflare Pages serves foo.html at /foo and
        # 308-redirects /foo.html, so keeping .html here would cost a redirect
        # on every card click.
        href = md_path.relative_to(SRC_DIR).with_suffix("").as_posix()
        # percent-encode everything unsafe in a URL path (spaces, #, [], &, %...)
        href_safe = html.escape(quote(href, safe="/"), quote=True)

        meta = _meta_for(md_path)
        difficulty = (meta.get("difficulty") or "").strip()
        category   = (meta.get("category") or "").strip()
        summary    = (meta.get("summary") or "").strip()
        tags       = [t for t in (meta.get("tags") or []) if t][:5]
        dslug      = _diff_slug(difficulty)

        diff_pill = ""
        if difficulty and difficulty.lower() != "unknown":
            diff_pill = f'<span class="diff d-{dslug}">{html.escape(difficulty)}</span>'
        cat_html  = f'<div class="cat">{html.escape(category)}</div>' if category else ""
        sum_html  = f'<div class="sum">{html.escape(summary)}</div>' if summary else ""
        tags_html = ""
        if tags:
            chips = "".join(f'<span class="tag">{html.escape(t)}</span>' for t in tags)
            tags_html = f'<div class="tags">{chips}</div>'

        # searchable blob: name + category + tags + summary + difficulty
        blob = " ".join([name, category, " ".join(tags), summary, difficulty]).lower()
        blob_attr = html.escape(blob, quote=True)

        rows_html.append(f"""
        <a class="wrow" href="{href_safe}" data-name="{html.escape(name.lower(), quote=True)}" data-search="{blob_attr}" data-diff="{dslug}" data-cat="{_cat_slug(category or 'Uncategorised')}">
          <div class="banner">
            <div class="bhead">
              <span class="ix">#{i:03d}</span>
              <span class="meta"><span class="dot"></span>{short_label}</span>
              <span class="bright">{diff_pill}<span class="open-ic">↗</span></span>
            </div>
            <div class="nm" title="{html.escape(name, quote=True)}">{html.escape(name)}</div>
          </div>
          <div class="body">
            {cat_html}
            {sum_html}
            {tags_html}
          </div>
        </a>""")

    return f"""<details class="pcard {klass}" data-platform="{klass}">
  <summary>
    {icon_html}
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


# ─────────────────────────────────────────────────────────────────────────────
# Index — home sections modelled on the portfolio home page
#   hero (operator card: strap · avatar · title · chips · key/value list ·
#   4 stat cells with distribution bars) → Recent write-ups feed + Coverage
#   panel → Category matrix (click a card to filter the list below).
# ─────────────────────────────────────────────────────────────────────────────

# Category → domain, in display order. Categories missing here fall into the
# last domain so a new category never disappears from the matrix.
CATEGORY_DOMAINS = [
    ("FORENSICS", "acquire · parse · reconstruct",
     ["Windows DFIR", "Memory Forensics", "Linux DFIR", "Mobile Forensics",
      "Disk Forensics", "Endpoint Forensics", "Digital Forensics"]),
    ("DETECTION & RESPONSE", "detect · investigate · respond",
     ["Network Forensics", "Incident Response", "Email / Phishing", "Log Analysis",
      "Threat Intel", "Cloud Security", "Threat Hunting", "Security Operations", "OSINT"]),
    ("MALWARE & RE", "unpack · decode · attribute",
     ["Malware Analysis", "Reverse Engineering"]),
    ("OFFENSE", "break in · escalate · own",
     ["AD / Kerberos", "Web Exploitation", "Windows Privesc", "Linux Privesc"]),
]
MATRIX_MIN_CARD = 4          # smaller categories render as chips under the domain

# Bar / dot colour per platform class (CSS custom properties, theme-aware)
PLAT_COLOR = {
    "p-cd": "var(--soc-cy)", "p-ld": "var(--soc-gn)", "p-btlo": "var(--soc-rd)",
    "p-htb-sherlock": "var(--soc-am)", "p-htb-machine": "var(--machine-kicker)",
    "p-thm": "var(--soc-vi)", "p-hacksmarter": "var(--plat-pink)",
    "p-unlisted": "var(--soc-ink4)",
    "p-memlabs": "var(--soc-vi)", "p-leveleffect": "var(--soc-cy2)",
}
# Short platform codes for dense spots (evidence lines, hero chip). HTB's two
# folders share one code, so their counts merge.
PLAT_ABBR = {"p-cd": "CD", "p-ld": "LD", "p-btlo": "BTLO", "p-htb-sherlock": "HTB",
             "p-htb-machine": "HTB", "p-thm": "THM", "p-hacksmarter": "HS", "p-unlisted": "CTF",
             "p-memlabs": "ML", "p-leveleffect": "LE"}
DIFF_COLOR = {"very-easy": "var(--soc-cy)", "easy": "var(--soc-gn)",
              "medium": "var(--soc-am)", "hard": "var(--soc-rd)", "insane": "var(--soc-vi)"}


def _cat_slug(cat: str) -> str:
    return re.sub(r'[^a-z0-9]+', '-', cat.lower()).strip('-') or "uncategorised"


def _bar(parts: list) -> str:
    """parts: [(value, css colour, title)] → one segmented distribution bar."""
    total = sum(v for v, _, _ in parts) or 1
    segs = "".join(
        f'<i style="flex:{v};background:{c}" title="{html.escape(t)} · {v}"></i>'
        for v, c, t in parts if v)
    return f'<div class="hm-bar" aria-hidden="true">{segs}</div>'


def _entries(md_files: list) -> list:
    out = []
    for f in md_files:
        folder = _platform_group_key(f)
        plat = detect_platform(folder)
        meta = _meta_for(f)
        out.append({
            "name": _strip_platform_prefix(f.stem),
            "href": html.escape(quote(f.relative_to(SRC_DIR).with_suffix("").as_posix(), safe="/"), quote=True),
            "plat": plat,
            "cat": (meta.get("category") or "").strip() or "Uncategorised",
            "diff": (meta.get("difficulty") or "").strip(),
            "tags": [t for t in (meta.get("tags") or []) if t],
            "date": (meta.get("date") or "").strip(),
        })
    return out


def _home_html(md_files: list, class_counts: dict, class_label: dict) -> str:
    E = _entries(md_files)
    total = len(E)
    by_class = sorted(class_counts.items(), key=lambda kv: -kv[1])
    short_of = {e["plat"]["class"]: e["plat"]["short"] for e in E}
    sev_of = {e["plat"]["class"]: e["plat"]["sev"] for e in E}

    dated = sorted((e for e in E if e["date"]), key=lambda e: (e["date"], e["name"]), reverse=True)
    latest = dated[0] if dated else None
    cats = {}
    for e in E:
        cats.setdefault(e["cat"], []).append(e)
    top_cat = max(cats.items(), key=lambda kv: len(kv[1]))[0] if cats else "—"

    DIFF_ORDER = ["Very Easy", "Easy", "Medium", "Hard", "Insane"]
    dcount = {d: sum(1 for e in E if e["diff"] == d) for d in DIFF_ORDER}
    graded = sum(dcount.values())
    year = latest["date"][:4] if latest else ""
    this_year = [e for e in E if e["date"].startswith(year)] if year else []

    # ── hero ────────────────────────────────────────────────────────────────
    plat_parts = [(n, PLAT_COLOR.get(c, "var(--soc-ink4)"), class_label[c]) for c, n in by_class]
    diff_parts = [(dcount[d], DIFF_COLOR[_diff_slug(d)], d) for d in DIFF_ORDER if dcount[d]]
    dom_counts = []
    placed = set()
    for title, _, members in CATEGORY_DOMAINS:
        n = sum(len(cats.get(m, [])) for m in members)
        placed.update(members)
        dom_counts.append((title, n))
    other = sum(len(v) for k, v in cats.items() if k not in placed)
    dom_colors = ["var(--soc-cy)", "var(--soc-gn)", "var(--soc-vi)", "var(--soc-rd)"]
    dom_parts = [(n, dom_colors[i % 4], t) for i, (t, n) in enumerate(dom_counts)]
    if other:
        dom_parts.append((other, "var(--soc-ink4)", "Other"))
    yr_counts = {}
    for e in this_year:
        yr_counts[e["plat"]["class"]] = yr_counts.get(e["plat"]["class"], 0) + 1
    yr_parts = [(n, PLAT_COLOR.get(c, "var(--soc-ink4)"), class_label[c])
                for c, n in sorted(yr_counts.items(), key=lambda kv: -kv[1])]

    top3 = " · ".join(dict.fromkeys(PLAT_ABBR.get(c, c) for c, _ in by_class))
    diff_sub = " · ".join(f"{dcount[d]} {d.lower()}" for d in ("Easy", "Medium", "Hard") if dcount[d])
    latest_html = (f'<a href="{latest["href"]}">{html.escape(latest["name"])}</a>' if latest else "—")

    stats = [
        ("cy", "Write-ups", f"{total}", _bar(plat_parts), f"{len(class_counts)} platforms"),
        ("am", "Graded", f"{graded}", _bar(diff_parts), diff_sub),
        ("vi", "Categories", f"{len(cats)}", _bar(dom_parts), f"{len(CATEGORY_DOMAINS)} domains"),
        ("gn", f"Published {year}", f"{len(this_year)}", _bar(yr_parts),
         f"latest {latest['date']}" if latest else ""),
    ]
    stats_html = "".join(f"""
      <div class="hm-stat {k}">
        <div class="hm-stat-lbl">{lbl}</div>
        <div class="hm-stat-val">{val}</div>
        {bar}
        <div class="hm-stat-sub">{html.escape(sub)}</div>
      </div>""" for k, lbl, val, bar, sub in stats)

    hero = f"""
  <section class="hm-hero">
    <div class="hm-strap">
      <div class="seg"><b>portfolio</b><span class="dim">/</span><span class="v">write_ups</span></div>
      <div class="seg"><b>indexed</b> <span class="v">{total}</span></div>
      <div class="seg"><b>platforms</b> <span class="v">{len(class_counts)}</span></div>
      <div class="seg hm-strap-r"><b>operator</b> <span class="v">{AUTHOR.lower()}</span></div>
    </div>
    <div class="hm-id">
      <div class="hm-av"><img src="{AVATAR_URL}" alt="" width="72" height="72"></div>
      <div class="hm-id-main">
        <h1 class="hm-title">Write-Ups Collection</h1>
        <p class="hm-sub"><span class="hm-sub-in"><span>DFIR</span><span>Malware Analysis</span><span>Network Forensics</span><span>Active Directory</span><span class="hm-sub-tail">lab solutions, documented and reproducible</span></span></p>
        <div class="hm-chips">
          <span class="sev green"><span class="dot"></span>{total} SOLVED</span>
          <span class="sev cyan"><span class="dot"></span>TLP:CLEAR</span>
          <span class="sev am"><span class="dot"></span>{html.escape(top3)}</span>
        </div>
      </div>
      <dl class="hm-kv">
        <dt>LATEST</dt><dd>{latest_html}</dd>
        <dt>UPDATED</dt><dd>{latest['date'] if latest else '—'}</dd>
        <dt>TOP_DOMAIN</dt><dd>{html.escape(top_cat)}</dd>
        <dt>OPERATOR</dt><dd>{AUTHOR}</dd>
      </dl>
    </div>
    <div class="hm-stats">{stats_html}
    </div>
  </section>"""

    # ── recent feed + coverage panel ────────────────────────────────────────
    feed_rows = "".join(f"""
      <a class="hm-feed-row" href="{e['href']}">
        <span class="sev {e['plat']['sev']} hm-feed-tag"><span class="dot"></span>{e['plat']['short']}</span>
        <span class="hm-feed-txt">
          <span class="hm-feed-nm">{html.escape(e['name'])}</span>
          <span class="hm-feed-sub"><span class="hm-feed-plat">{e['plat']['short']} · </span>{html.escape(e['cat'])} · {e['date']}{(' · ' + html.escape(e['diff'])) if e['diff'] and e['diff'] != 'Unknown' else ''}</span>
        </span>
        <span class="hm-feed-btn">READ ↗</span>
      </a>""" for e in dated[:5])

    maxn = by_class[0][1] if by_class else 1
    cov_rows = "".join(f"""
        <div class="hm-cov-row">
          <span class="hm-cov-nm"><span class="hm-dot" style="background:{PLAT_COLOR.get(c, 'var(--soc-ink4)')}"></span>{html.escape(class_label[c])}</span>
          <span class="hm-cov-track"><i style="width:{n / maxn * 100:.1f}%;background:{PLAT_COLOR.get(c, 'var(--soc-ink4)')}"></i></span>
          <span class="hm-cov-n">{n}</span>
        </div>""" for c, n in by_class)
    diff_rows = "".join(
        f'<span class="hm-dchip d-{_diff_slug(d)}">{d} <b>{dcount[d]}</b></span>'
        for d in DIFF_ORDER if dcount[d])

    split = f"""
  <div class="hm-split">
    <section class="hm-col">
      <div class="hm-sec"><span class="hm-sec-t">Recent write-ups</span><span class="hm-sec-r">tail -f /var/log/writeups.feed</span></div>
      <div class="hm-feed">{feed_rows}
      </div>
    </section>
    <section class="hm-col">
      <div class="hm-sec"><span class="hm-sec-t">Coverage</span><span class="hm-sec-r">/platforms/*.md</span></div>
      <div class="hm-cov">
        <div class="hm-cov-head"><span class="hm-cov-kicker">PLATFORM COVERAGE</span><span class="sev green"><span class="dot"></span>{total} INDEXED</span></div>
        {cov_rows}
        <div class="hm-cov-head hm-cov-head2"><span class="hm-cov-kicker">DIFFICULTY</span></div>
        <div class="hm-dchips">{diff_rows}</div>
      </div>
    </section>
  </div>"""

    # ── category matrix ─────────────────────────────────────────────────────
    domains = [list(d) for d in CATEGORY_DOMAINS]
    leftovers = [c for c in cats if c not in placed]
    if leftovers:
        domains[-1][2] = list(domains[-1][2]) + leftovers
    dom_html = []
    code_n = 0
    for di, (title, tagline, members) in enumerate(domains):
        present = sorted((m for m in members if m in cats), key=lambda m: -len(cats[m]))
        if not present:
            continue
        cards, small = [], []
        for m in present:
            items = cats[m]
            if len(items) < MATRIX_MIN_CARD:
                small.append(f'<button class="hm-mini" data-cat="{_cat_slug(m)}" data-cat-label="{html.escape(m, quote=True)}">{html.escape(m)} <b>{len(items)}</b></button>')
                continue
            code_n += 1
            code = "".join(w[0] for w in re.findall(r'[A-Za-z]+', m))[:2].upper()
            pc = {}
            for e in items:
                a = PLAT_ABBR.get(e["plat"]["class"], "?")
                pc[a] = pc.get(a, 0) + 1
            ev = " ".join(f'<span><b>{n}</b> {html.escape(a)}</span>'
                          for a, n in sorted(pc.items(), key=lambda kv: (-kv[1], kv[0]))[:4])
            dparts = [(sum(1 for e in items if e["diff"] == d), DIFF_COLOR[_diff_slug(d)], d) for d in DIFF_ORDER]
            cards.append(f"""
        <button class="hm-card d{di}" data-cat="{_cat_slug(m)}" data-cat-label="{html.escape(m, quote=True)}">
          <span class="hm-card-h"><span class="hm-code">{code}-{code_n:02d}</span><span class="hm-card-t">{html.escape(m)}</span><span class="hm-card-n">{len(items)}</span></span>
          {_bar(dparts)}
          <span class="hm-ev"><span class="hm-ev-l">EVIDENCE</span> {ev}</span>
        </button>""")
        total_dom = sum(len(cats[m]) for m in present)
        small_html = f'<div class="hm-minis"><span class="hm-minis-l">also</span>{"".join(small)}</div>' if small else ""
        dom_html.append(f"""
    <div class="hm-dom d{di}">
      <div class="hm-dom-h"><span class="hm-dom-t">{html.escape(title)}</span><span class="hm-dom-tag">{html.escape(tagline)}</span><span class="hm-dom-line"></span><span class="hm-dom-n">{total_dom} write-ups</span></div>
      <div class="hm-grid">{''.join(cards)}
      </div>{small_html}
    </div>""")

    matrix = f"""
  <section class="hm-matrix" id="matrix">
    <div class="hm-sec"><span class="hm-sec-t">Category matrix</span><span class="hm-sec-r">{len(cats)} categories · click to filter</span></div>{''.join(dom_html)}
  </section>

  <div class="hm-sec hm-sec-all" id="all"><span class="hm-sec-t">All write-ups</span><span class="hm-sec-r">grep · filter · sort</span></div>"""

    return hero + split + matrix


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

    # ── difficulty chips (only levels present, canonical order) ────────────────
    DIFF_ORDER = ["Very Easy", "Easy", "Medium", "Hard", "Insane"]
    diff_counts: dict[str, int] = {}
    for f in md_files:
        d = (_meta_for(f).get("difficulty") or "").strip()
        if d and d.lower() != "unknown":
            diff_counts[d] = diff_counts.get(d, 0) + 1
    graded = sum(diff_counts.values())
    dchips = ['<button class="dchip active" data-diff="all">All <span class="cnt">' + str(graded) + '</span></button>']
    for d in DIFF_ORDER:
        n = diff_counts.get(d)
        if n:
            dchips.append(f'<button class="dchip d-{_diff_slug(d)}" data-diff="{_diff_slug(d)}">{d} <span class="cnt">{n}</span></button>')
    dchips_html = "\n      ".join(dchips)


    # ── platform panels, sorted by count desc
    panel_blocks = []
    for folder, files in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        panel_blocks.append(_panel_html(folder, files))
    panels_html = "\n\n    ".join(panel_blocks)

    # ── topbar
    crumb_html = '<b class="here">WRITE-UPS</b>'
    badges_html = (
        '<span class="sev cyan"><span class="dot"></span>TLP:CLEAR</span> '
        '<span class="sev green"><span class="dot"></span>OPERATIONAL</span> '
        f'<a class="sev-link" href="{PORTFOLIO_URL}">PORTFOLIO <span class="ar">↗</span></a> '
        f'<a class="sev-link" href="{REPO_URL}" target="_blank" rel="noopener noreferrer">GITHUB <span class="ar">↗</span></a>'
    )
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    clock_label = f"LAST.SYNC · {today}"

    description = (
        f"CTF challenges & cybersecurity lab solutions by {AUTHOR}. "
        f"Browse {total} write-ups across {platform_count} platforms."
    )

    # NB: local name is `page`, not `html` — `html` is the stdlib module used
    # for escaping elsewhere in this file and shadowing it breaks that.
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
{common_head("Write-Ups Collection", description=description)}
{css_links("", "base", "index")}
</head>
<body>

{topbar(crumb_html, badges_html, clock_label)}

<main class="page">

{_home_html(md_files, class_counts, class_label)}

  <div class="toolbar">
    <div class="search-wrap">
      <input id="search" class="search-input" type="text" placeholder="grep write-ups..." autocomplete="off" spellcheck="false">
      <span class="search-icon">⌕</span>
    </div>
    <button class="catpill" id="catpill" type="button" title="Clear category filter"><span class="lbl"></span><span class="x">✕</span></button>
    <div class="filters" id="filters">
      <span class="fchip-label">Platform</span>
      {chips_html}
    </div>
    <div class="filters dfilters" id="dfilters">
      <span class="fchip-label">Difficulty</span>
      {dchips_html}
    </div>
  </div>

  <button class="tweak-toggle" id="tw-open">⚙ Tweaks</button>

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
      <a href="{PORTFOLIO_URL}" target="_blank" rel="noopener noreferrer">Portfolio ↗</a>
      <a href="{REPO_URL}" target="_blank" rel="noopener noreferrer">GitHub ↗</a>
    </span>
  </footer>

</main>

{_index_scripts()}

</body>
</html>
"""

    (BUILD_DIR / "index.html").write_text(page, encoding="utf-8")
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
        <button data-val="rows">Rows</button>
        <button data-val="cards">Cards</button>
        <button data-val="grid">Grid</button>
      </div>
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
        <button data-val="diff">Difficulty</button>
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
  const dchips = document.querySelectorAll('.dchip');
  let activeFilter = 'all';
  let activeDiff = 'all';
  let activeCat = 'all';
  const catTriggers = document.querySelectorAll('[data-cat-label]');
  const catpill = document.getElementById('catpill');

  /* rows are cached once — querySelectorAll per card on every keystroke over
     ~360 entries was the bulk of the search cost */
  const cardRows = new Map();
  cards.forEach(card => cardRows.set(card, Array.from(card.querySelectorAll('.wrow'))));

  function applyFilter(){
    const q = input.value.toLowerCase().trim();
    let anyVisible = false;
    cards.forEach(card => {
      const platOk = (activeFilter === 'all') || card.dataset.platform === activeFilter;
      if(!platOk){ card.classList.add('all-hidden'); return; }
      const rows = cardRows.get(card);
      let cardHasMatch = false;
      rows.forEach(r => {
        /* data-search is emitted already lowercased by the build script */
        const blob = r.dataset.search || r.dataset.name || '';
        const diffOk = (activeDiff === 'all') || (r.dataset.diff === activeDiff);
        const catOk = (activeCat === 'all') || (r.dataset.cat === activeCat);
        const show = diffOk && catOk && (!q || blob.includes(q));
        r.classList.toggle('hidden', !show);
        if(show) cardHasMatch = true;
      });
      card.classList.toggle('all-hidden', !cardHasMatch);
      if(cardHasMatch) anyVisible = true;
      if((q || activeFilter !== 'all' || activeDiff !== 'all' || activeCat !== 'all') && cardHasMatch) card.open = true;
    });
    const filtering = !!q || activeFilter !== 'all' || activeDiff !== 'all' || activeCat !== 'all';
    noRes.classList.toggle('show', !anyVisible && filtering);
    nrq.textContent = q ? ('"' + input.value.trim() + '"')
                        : (activeCat !== 'all' ? ('category: ' + activeCat)
                        : activeDiff !== 'all' ? ('difficulty: ' + activeDiff)
                        : (activeFilter !== 'all' ? ('filter: ' + activeFilter) : ''));
  }
  /* coalesce keystrokes into one layout pass per frame */
  let raf = 0;
  input.addEventListener('input', () => {
    if(raf) cancelAnimationFrame(raf);
    raf = requestAnimationFrame(() => { raf = 0; applyFilter(); });
  });
  fchips.forEach(c => c.addEventListener('click', () => {
    fchips.forEach(x => x.classList.remove('active'));
    c.classList.add('active');
    activeFilter = c.dataset.filter;
    applyFilter();
  }));
  dchips.forEach(c => c.addEventListener('click', () => {
    dchips.forEach(x => x.classList.remove('active'));
    c.classList.add('active');
    activeDiff = c.dataset.diff;
    applyFilter();
  }));

  /* category matrix: a card filters the list below and scrolls to it;
     clicking the active card (or the pill's ✕) clears the filter */
  function setCat(slug, label){
    activeCat = slug;
    catTriggers.forEach(t => t.classList.toggle('is-on', t.dataset.cat === slug));
    catpill.classList.toggle('show', slug !== 'all');
    catpill.querySelector('.lbl').textContent = slug === 'all' ? '' : 'Category: ' + label;
    applyFilter();
  }
  catTriggers.forEach(t => t.addEventListener('click', () => {
    if(activeCat === t.dataset.cat){ setCat('all', ''); return; }
    setCat(t.dataset.cat, t.dataset.catLabel);
    document.getElementById('all').scrollIntoView({behavior:'smooth', block:'start'});
  }));
  catpill.addEventListener('click', () => setCat('all', ''));

  /* ─── Tweaks ─── */
  const DEFAULTS = {
    "view":"rows","cardMin":320,"showMeta":true,"showIndex":true,
    "accent":"subtle","startOpen":"none","sort":"az"
  };
  const LS = 'writeup-index-tweaks';
  let state = Object.assign({}, DEFAULTS);
  try{ const saved = JSON.parse(localStorage.getItem(LS)||'null'); if(saved) state = Object.assign(state, saved); }catch(e){}

  const panel = document.getElementById('tw-panel');
  const VIEW_LABELS = {rows:'Rows', cards:'Cards', grid:'Grid'};
  const ACCENT_LABELS = {subtle:'Subtle', bold:'Bold'};
  const START_LABELS = {first:'First only', all:'All', none:'Collapsed'};
  const SORT_LABELS = {az:'A → Z', za:'Z → A', diff:'Difficulty ↑', orig:'Original'};
  const DIFF_RANK = {'very-easy':0, 'easy':1, 'medium':2, 'hard':3, 'insane':4};

  document.querySelectorAll('.wlist').forEach(list => { list._origOrder = Array.from(list.children); });

  function applySort(mode){
    document.querySelectorAll('.wlist').forEach(list => {
      const items = Array.from(list.children);
      let sorted;
      if(mode === 'az')      sorted = items.slice().sort((a,b)=>(a.dataset.name||'').localeCompare(b.dataset.name||''));
      else if(mode === 'za') sorted = items.slice().sort((a,b)=>(b.dataset.name||'').localeCompare(a.dataset.name||''));
      else if(mode === 'diff') sorted = items.slice().sort((a,b)=>{
        const ra = (a.dataset.diff in DIFF_RANK) ? DIFF_RANK[a.dataset.diff] : 9;
        const rb = (b.dataset.diff in DIFF_RANK) ? DIFF_RANK[b.dataset.diff] : 9;
        return ra - rb || (a.dataset.name||'').localeCompare(b.dataset.name||'');
      });
      else                   sorted = list._origOrder.filter(n=>items.indexOf(n) !== -1);
      /* one reflow instead of one per row */
      const frag = document.createDocumentFragment();
      sorted.forEach(n => frag.appendChild(n));
      list.appendChild(frag);
    });
  }

  function applyTweaks(){
    const body = document.body;
    body.classList.toggle('tw-rows',        state.view === 'rows');
    body.classList.toggle('tw-grid',        state.view === 'grid');
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
  panel.querySelector('[data-tw="cardMin"]')?.addEventListener('input', e => persist('cardMin', parseInt(e.target.value,10)));
  document.getElementById('tw-reset').addEventListener('click', () => {
    state = Object.assign({}, DEFAULTS);
    try{ localStorage.removeItem(LS); }catch(e){}
    applyTweaks();
  });
  const twOpen = document.getElementById('tw-open');
  const twClose = document.getElementById('tw-close');
  const syncTw = () => { const on = panel.classList.contains('show'); twOpen.classList.toggle('active', on); twOpen.classList.toggle('hidden-by-panel', on); };
  twOpen.addEventListener('click', () => { panel.classList.toggle('show'); syncTw(); });
  twClose.addEventListener('click', () => { panel.classList.remove('show'); syncTw(); });

  applyTweaks();
})();
</script>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def collect_md_files() -> list[Path]:
    """Every write-up markdown file. Repo docs (README/CLAUDE/…) and any
       markdown sitting at the repo root are not write-ups and never publish."""
    md_files: list[Path] = []
    for root, dirs, files in os.walk(SRC_DIR):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        rel_root = Path(root).relative_to(SRC_DIR)
        at_root = rel_root == Path(".")
        for fn in files:
            if not fn.lower().endswith(".md"):
                continue
            if at_root or fn.lower() in SKIP_NAMES:
                continue
            md_files.append(Path(root) / fn)
    return sorted(md_files)


# ── Image optimisation ───────────────────────────────────────────────────────
# resources/ is ~1 GB of PNG screenshots and GitHub Pages caps a published site
# at 1 GB. Lossless WebP holds ~58% of the PNG bytes on this corpus with no
# quality loss at all — which matters here, because readers zoom into hex dumps
# and log lines. Lossy q85 only reaches ~47% and softens text, so it is not
# worth it. method=2 is the knee of the size/time curve (method=6 is ~30x
# slower for ~1pp).
#
# Encoding is content-addressed in IMG_CACHE_DIR: resource filenames are
# already content hashes, so a cache hit means a copy instead of a re-encode.
# Cache that directory in CI and only new screenshots ever cost time.
IMG_CACHE_DIR = Path(os.environ.get("IMG_CACHE_DIR", ".imgcache"))
SKIP_IMAGE_OPT = os.environ.get("SKIP_IMAGE_OPT") == "1"
RASTER_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".tiff"}
WEBP_OPTS = dict(lossless=True, quality=100, method=2)


def _encode_one(args: tuple) -> tuple:
    """Worker: (rel, src, dst_dir) -> (rel, out_name, w, h) or (rel, None, 0, 0).

       Returns the original name when WebP would not actually be smaller."""
    from PIL import Image  # imported in the worker so the parent stays importable

    rel, src_str, dst_dir_str, cache_dir_str = args
    src = Path(src_str)
    dst_dir = Path(dst_dir_str)
    cache = Path(cache_dir_str) / (Path(rel).stem + ".webp")
    out_rel = str(Path(rel).with_suffix(".webp")).replace("\\", "/")

    try:
        with Image.open(src) as im:
            im.load()
            w, h = im.size
            if not cache.is_file():
                cache.parent.mkdir(parents=True, exist_ok=True)
                tmp = cache.with_suffix(".webp.tmp")
                if im.mode not in ("RGB", "RGBA", "L"):
                    im = im.convert("RGBA" if "A" in im.getbands() else "RGB")
                im.save(tmp, "WEBP", **WEBP_OPTS)
                tmp.replace(cache)
    except Exception:
        return (rel, None, 0, 0)

    if cache.stat().st_size >= src.stat().st_size:
        return (rel, None, w, h)  # PNG already smaller — keep it

    dst = dst_dir / out_rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(cache, dst)
    return (rel, out_rel, w, h)


def copy_resources(needed: set) -> dict:
    """Publish only the images the generated pages reference, WebP-encoded.

       resources/ holds ~8.4k files, several hundred orphaned from deleted
       write-ups; shipping those is both slow and a real ceiling risk.

       Returns {source_rel: {"out": published_rel, "w": int, "h": int}}."""
    resources_src = SRC_DIR / "resources"
    resources_dst = BUILD_DIR / "resources"
    mapping: dict = {}
    if not resources_src.exists():
        return mapping
    if resources_dst.exists():
        shutil.rmtree(resources_dst)
    ensure_build_path(resources_dst)

    present, missing = [], []
    for rel in sorted(needed):
        (present if (resources_src / rel).is_file() else missing).append(rel)

    # Non-raster (svg, gif, pdf…) and any pass-through copies happen verbatim.
    raster = [r for r in present if Path(r).suffix.lower() in RASTER_EXTS]
    raster_set = set(raster)
    verbatim = [r for r in present if r not in raster_set]

    if raster and not SKIP_IMAGE_OPT:
        try:
            import PIL  # noqa: F401
        except ImportError:
            print("⚠ Pillow not installed — publishing PNGs unoptimised "
                  "(pip install pillow)")
            verbatim += raster
            raster = []

    if raster:
        ensure_build_path(IMG_CACHE_DIR)
        jobs = [(r, str(resources_src / r), str(resources_dst), str(IMG_CACHE_DIR))
                for r in raster]
        workers = max(1, (os.cpu_count() or 2))
        print(f"Encoding {len(jobs)} images to lossless WebP on {workers} workers…")
        with ProcessPoolExecutor(max_workers=workers) as pool:
            for i, (rel, out_rel, w, h) in enumerate(pool.map(_encode_one, jobs, chunksize=8), 1):
                if out_rel is None:
                    verbatim.append(rel)
                else:
                    mapping[rel] = {"out": out_rel, "w": w, "h": h}
                if i % 500 == 0:
                    print(f"  …{i}/{len(jobs)}")

    for rel in verbatim:
        dst = resources_dst / rel
        ensure_build_path(dst.parent)
        shutil.copy2(resources_src / rel, dst)

    src_bytes = sum((resources_src / r).stat().st_size for r in present)
    out_bytes = sum(p.stat().st_size for p in resources_dst.rglob("*") if p.is_file())
    on_disk = sum(1 for p in resources_src.rglob("*") if p.is_file())
    print(f"Published {len(present)} referenced resources: "
          f"{src_bytes/1e6:.1f} MB → {out_bytes/1e6:.1f} MB "
          f"({100*out_bytes/max(src_bytes,1):.0f}%); "
          f"{on_disk - len(present)} unreferenced files skipped")
    if missing:
        print(f"❌ {len(missing)} referenced image(s) missing from resources/ "
              f"— these render broken:")
        for rel in missing[:20]:
            print(f"   {rel}")
    return mapping


_IMG_TAG_RE = re.compile(r'<img\b([^>]*?)src="((?:\.{1,2}/)*resources/)([^"?#]+)"([^>]*)>')

def apply_image_mapping(mapping: dict) -> None:
    """Point built pages at the WebP files and stamp intrinsic width/height.

       Runs as a post-pass because which images are needed is only known after
       the pages are rendered. width/height kills layout shift as the lazy
       images stream in."""
    if not mapping:
        return
    rewritten = pages = 0

    def sub(m):
        nonlocal rewritten
        pre, prefix, name, post = m.groups()
        info = mapping.get(name)
        if not info:
            return m.group(0)
        rewritten += 1
        # markdown2 emits `<img ... />`; that trailing slash must not end up
        # between the existing attributes and the injected ones.
        post = post.rstrip()
        self_closing = post.endswith("/")
        if self_closing:
            post = post[:-1].rstrip()
        dims = ""
        if info["w"] and "width=" not in pre and "width=" not in post:
            dims = f' width="{info["w"]}" height="{info["h"]}"'
        return f'<img{pre}src="{prefix}{info["out"]}"{post}{dims}{" /" if self_closing else ""}>'

    for page in BUILD_DIR.rglob("*.html"):
        text = page.read_text(encoding="utf-8")
        new = _IMG_TAG_RE.sub(sub, text)
        if new != text:
            page.write_text(new, encoding="utf-8")
            pages += 1
    print(f"✅ Rewrote {rewritten} <img> tags across {pages} pages to WebP + intrinsic size")


def write_seo_files(md_files: list[Path]) -> None:
    urls = [f"{SITE_URL}/"]
    for md in md_files:
        rel = md.relative_to(SRC_DIR).with_suffix("").as_posix()
        urls.append(f"{SITE_URL}/{quote(rel, safe='/')}")
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    body = "\n".join(
        f"  <url><loc>{html.escape(u)}</loc><lastmod>{today}</lastmod></url>" for u in urls
    )
    (BUILD_DIR / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{body}\n</urlset>\n", encoding="utf-8")
    (BUILD_DIR / "robots.txt").write_text(
        f"User-agent: *\nAllow: /\nSitemap: {SITE_URL}/sitemap.xml\n", encoding="utf-8")

    # Cloudflare Pages reads _headers from the output root. Harmless on GitHub
    # Pages (served as a plain file, no directives honoured).
    #   · resources/  — filenames are content hashes, so immutable is safe
    #   · assets/     — cache key includes the ?v= hash, so a change is a new URL
    #   · *.html      — must revalidate, the index changes every build
    (BUILD_DIR / "_headers").write_text(
        "/resources/*\n"
        "  Cache-Control: public, max-age=31536000, immutable\n"
        "\n"
        "/assets/*\n"
        "  Cache-Control: public, max-age=31536000, immutable\n"
        "\n"
        "/*.html\n"
        "  Cache-Control: public, max-age=0, must-revalidate\n"
        "  X-Content-Type-Options: nosniff\n"
        "  Referrer-Policy: strict-origin-when-cross-origin\n",
        encoding="utf-8")
    print("✅ Wrote sitemap.xml + robots.txt + _headers")


def write_404_page() -> None:
    """A real 404 document.

       Cloudflare Pages falls back to index.html with HTTP 200 for every
       unmatched path when no 404.html exists — so deleted or mistyped URLs
       look like real pages to both readers and crawlers. Shipping this file
       makes Pages answer with a genuine 404, and replaces GitHub Pages'
       generic one. Asset links are absolute because this page is served for
       paths at any depth."""
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
{common_head("404 · Case Not Found", description="No write-up exists at this address.")}
{css_links("/", "base", "article")}
<style>
.nf-wrap{{max-width:640px;margin:0 auto;padding:80px 22px;text-align:center}}
.nf-code{{font-family:'JetBrains Mono',monospace;font-size:64px;font-weight:700;
  color:var(--soc-rd);letter-spacing:-.02em;line-height:1}}
.nf-msg{{font-size:15px;color:var(--soc-ink2);margin:14px 0 6px}}
.nf-sub{{font-family:'JetBrains Mono',monospace;font-size:12.5px;color:var(--soc-ink3);
  margin-bottom:28px}}
.nf-back{{display:inline-block;padding:9px 18px;border:1px solid var(--soc-line2);
  border-radius:5px;color:var(--soc-cy);text-decoration:none;font-family:'JetBrains Mono',monospace;
  font-size:13px}}
.nf-back:hover{{border-color:var(--soc-cy)}}
</style>
</head>
<body>

{topbar('<a href="/"><b>WRITE-UPS</b></a> <span class="sep">/</span> '
        '<b class="here">404</b>',
        '<span class="sev rd"><span class="dot"></span>NOT FOUND</span>')}

<div class="nf-wrap">
  <div class="nf-code">404</div>
  <p class="nf-msg">No write-up exists at this address.</p>
  <p class="nf-sub">// the case file may have been renamed, moved, or never existed</p>
  <a class="nf-back" href="/">← Back to all write-ups</a>
</div>

{article_footer("/")}

</body>
</html>
"""
    (BUILD_DIR / "404.html").write_text(page, encoding="utf-8")
    print("✅ Wrote 404.html")


def main() -> int:
    """Returns a process exit code. Non-zero must abort the deploy.

       This matters more than it looks: the deploy uploads whatever is in
       build/. A build that fails halfway but exits 0 publishes a partial site
       over a working one, and a build that finds no markdown at all would
       publish an empty one."""
    ensure_build_path(BUILD_DIR)
    write_assets()

    md_files = collect_md_files()
    if not md_files:
        print("❌ No markdown files found — refusing to publish an empty site")
        return 1
    print(f"Found {len(md_files)} markdown files")

    # Index
    create_index_html(md_files)

    # Per-write-up pages
    needed_resources: set = set()
    failed: list = []
    for md_file in md_files:
        rel_folder = md_file.parent.relative_to(SRC_DIR)
        out_file = BUILD_DIR / rel_folder / f"{md_file.stem}.html"
        try:
            md_to_html(md_file, out_file, res_sink=needed_resources)
            print(f"✅ {md_file.relative_to(SRC_DIR)}")
        except Exception as e:
            print(f"❌ {md_file}: {e}")
            failed.append((md_file, e))

    apply_image_mapping(copy_resources(needed_resources))
    write_404_page()
    write_seo_files(md_files)

    built = sum(1 for _ in BUILD_DIR.rglob("*.html"))
    if failed:
        print(f"\n❌ {len(failed)} page(s) failed to render — refusing to publish "
              f"a site that is missing them:")
        for md_file, e in failed:
            print(f"   {md_file.relative_to(SRC_DIR)}: {e}")
        return 1

    # index.html + 404.html + one page per write-up.
    expected = len(md_files) + 2
    if built != expected:
        print(f"\n❌ built {built} HTML pages, expected {expected} — aborting")
        return 1

    print(f"\n✅ Done — {len(md_files)} write-ups ({built} pages) written to {BUILD_DIR}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
