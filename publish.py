#!/usr/bin/env python3
"""
publish.py — one command between "exported from Joplin" and "pushed".

Replaces the old dance of running automated_fix.bat, hand-checking image
paths, remembering the writeups_meta.json entry, and hoping the build is clean:

    uv run publish.py            # fix + validate + report, then you commit
    uv run publish.py --push     # ...and commit + push it too

What it does, in order:

  1. Merges any _resources/ folders into resources/ and rewrites the markdown
     links to /resources/          (the old fix_paths.py step)
  2. Replaces Joplin's [toc] token with a real markdown TOC
                                   (the old fix_joplin_toc.py step)
  3. Scaffolds a writeups_meta.json entry for every write-up that lacks one,
     so a new lab can never silently render as a bare card
  4. Verifies every referenced image actually exists in resources/, which is
     how five screenshots stayed broken on the live site unnoticed
  5. Optionally commits and pushes, which triggers the Cloudflare deploy

Deliberately does NOT run the full site build: that copies ~500 MB and CI does
it anyway. Step 4 catches the failure the build would have reported.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import fix_joplin_toc
import fix_paths

REPO = Path(__file__).parent
META_PATH = REPO / "writeups_meta.json"
RESOURCES = REPO / "resources"

# Same reference styles the build normalises: /resources/x.png, _resources/x.png,
# ../_resources/x.png
IMG_REF = re.compile(r'!\[[^\]]*\]\(\s*(?:\.\./)*/?_?resources/([^)\s]+?)\s*\)')


def _iter_writeups():
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in fix_paths.SKIP_FOLDERS]
        for fn in files:
            if not fn.lower().endswith(".md"):
                continue
            p = Path(root) / fn
            rel = p.relative_to(REPO)
            if not fix_paths.is_writeup(Path(rel.as_posix())):
                continue
            yield p


def step_paths() -> None:
    print("── 1. resources ─────────────────────────────────────────────")
    moved = fix_paths.find_and_merge_resources()
    updated, total = fix_paths.update_markdown_files()
    if moved or updated:
        print(f"   moved {moved} file(s); rewrote links in {updated} write-up(s)")
    else:
        print("   nothing to move — already normalised")


def step_toc() -> None:
    print("── 2. [toc] ─────────────────────────────────────────────────")
    fixed = [p for p in _iter_writeups() if fix_joplin_toc.process_markdown_file(p)]
    print(f"   generated a table of contents in {len(fixed)} write-up(s)"
          if fixed else "   no [toc] tokens left to expand")
    for p in fixed:
        print(f"      {p.relative_to(REPO).as_posix()}")


def step_meta() -> list:
    """Scaffold entries for write-ups the sidecar does not know about."""
    print("── 3. writeups_meta.json ────────────────────────────────────")
    meta = json.loads(META_PATH.read_text(encoding="utf-8")) if META_PATH.exists() else {}
    keys = {p.relative_to(REPO).as_posix() for p in _iter_writeups()}

    missing = sorted(keys - meta.keys())
    stale = sorted(meta.keys() - keys)

    for key in missing:
        meta[key] = {
            "difficulty": "Unknown",
            "category": "",
            "tags": [],
            "summary": "",
        }
    if missing:
        META_PATH.write_text(
            json.dumps(dict(sorted(meta.items())), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")
        print(f"   scaffolded {len(missing)} entr(y/ies) — fill these in:")
        for k in missing:
            print(f"      {k}")
    else:
        print(f"   all {len(keys)} write-ups have an entry")

    # An entry that exists but is blank still renders a bare card.
    blank = sorted(k for k in keys
                   if k in meta and not (meta[k].get("summary") or "").strip())
    if blank and not missing:
        print(f"   ⚠ {len(blank)} entr(y/ies) have no summary yet")
    for k in blank[:10]:
        if k not in missing:
            print(f"      (blank) {k}")

    if stale:
        print(f"   ⚠ {len(stale)} entr(y/ies) refer to files that no longer exist")
        for k in stale[:5]:
            print(f"      (stale) {k}")

    return missing + [k for k in blank if k not in missing]


def step_images() -> list:
    """Every referenced image must exist, or it renders broken on the site."""
    print("── 4. images ────────────────────────────────────────────────")
    have = {p.name for p in RESOURCES.iterdir()} if RESOURCES.exists() else set()
    broken = []
    refs = 0
    for p in _iter_writeups():
        text = p.read_text(encoding="utf-8", errors="ignore")
        for m in IMG_REF.finditer(text):
            refs += 1
            name = m.group(1).split("/")[-1]
            if name not in have:
                broken.append((p.relative_to(REPO).as_posix(), name))
    if broken:
        print(f"   ❌ {len(broken)} referenced image(s) missing from resources/:")
        for src, name in broken[:20]:
            print(f"      {name}  <- {src}")
        print("   these will render broken. If the file was lost in the")
        print("   _resources/ rename it is probably still in git history:")
        print("      git rev-list --all --objects | grep <name>")
        print("      git cat-file -p <sha> > resources/<name>")
    else:
        print(f"   all {refs} referenced image(s) present")
    return broken


def step_push(message: str) -> None:
    print("── 5. publish ───────────────────────────────────────────────")
    subprocess.run(["git", "add", "-A"], cwd=REPO, check=True)
    diff = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=REPO)
    if diff.returncode == 0:
        print("   nothing staged — no commit made")
        return
    subprocess.run(["git", "commit", "-m", message], cwd=REPO, check=True)
    subprocess.run(["git", "push", "origin", "main"], cwd=REPO, check=True)
    print("   pushed — Cloudflare deploys in ~2 minutes")
    print("   watch: gh run watch $(gh run list -L1 --json databaseId -q '.[0].databaseId')")


def main() -> int:
    ap = argparse.ArgumentParser(description="Prepare a Joplin export for publishing.")
    ap.add_argument("--push", action="store_true",
                    help="commit and push when everything checks out")
    ap.add_argument("-m", "--message", default="content: add write-up",
                    help="commit message used with --push")
    args = ap.parse_args()

    step_paths()
    step_toc()
    needs_meta = step_meta()
    broken = step_images()

    print("── summary ──────────────────────────────────────────────────")
    blocked = bool(broken)
    if broken:
        print(f"   ❌ {len(broken)} missing image(s) — fix before publishing")
    if needs_meta:
        print(f"   ⚠  {len(needs_meta)} write-up(s) need difficulty/category/tags/summary")
        print("      ask Claude to fill them in, or edit writeups_meta.json by hand")
    if not blocked and not needs_meta:
        print("   ✅ ready to publish")

    if args.push:
        if blocked:
            print("   refusing to push with broken images — pass nothing and fix first")
            return 1
        step_push(args.message)
    elif not blocked:
        print("   next: git add -A && git commit -m '...' && git push")

    return 1 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
