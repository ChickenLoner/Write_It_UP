"""Extract a compact metadata-generation input for every write-up md.
Writes batch_XX.json files (lists of records) into <out>/batches/.
Run from repo root."""
import os, re, json, sys
from pathlib import Path

SRC = Path(".")
OUT = Path(sys.argv[1])          # scratchpad working dir
BATCH_SIZE = 16
EXCERPT_CHARS = 2600

SKIP_DIRS = {"build", ".github", ".git", "node_modules", ".venv", "__pycache__", "re-design"}

PLATFORMS = [
    (("hackthebox", "sherlock"), "HTB Sherlocks"),
    (("hackthebox", "machine"),  "HTB Machines"),
    (("hackthebox",),            "HackTheBox"),
    (("btlo",),                  "Blue Team Labs Online"),
    (("cyberdefenders",),        "CyberDefenders"),
    (("letsdefend",),            "LetsDefend"),
    (("tryhackme",),             "TryHackMe"),
    (("hacksmarter",),           "HackSmarter.org"),
    (("unlisted",),              "Unlisted Labs"),
]
def platform_of(folder: str) -> str:
    fl = folder.lower()
    for keys, name in PLATFORMS:
        if all(k in fl for k in keys):
            return name
    return "Write-Up"

DIFF_RE = re.compile(r"\b(very\s+easy|insane|medium|hard|easy)\b", re.I)

def clean_body(text: str) -> tuple[str, list[str]]:
    lines = text.splitlines()
    out, prompts = [], []
    in_fence = False
    for ln in lines:
        s = ln.strip()
        if s.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        # drop pure image lines
        if re.fullmatch(r"!\[[^\]]*\]\([^)]*\)", s):
            continue
        # strip inline images
        s = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", s).strip()
        if not s or s == "* * *":
            continue
        # capture task/question prompts (reveal techniques covered)
        if re.match(r"^>?\s*(Task\s*\d+|Q\d+|Question\s*\d+)\b", s, re.I):
            prompts.append(re.sub(r"^>\s*", "", s))
        out.append(s)
    return "\n".join(out), prompts

def extract(md: Path) -> dict:
    raw = md.read_text(encoding="utf-8", errors="replace")
    rel = md.relative_to(SRC).as_posix()
    folder = md.parent.relative_to(SRC).as_posix()
    stem = md.stem
    title = re.sub(r"^\[[^\]]*Write-up\]\s*", "", stem).strip()

    cat = tags = diff = ""
    m = re.search(r"^\s*>?\s*Category:\s*(.+)$", raw, re.M | re.I)
    if m: cat = m.group(1).strip()
    m = re.search(r"^\s*>?\s*Tags:\s*(.+)$", raw, re.M | re.I)
    if m: tags = m.group(1).strip()
    m = re.search(r"Difficulty[:\s]+(" + DIFF_RE.pattern + r")", raw, re.I)
    if m: diff = m.group(1).strip()
    # difficulty hint from narrative ("very easy Sherlock", etc.)
    if not diff:
        m = DIFF_RE.search(raw)
        if m and re.search(r"(this|very)\s+" + re.escape(m.group(0)), raw, re.I):
            diff = m.group(0)

    body, prompts = clean_body(raw)
    # trim: header line already in body; keep first EXCERPT_CHARS
    excerpt = body[:EXCERPT_CHARS]
    prompts = prompts[:12]
    return {
        "key": rel,
        "platform": platform_of(folder),
        "title": title,
        "existing_category": cat,
        "existing_tags": tags,
        "difficulty_hint": diff,
        "prompts": prompts,
        "excerpt": excerpt,
    }

def main():
    md_files = []
    for root, dirs, files in os.walk(SRC):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in files:
            if fn.endswith(".md") and fn.lower() != "readme.md":
                md_files.append(Path(root) / fn)
    md_files.sort()
    recs = [extract(p) for p in md_files]

    bdir = OUT / "batches"
    bdir.mkdir(parents=True, exist_ok=True)
    for f in bdir.glob("batch_*.json"):
        f.unlink()
    n = 0
    for i in range(0, len(recs), BATCH_SIZE):
        chunk = recs[i:i+BATCH_SIZE]
        (bdir / f"batch_{n:02d}.json").write_text(json.dumps(chunk, ensure_ascii=False, indent=1), encoding="utf-8")
        n += 1
    print(f"records={len(recs)} batches={n} dir={bdir}")

if __name__ == "__main__":
    main()
