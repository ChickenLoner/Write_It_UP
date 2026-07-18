"""Merge per-batch metadata out-files into writeups_meta.json at repo root.
Validates keys against the batch inputs, normalizes difficulty/tags/summary.
Usage: uv run merge_meta.py <wqdir> <repo_root>"""
import json, sys, glob, os
from pathlib import Path

WQ = Path(sys.argv[1])
ROOT = Path(sys.argv[2])

DIFFS = {"very easy":"Very Easy","easy":"Easy","medium":"Medium",
         "hard":"Hard","insane":"Insane","unknown":"Unknown"}

def norm_diff(d):
    if not d: return "Unknown"
    return DIFFS.get(str(d).strip().lower(), "Unknown")

def norm_tags(t):
    if not isinstance(t, list): return []
    out, seen = [], set()
    for x in t:
        s = str(x).strip().lower().lstrip("#")
        if s and s not in seen and len(s) <= 24:
            seen.add(s); out.append(s)
    return out[:6]

def norm_sum(s):
    s = (s or "").strip().replace("\n", " ")
    if len(s) > 165: s = s[:162].rstrip() + "…"
    return s

# expected keys from batch inputs
expected = {}
for bf in sorted(glob.glob(str(WQ / "batches" / "batch_*.json"))):
    for r in json.load(open(bf, encoding="utf-8")):
        expected[r["key"]] = r["platform"]

meta = {}
bad = []
for of in sorted(glob.glob(str(WQ / "out" / "batch_*.json"))):
    try:
        data = json.load(open(of, encoding="utf-8"))
    except Exception as e:
        bad.append(f"{os.path.basename(of)}: unreadable ({e})"); continue
    if not isinstance(data, list):
        bad.append(f"{os.path.basename(of)}: not a list"); continue
    for o in data:
        k = o.get("key")
        if not k: continue
        meta[k] = {
            "difficulty": norm_diff(o.get("difficulty")),
            "category": (o.get("category") or "").strip(),
            "tags": norm_tags(o.get("tags")),
            "summary": norm_sum(o.get("summary")),
        }

missing = [k for k in expected if k not in meta]
extra   = [k for k in meta if k not in expected]

(ROOT / "writeups_meta.json").write_text(
    json.dumps(meta, ensure_ascii=False, indent=1, sort_keys=True), encoding="utf-8")

print(f"expected={len(expected)} got={len(meta)} missing={len(missing)} extra={len(extra)} bad_files={len(bad)}")
for b in bad: print("  BAD", b)
for m in missing[:20]: print("  MISS", m)
if extra[:5]:
    for e in extra[:5]: print("  EXTRA", e)
# difficulty distribution
from collections import Counter
print("diff dist:", dict(Counter(v["difficulty"] for v in meta.values())))
print("no-summary:", sum(1 for v in meta.values() if not v["summary"]))
print("no-tags:", sum(1 for v in meta.values() if not v["tags"]))
print("no-category:", sum(1 for v in meta.values() if not v["category"]))
