"""
fix_answer_blocks.py
─────────────────────────────────────────────────────────────────────────────
Turns a bare fenced block that holds a question's ANSWER into the click-to-
reveal answer block BTLO write-ups already use:

    <details>
      <summary>Answer</summary>
    <pre><code>the answer</code></pre>
    </details>

Why: a bare ``` fence looks identical whether it holds a command or an answer,
so readers cannot tell them apart. The build styles <details> as a green
reveal block, separate from the dark terminal blocks used for real code.

How it tells answers from commands — STRUCTURE, never content (`whoami` is a
valid command and a valid answer). A write-up is a Q&A write-up if it has
question blockquotes ("> Q1 …", "> What is …"). Inside one question's section
(question → next question / heading / rule), a fence is converted only when
it has no language tag, is 1-3 lines long, and is the section's only fence — or
its LAST fence, in which case every earlier fence is kept as code (the usual
shape is a query or script followed by its one-line answer). Anything else is
reported for a human and left untouched:

    lang-tagged or long fence       (real code)
    fence outside any question      (commands in a machine write-up)
    several fences, last not short  (nothing to pick as the answer)
    short fence before the answer   (kept as code; listed so it can be checked)

Some write-ups have no "> question" lines: SOC alert playbooks answer each
"### Step" heading directly. `--heading-sections` makes a heading start a
section, exactly like a question. It needs `--only`, because in a machine
write-up the very same shape (a fence under a heading) is a command.
`--max-lines N` raises the 3-line limit for longer analyst notes.

Dry run by default.
    uv run fix_answer_blocks.py [--platform TryHackMe] [--apply]
    uv run fix_answer_blocks.py --platform LetsDefend --only "LetsDefend Alert" \\
        --heading-sections --max-lines 12
─────────────────────────────────────────────────────────────────────────────
"""

import argparse
import html
import os
import re
import sys
from pathlib import Path

import fix_paths                       # same file-walk policy as the other fixers

FENCE_RE   = re.compile(r"^(\s*)(```+|~~~+)(.*)$")
BQ_RE      = re.compile(r"^>\s*(.*)$")
# Blockquotes that are metadata or notes, not questions.
NOT_Q_RE   = re.compile(r"^(\*\*)?(tags|category|note|created|last updated)\b", re.I)
HEADING_RE = re.compile(r"^#{1,6}\s")
RULE_RE    = re.compile(r"^\s*(\* \* \*|\*\*\*|---)\s*$")
MAX_ANSWER_LINES = 3


def _is_question(line: str) -> bool:
    m = BQ_RE.match(line)
    if not m:
        return False
    body = m.group(1).strip()
    return bool(body) and not NOT_Q_RE.match(body)


def _answer_block(body: list[str]) -> list[str]:
    # rstrip: markdown2 expands a trailing tab to spaces, altering the answer.
    text = html.escape("\n".join(l.rstrip() for l in body), quote=False)  # & < > only
    return ["<details>", "  <summary>Answer</summary>",
            f"<pre><code>{text}</code></pre>", "</details>"]


def convert(text: str, heading_sections: bool = False,
            max_lines: int = MAX_ANSWER_LINES):
    """Return (new_text, converted, spaced, review).
    spaced = <details> blocks separated from a preceding "> question" line.
    review = [(line, reason, preview)]."""
    lines = text.split("\n")
    n = len(lines)

    # Pass 1: walk once, recording every fence and which question it belongs to.
    fences = []                    # dict(start, end, lang, body, qi, in_details)
    q_starts = []                  # line index of each question section
    cur_q = None
    in_details = False
    i = 0
    while i < n:
        line = lines[i]
        m = FENCE_RE.match(line)
        if m:
            j = i + 1
            while j < n and not lines[j].lstrip().startswith(m.group(2)[:3]):
                j += 1
            fences.append(dict(start=i, end=j, lang=m.group(3).strip(),
                               body=lines[i + 1:j], q=cur_q,
                               in_details=in_details))
            i = j + 1
            continue
        if "<details" in line:
            in_details = True
        if "</details>" in line:
            in_details = False
        if _is_question(line) or (heading_sections and HEADING_RE.match(line)):
            q_starts.append(i)
            cur_q = len(q_starts) - 1
        elif HEADING_RE.match(line) or RULE_RE.match(line):
            cur_q = None
        i += 1

    by_q = {}
    for f in fences:
        if not f["in_details"]:
            by_q.setdefault(f["q"], []).append(f)

    def answer_shaped(f):
        return (not f["lang"] and 1 <= len(f["body"]) <= max_lines
                and any(b.strip() for b in f["body"]))

    review, edits = [], []
    for q, fs in by_q.items():
        if q is not None and len(fs) > 1:
            # Query/script then answer: only the last fence can be the answer.
            if answer_shaped(fs[-1]):
                edits.append(fs[-1])
                for f in fs[:-1]:
                    if answer_shaped(f):       # short and untagged: worth a look
                        review.append((f["start"] + 1, "kept as code, precedes the answer",
                                       " | ".join(f["body"])[:70]))
            else:
                for f in fs:
                    review.append((f["start"] + 1, "several fences, last is not an answer",
                                   " | ".join(f["body"])[:70]))
            continue
        for f in fs:
            body = [b for b in f["body"]]
            preview = " | ".join(body)[:70]
            if q is None:
                review.append((f["start"] + 1, "outside any question", preview))
            elif f["lang"]:
                review.append((f["start"] + 1, f"language-tagged ({f['lang']})", preview))
            elif not (1 <= len(body) <= max_lines) or not any(b.strip() for b in body):
                review.append((f["start"] + 1, f"{len(body)} lines", preview))
            else:
                edits.append(f)

    # Question sections that already contain a <details> answer must not get a
    # second one — drop any edit whose section already has an Answer block.
    for f in list(edits):
        lo = q_starts[f["q"]]
        hi = q_starts[f["q"] + 1] if f["q"] + 1 < len(q_starts) else n
        if any("<summary>Answer</summary>" in l for l in lines[lo:hi]):
            edits.remove(f)
            review.append((f["start"] + 1, "section already has an Answer block",
                           " | ".join(f["body"])[:70]))

    # Apply bottom-up so earlier indices stay valid; blank line either side.
    for f in sorted(edits, key=lambda f: f["start"], reverse=True):
        block = _answer_block(f["body"])
        before_blank = f["start"] > 0 and lines[f["start"] - 1].strip() == ""
        after_blank = f["end"] + 1 >= n or lines[f["end"] + 1].strip() == ""
        repl = ([] if before_blank or f["start"] == 0 else [""]) + block + ([] if after_blank else [""])
        lines[f["start"]:f["end"] + 1] = repl

    # A <details> on the line right after a "> question" line is folded into the
    # blockquote by markdown (lazy continuation), so the answer renders INSIDE
    # the question box. A blank line in between ends the blockquote.
    spaced = 0
    k = 1
    while k < len(lines):
        if (lines[k].lstrip().startswith("<details")
                and lines[k - 1].lstrip().startswith(">")):
            lines.insert(k, "")
            spaced += 1
            k += 1
        k += 1

    return "\n".join(lines), len(edits), spaced, sorted(review)


def iter_writeups(platform: str | None, only: str | None = None):
    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d not in fix_paths.SKIP_FOLDERS]
        for name in files:
            if not name.endswith(".md"):
                continue
            p = Path(root, name)
            rel = Path(os.path.relpath(p, "."))
            if not fix_paths.is_writeup(rel):
                continue
            if platform and rel.parts[0].lower() != platform.lower():
                continue
            if only and only.lower() not in rel.as_posix().lower():
                continue
            yield rel


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--platform", help="top-level folder, e.g. TryHackMe")
    ap.add_argument("--only", help="only paths containing this text, e.g. 'LetsDefend Alert'")
    ap.add_argument("--heading-sections", action="store_true",
                    help="treat each heading as the question (SOC alert playbooks); needs --only")
    ap.add_argument("--max-lines", type=int, default=MAX_ANSWER_LINES,
                    help=f"longest fence to treat as an answer (default {MAX_ANSWER_LINES})")
    ap.add_argument("--apply", action="store_true", help="write changes (default: dry run)")
    args = ap.parse_args()
    if args.heading_sections and not args.only:
        ap.error("--heading-sections needs --only: fences under headings are "
                 "commands in machine write-ups")

    total = spaced_total = files_changed = 0
    all_review = []
    for rel in sorted(iter_writeups(args.platform, args.only)):
        text = rel.read_text(encoding="utf-8")
        new, count, spaced, review = convert(text, args.heading_sections, args.max_lines)
        for line, why, prev in review:
            all_review.append((rel, line, why, prev))
        if count or spaced:
            total += count
            spaced_total += spaced
            files_changed += 1
            if args.apply:
                rel.write_text(new, encoding="utf-8", newline="\n")

    verb = "converted" if args.apply else "would convert"
    print(f"{verb} {total} answer(s), separated {spaced_total} <details> from its "
          f"question blockquote, in {files_changed} file(s)")
    if all_review:
        print(f"\nleft untouched, needs a human ({len(all_review)}):")
        for rel, line, why, prev in all_review:
            print(f"  {rel.name}:{line}  [{why}]  {prev}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
