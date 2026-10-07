# Write_It_UP

Personal CTF / cybersecurity lab write-up collection. Markdown write-ups are
built into a SOC-themed static site by `build_md_to_html_with_toc.py` and
deployed to **Cloudflare Pages** on every push to `main`
(`.github/workflows/cloudflare-deploy.yml`). Live at
<https://writeups.chicken0248.fyi>.

## Adding a write-up

Export from Joplin, drop the folder (markdown + its `_resources/`) into the
right platform folder, then:

```
uv run publish.py            # fix + validate + report
uv run publish.py --push     # ...and commit + push
```

`publish.py` merges `_resources/` into `resources/` and rewrites the links,
expands Joplin's `[toc]` token, turns bare ``` answers into answer blocks (see
*Answer blocks*), scaffolds a `writeups_meta.json` entry for any write-up missing
one, and verifies every referenced image exists. It refuses to
push when an image is missing. Cloudflare deploys ~2 minutes after the push.

The folder path drives the platform badge, colours and index grouping, so put
the file under the correct platform directory. Markdown at the repo root is
never published — it is treated as repo documentation.

`fix_paths.py` and `fix_joplin_toc.py` still exist and still work (that is what
`automated_fix.bat` runs); `publish.py` calls into them and adds the validation.

### Answer blocks

Lab answers are click-to-reveal blocks, never bare fences, so a reader can tell
an answer from a command:

```html
<details>
  <summary>Answer</summary>
<pre><code>the answer, HTML-escaped</code></pre>
</details>
```

Exports from Joplin come in with bare ``` fences. `publish.py` converts them
automatically, but only in write-ups that are **new or changed in git** — it never
rewrites the rest — and prints what it converted, what it left alone and why, and
a `⚠` line for every fence it was unsure about (a command or an answer? ask
Claude Code). `--skip-answers` turns the step off. The same logic is also
available by hand as `fix_answer_blocks.py` (`--platform <Folder>`, dry run unless
`--apply`). It decides by
structure, not content (`whoami` is a valid command and a valid answer): in a
question's section, the sole — or last — untagged 1-3 line fence is the answer;
earlier fences are code and stay. Lang-tagged or long fences, fences outside any
question (machine write-ups have none), and anything ambiguous are listed for a
human and left alone. A file where under half the fences sit under a question is
skipped whole (`--min-qa-share`): machine write-ups sometimes quote a note with
`>` and the command below it would otherwise be mistaken for an answer — HTB
Machines would have lost 4 commands that way. Pass `--platform` (and `--only`)
so it only ever runs on the platform being checked.
Two kinds of write-up have no questions and answer each heading instead: SOC
alert playbooks (`LetsDefend Alert`, each `### Step`) and CTF write-ups
(`Unlisted Labs`, each challenge heading, where the answer is a flag or a short
value). They take `--only "<folder>" --heading-sections --max-lines <N>` (12 for
alerts, whose analyst notes run long; 3 for CTFs), which refuses to run without
`--only` because under a heading a machine write-up's fence is a command. In that
mode a section whose fences are all single-line flags (`word{...}`) has every one
converted, since one challenge can hold several flags; and a fence that starts
with a shell prompt (`$ `, `# `, `PS>`, `sudo `) is always kept as code. `publish.py`
does not use this mode: for a new write-up in either folder it prints the exact
command to run instead.

The build puts a blank line around every `<details>` before rendering, because
markdown2 otherwise folds the tag into the previous paragraph or blockquote.

### Metadata — Claude fills this in

`writeups_meta.json` drives the index card: difficulty pill, category, tags,
summary. `publish.py` scaffolds a blank entry but cannot fill it, because the
values require reading the lab. Without a summary the card renders bare.

**This is a job for Claude, not the user.** Whenever `publish.py` reports
scaffolded or blank entries — or the user adds a write-up and asks to publish —
read each new write-up and write the entry directly into `writeups_meta.json`.
Do not hand the blank JSON back and ask the user to complete it. Ask only when
the lab genuinely gives no signal for a field.

```json
"<Folder>/<[Platform Write-up] Name>.md": {
  "difficulty": "Very Easy | Easy | Medium | Hard | Insane | Unknown",
  "category": "1-3 word Title-Case domain, e.g. Network Forensics / AD / Kerberos",
  "tags": ["3-6", "short", "lowercase", "tools-or-techniques"],
  "summary": "One active-voice sentence <=155 chars; never start with \"This lab\""
}
```

How to derive each field — read the write-up's scenario block, its questions,
and the tools that actually appear in the commands and screenshots:

- **difficulty** — use the platform's own label when the write-up states one
  (HTB, THM and CyberDefenders normally do). Never invent one to avoid
  `Unknown`; `Unknown` is the correct answer when there is no signal.
- **category** — the investigative domain, not the platform. **Reuse an
  existing category** unless nothing fits; there are 22 in use and the index
  should not sprout near-duplicates. Most common, by entry count:

  `Windows DFIR` (59) · `Malware Analysis` (54) · `Network Forensics` (50) ·
  `Memory Forensics` (43) · `AD / Kerberos` (27) · `Incident Response` (19) ·
  `Linux DFIR` (18) · `Reverse Engineering` (17) · `Email / Phishing` (13) ·
  `Log Analysis` (12) · `Web Exploitation` (10) · `Threat Intel` (9)
- **tags** — concrete tools, artifacts, techniques, MITRE IDs. Lowercase, no
  `#`. 875 tags are in use; the most common are `wireshark`, `pcap`,
  `volatility`, `cyberchef`, `c2`, `virustotal`, `powershell`, `sysmon` — reuse
  those spellings rather than inventing variants. Skip generic filler like
  `forensics` or `ctf` that every entry would carry.
- **summary** — what the reader *does* in this lab, active voice. Target ≤155
  characters; existing entries run 105-163 with a median of 135, so aim for
  ~135 and treat 155 as the ceiling. Never open with "This lab" / "This
  write-up" — no existing entry does. Be specific enough to distinguish it from
  the other 360 entries.

Match the surrounding entries' voice — read a few neighbours in the same
platform folder before writing. Keep it a single-lab edit; the batch pipeline
in `tools/README.md` is only for regenerating everything at once.

## Build

`build/` is generated by CI and git-ignored — never commit it. To build locally
on Windows run with `PYTHONUTF8=1` (the script prints ✅, which crashes the
cp874 console otherwise). `SKIP_IMAGE_OPT=1` skips WebP encoding for a fast
local render.

**The build returns a real exit code and the deploy depends on it.** The deploy
uploads whatever is in `build/`, so a build that fails halfway but exits 0 would
publish a partial site over a working one. It exits non-zero when no write-ups
are found, when any page fails to render, or when the page count is not
`write-ups + index + 404`. The workflow then sanity-checks the tree before
uploading: `index.html`/`404.html` non-empty, at least 100 HTML pages, and
`index.html` must actually contain `class="wrow"` cards. Do not weaken these to
get a deploy through.

What the build does and does not publish:

- Write-ups only. Markdown at the repo root (`README.md`, `CLAUDE.md`) and repo
  docs anywhere (`SKIP_NAMES`) are never rendered; `tools/` and `re-design/`
  are not walked. `fix_paths.py` and `fix_joplin_toc.py` apply the same policy —
  they rewrite write-ups only, never repo docs.
- Joplin centres screenshots in raw HTML (`<div align=center>`). Markdown
  ignores the contents of a block-level HTML tag, so the build injects
  `markdown="1"` into block tags and enables markdown2's `markdown-in-html`.
  Without it those images render as literal `![shot.png](...)` text — this was
  silently true for 205 images across 56 write-ups. Fenced code blocks are
  excluded so an example `<div>` stays literal.
- Shared CSS is written once to `build/assets/{base,article,index}.css` with a
  content-hash query string, not inlined per page.
- `build/resources/` gets only the images the generated HTML actually
  references, re-encoded to **lossless** WebP (~58% of the PNG bytes, no
  quality loss — readers zoom into hex dumps, so lossy is not acceptable).
  Originals are kept whenever WebP would be larger. `<img>` tags are rewritten
  in a post-pass and stamped with intrinsic `width`/`height` to stop layout
  shift.
- Unreferenced files in `resources/` are skipped, not deleted. Be careful
  reasoning about that count: 202 of the files once assumed to be orphans were
  in fact the raw-HTML images above, unreferenced only because of the render
  bug. Never delete from `resources/` based on the skip count.
- Encoding is cached in `.imgcache/` (git-ignored, restored by `actions/cache`
  in CI). Resource filenames are content hashes, so a cached WebP never goes
  stale — only newly added screenshots cost encode time.
- The build reports referenced images **missing** from `resources/`. Those
  render broken. Files lost in the `_resources/` → `resources/` rename are
  usually still in git history:
  `git rev-list --all --objects | grep <name>` then
  `git cat-file -p <sha> > resources/<name>`.
- `sitemap.xml`, `robots.txt` and `_headers` are generated from the write-up
  list, plus a styled `404.html`.

## Hosting

Cloudflare Pages, migrated from GitHub Pages on 2026-07-23. DNS is at
**Porkbun** — `writeups` is a CNAME to `write-it-up.pages.dev`. The zone stays
on Porkbun: Cloudflare only needs to own the zone for apex domains, not
subdomains.

Deployment is **Direct Upload** from Actions, not Cloudflare's git integration,
because Cloudflare caps builds at 20 minutes on every plan and the cold WebP
encode exceeds that. A Direct Upload project cannot be converted to git
integration later.

Cloudflare serves `foo.html` at `/foo` and 308-redirects the `.html` form, so
the index and sitemap emit **extension-less** URLs. That is Cloudflare-specific:
GitHub Pages 404s those paths.

Without a `404.html`, Cloudflare falls back to `index.html` with HTTP 200 for
every unmatched path — which silently resurrects deleted pages and makes every
typo an indexable duplicate. The build always writes one.

Deploys are serialised (`concurrency: cloudflare-pages`, cancel-in-progress) so
two quick pushes cannot publish the older build last.

Every same-repo pull request is also built and uploaded as a **preview**
deployment by `cloudflare-preview.yml`, at `<branch>.write-it-up.pages.dev`
(the URL is in the job summary). Production is unaffected — custom domains only
serve the production deployment, and the preview job refuses to run for `main`.
Use it to check a change on a real URL before merging.

**GitHub Pages was retired on 2026-10-07.** `deploy.yml` (the manual-only
rollback workflow) was removed and the Pages site unpublished in repo settings;
Cloudflare is the only host. Rolling back a bad deploy now means reverting the
commit on `main` (the deploy runs on every push), or rolling back to an earlier
production deployment from the Cloudflare dashboard. Going back to GitHub Pages
would mean restoring the workflow (`git show eb48bdb:.github/workflows/deploy.yml`),
re-enabling Pages and the custom domain, repointing the Porkbun CNAME, and
reverting the extension-less URL commit, so treat it as a rebuild, not a rollback.

### Capacity

**531 MB across 8,074 files**, averaging ~1.4 MiB and ~21 images per write-up.

Cloudflare Pages free has no documented total-size cap; the binding limits are
**20,000 files per deployment** (~570 more write-ups at the current rate) and
25 MiB per file. Static-asset requests are free and unlimited. The workflow
fails the build above 19,000 files and warns above 15,000.

For context on why the WebP pass mattered: GitHub Pages caps a published site
at **1 GB and that is a hard limit**. Before WebP the site was ~0.96 GiB —
roughly 40 MB from failing to deploy at all.
