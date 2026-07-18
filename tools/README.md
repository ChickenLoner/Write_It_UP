# Write-up metadata generator

`writeups_meta.json` (repo root) drives the index cards — difficulty, category,
tags, and a one-line summary per lab. It is keyed by each markdown file's path
relative to the repo root. Entries that are missing degrade gracefully (no pill/tags).

When you add new write-ups, regenerate (or hand-edit the JSON directly).

## Flow

1. **Prep** — build compact extracts (header + scenario + task prompts) per lab,
   chunked into batches:

   ```
   uv run tools/prep_extract.py <workdir>
   # -> <workdir>/batches/batch_XX.json
   ```

2. **Generate** — for each `batches/batch_XX.json`, have an LLM produce a JSON
   array (same order) of `{key, difficulty, category, tags, summary}` and write it
   to `<workdir>/out/batch_XX.json`. Rules given to the model:

   - `key`: copy verbatim.
   - `difficulty`: one of `Very Easy | Easy | Medium | Hard | Insane | Unknown`.
     Use `difficulty_hint` if present, else infer conservatively; `Unknown` if no signal.
   - `category`: 1-3 word Title-Case domain (e.g. `Network Forensics`, `AD / Kerberos`).
   - `tags`: 3-6 short lowercase tags (tools/artifacts/techniques/MITRE IDs), no `#`.
   - `summary`: one active-voice sentence <=155 chars; never starts with "This lab".

   (Original run used Claude Code's Workflow tool, one agent per batch. A plain
   loop calling any capable model with the same prompt works too.)

3. **Merge** — validate + normalize all `out/batch_XX.json` into the sidecar:

   ```
   uv run tools/merge_meta.py <workdir> .
   # -> writeups_meta.json  (reports missing/extra keys + difficulty distribution)
   ```

Then run the site build (`build_md_to_html_with_toc.py`) as usual.
