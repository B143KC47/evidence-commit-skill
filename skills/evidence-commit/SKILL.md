---
name: evidence-commit
description: >-
  Partition dirty working-tree changes into software-engineering-grade atomic commits
  and create commits backed by tree-bound verbatim Before/After execution logs, causal
  rationale, and UI visual proof. Use whenever deciding whether/how to git commit,
  splitting or coalescing diffs, committing a bugfix or UI change with empirical proof,
  or invoking /evidence-commit.
---

# Evidence Commit

A commit is not `Ctrl+S`. Every commit in shared history must be a **revertable, bisectable, single-intent transition** accompanied by **causal rationale (`Why`)** and **tree-bound empirical proof (`Evidence`)**.

## 1. Decide Commit Worthiness & Granularity First

> **Core Granularity Rule:**
> Commit when you can state **one concrete acceptance condition**, the staged tree contains the **complete** set of changes needed to satisfy that condition (implementation + callers + tests/types/schema), and that exact staged state passes verification. Split whenever removing a subset leaves two parts that each have an independently valuable engineering outcome and verification check.

### Four Hard Gates Before Committing
1. **Authority Gate (When NOT to commit):**
   - Do **not** commit if tests/build fail, if debugging scaffolding remains, or if you are on the default branch (`main`/`master`) or in a user-dirtied working tree without explicit user permission to commit.
2. **Splitting Gate (Never Too Coarse — *Tidy First*):**
   - Separate **structural** changes (behavior-preserving extract/move/rename/format) from **behavioral** changes (`fix`, `feat`, `perf`). Commit the verified structural refactor first, then the behavioral change.
   - Split unrelated fixes/features that someone might reasonably `git revert` independently.
3. **Coalescing Gate (Never Too Fine — No Broken History):**
   - Keep an interface/logic change, all affected call sites, lockfile/codegen updates caused by it, and its regression test **in the same commit**. Never create `WIP` -> `fix typo` -> `add test` micro-commit chains.
4. **Hunk/Index Gate (Never `git add .`):**
   - Inspect `git status --short` and `git diff --cached` first. Stage explicit paths (or hunks via `git add -p` when a file mixes concerns). If the index already contains unrelated user-staged work, stop rather than wiping or committing it.

For edge cases (coupled refactors, TDD, migrations, lockfiles, stacked commits), read [granularity-and-contracts.md](./references/granularity-and-contracts.md).

---

## 2. Match Evidence to What the Commit Claims

Never rely on commit-type prefixes alone—satisfy **every** contract implied by the actual change:

| Claimed Change | Required `Before` / Baseline | Required `After` (on Exact Staged Tree `T`) |
| :--- | :--- | :--- |
| **Bugfix (`fix`)** | Same probe triggers the concrete defect on parent `P` (via `--overlay` if the regression test is new) | Same probe passes on candidate tree `T` with target assertion actually executed (never skipped) |
| **Feature (`feat`)** | Parent baseline capability/absence noted (`root: none` on initial commit) | Real entrypoint/acceptance test runs on `T` and verifies expected output |
| **Refactor (`refactor`)** | Observable invariant measured on parent `P` | Same check runs on `T` demonstrating behavioral preservation |
| **Performance (`perf`)** | Fixed-workload baseline measurement on `P` | Comparable measurement + correctness check on `T` |
| **UI Change** | Prior screenshot of same route/state/viewport via `attach-ui --before` (plus runtime `Before` if fixing a behavioral UI bug) | Matching screenshot (`attach-ui --after`) + passing verification run on `T` |
| **Docs / Test / Chore** | Broken command, coverage gap, or build rule stated | Executed command/test/package verification on `T` |

---

## 3. Execute Deterministic Tree-Bound Commit via `proof_commit.mjs`

Always run [proof_commit.mjs](./scripts/proof_commit.mjs) rather than hand-typing terminal quotes into `git commit -m`. It freezes `P = HEAD` and `T = git write-tree`, executes checks in an isolated snapshot outside the repo so unstaged edits cannot fake a pass, extracts exact byte-slice quotes without trimming, scans public text for home-path/token leaks, commits with `--cleanup=verbatim`, and verifies the resulting Git commit object.

### Step 1 — Stage Explicit Files & Initialize Run
```bash
node <skill-dir>/scripts/proof_commit.mjs stage --files src/parser.mjs tests/parser.test.mjs
node <skill-dir>/scripts/proof_commit.mjs init --case "Zero quantity is accepted by order validator"
```

### Step 2 — Record `Before` (Required for `fix`, `refactor`, and `perf`)
If the regression test was newly added in staged tree `T`, pass `--overlay` so the exact staged test runs against unmodified parent `P`:
```bash
node <skill-dir>/scripts/proof_commit.mjs record \
  --phase before \
  --overlay tests/parser.test.mjs \
  -- node --test tests/parser.test.mjs
```

### Step 3 — Record `After` Against Exact Staged Tree `T`
```bash
node <skill-dir>/scripts/proof_commit.mjs record \
  --phase after \
  -- node --test tests/parser.test.mjs
```
*(Default `--mode snapshot` materializes `T` into an isolated temp directory outside the repo. Use `--mode workspace` only when local `.venv`/`node_modules` cannot resolve outside the workspace; the commit will truthfully record `Verification: workspace`.)*

### Step 4 — Attach UI Screenshots (Whenever Visual Output Changes)
```bash
node <skill-dir>/scripts/proof_commit.mjs attach-ui \
  --before ./artifacts/before-mobile.png \
  --after ./artifacts/after-mobile.png \
  --route "/dashboard" \
  --viewport "390x844" \
  --notes "Filter bar wraps cleanly at 390px with zero horizontal overflow"
```

### Step 5 — Verify & Create the Commit
```bash
node <skill-dir>/scripts/proof_commit.mjs commit \
  --type fix \
  --scope parser \
  --title "allow zero quantity in boundary validation" \
  --why "Validator used strict > 0 check while API contract permits 0, rejecting valid zero-delta orders; relax lower bound to >= 0 and lock with boundary test." \
  --pick-before "accepts zero quantity" \
  --pick-after "accepts zero quantity"
```
Confirm `proof_commit.mjs` reports `COMMIT_VERIFIED` (`tree`, `parent`, and `Evidence-ID` verified via `git cat-file commit`).

### Step 6 — Publish Per-Commit Verbatim & Visual Proof to GitHub PR (`gh >= 2.103.0`)
After pushing your feature/fix branch (`git push -u origin <branch>`), publish or update the Pull Request with native `--attach` screenshot uploads and cryptographic/remote read-back verification:
```bash
node <skill-dir>/scripts/proof_commit.mjs publish-pr \
  --base main \
  --title "fix(parser): allow zero quantity in boundary validation" \
  --closes 42
```
`publish-pr` re-verifies every commit's Git object, `Evidence-ID`, raw log hashes, and PNG integrity across `base..HEAD`, verifies `origin` matches `--repo` on `github.com` (pass `--allow-custom-origin --repo host/owner/repo` for enterprise Git remotes while keeping `ls-remote` OID checks, or `--skip-push-check` for offline mock tests), uploads digest-bound `evc-<shortSha>-<before|after>-<sha256>` images from a clean staging working directory, verifies hosted screenshot bytes match each manifest's SHA-256 digest (pass `--allow-private-unverified-assets` on private repositories with cookie-gated attachments), preserves human PR notes outside its bounded report markers, recovers cleanly if a prior `--attach` upload partially succeeded, and verifies same-repo `OPEN` state, `headRefOid`, `baseRefName`, `baseRefOid` range consistency, and exact report read-back on GitHub.

### Optional — Record Independent Reviewer Model + Harness Provenance
When (and **only** when) a separate, independent model/agent review actually inspected the staged diff or branch—never record unexecuted reviews or the authoring session itself—append `--reviewed-by "<model> via <harness>"` (self-attested provenance; repeatable; also accepts `<model> @ <harness>` or `<model> [<harness>]`) to `commit` (emits `AI-Reviewed-By:` trailer bound into `Evidence-ID`) or `publish-pr` (records `Branch AI-Reviewed-By:` locally per HEAD OID; clear via `--clear-reviewers`):
```bash
--reviewed-by "claude-opus-5-5-high via Antigravity CLI" \
--reviewed-by "gpt-6.2-astra (xhigh) via Codex CLI"
```
