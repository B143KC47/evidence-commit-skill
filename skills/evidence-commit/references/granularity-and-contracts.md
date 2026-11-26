# Commit Granularity Rubric & Tree-Bound Evidence Specification

## 1. Operational Granularity Matrix

| Scenario | Decision | Operational Test |
| :--- | :--- | :--- |
| **Helper extraction followed by bugfix** | **Split if reusable; merge if throwaway** | If the extraction eliminates duplication, preserves behavior on identical inputs, and would remain valuable even if the bugfix were reverted, commit `refactor` first, then `fix`. If the split invents an artificial intermediate signature immediately replaced in the next commit, keep together. |
| **Function signature change across 6 callers + types + tests** | **Single commit** | Acceptance criterion: the new contract holds everywhere. Omitting any caller breaks build/tests and violates bisectability. |
| **Bugfix + repo-wide auto-formatting** | **Split or drop formatting** | Formatting masks behavioral lines during review and breaks targeted `git revert` / `git blame`. |
| **TDD (write failing test -> write implementation)** | **Capture Red as `Before`, commit Green together** | Use the failing run as `Before` evidence (`--overlay`), then commit implementation + regression test as one complete fix commit. (Standalone characterization tests that already pass on `HEAD` may be committed independently.) |
| **Lockfile, codegen, or schema sync caused by a change** | **Same commit as its cause** | If a clean checkout of `T` would fail install, drift on codegen, or break contract checks without the generated file, include it. Unrelated dependency upgrades belong in their own commit. |
| **Multi-step database / protocol migration** | **Split by deployable compatibility states** | Commit 1: additive schema; Commit 2: dual-read/write migration; Commit 3: drop legacy field—each independently verifiable. |
| **Typo in published docs vs typo in uncommitted feature** | **Context-dependent** | Fixing a broken published install command is a complete user-visible `docs` fix; fixing a typo in code not yet committed folds into that feature commit. |
| **Multi-commit feature stack** | **Ordered atomic prefixes** | Every prefix commit must leave the repo buildable and passing tests (e.g., Commit 1: standalone local CLI + tests; Commit 2: remote GitHub PR publisher + tests). |

---

## 2. Why Tree-Bound Snapshot Verification Matters

Validating the working directory (`cwd`) and then running `git commit` has three classic failure modes:
1. **Unstaged Fix Trap:** A bug is fixed on disk, tests pass in `cwd`, and `git commit` records the broken staged index `T` alongside genuine passing logs.
2. **Hidden Flag Drift:** Files marked `assume-unchanged` (`h`) or `skip-worktree` (`S`) appear clean under `git diff --quiet` while diverging on disk from `T = git write-tree`.
3. **Skipped Test False Positive:** Test runners exit `0` when all selected tests are marked `SKIP` or `TODO` (`# pass 0`).

`proof_commit.mjs` closes all three:
- Freezes `P = rev-parse HEAD` (`null` on unborn root) and `T = git write-tree`.
- Materializes `T` (and `P` + declared `--overlay` test files for `Before`) using a private `GIT_INDEX_FILE` (`git read-tree` + `git checkout-index --all --prefix=...`) into `os.tmpdir()` **outside** the repository tree so ESM/Python module resolution cannot accidentally climb into parent directories.
- Rejects `After` runs with zero passing assertions or selected `SKIP`/`TODO`-only lines.
- Invokes `git commit --cleanup=verbatim -F <msg>` (with no path arguments) and immediately inspects `git cat-file commit HEAD` to confirm `tree === T`, `parent === P`, and unique `Evidence-ID`.

---

## 3. Canonical `Evidence-ID` Specification (`schema_version: 1`)

`Evidence-ID` is `sha256:<hex>` of the UTF-8 canonical JSON serialization (keys sorted lexicographically at every object level, arrays in recorded order, no whitespace, `null` for absent root parent, omitting `evidence_id`, `commit_oid`, and post-commit remote URLs) of:

```json
{
  "after": {
    "argv": ["node", "--test", "tests/example.test.mjs"],
    "exit_code": 0,
    "quotes": [
      { "end_byte": 42, "line": 3, "start_byte": 12, "stream": "stdout", "text": "ok 1 - accepts zero" }
    ],
    "stderr_sha256": "...",
    "stdout_sha256": "..."
  },
  "before": null,
  "case_name": "Zero quantity accepted",
  "overlay": [],
  "parent_oid": null,
  "schema_version": 1,
  "scope": "parser",
  "tree_oid": "...",
  "type": "feat",
  "ui": null,
  "verification_mode": "snapshot"
}
```

### Verbatim Quote Integrity & Privacy Rules
- Every `  | <line>` in the commit message corresponds to exact bytes `[start_byte, end_byte)` in the captured stream (excluding `\r\n` or `\n`), with **no** `.trim()`, tab substitution, or silent `[REDACTED]` mutation.
- Lines containing ANSI escape codes (`\x1b`), bare `\r` carriage-return overwrites, invalid UTF-8, normalized local home-directory paths (`os.homedir()`), or high-confidence credential tokens (`ghp_...`, `gho_...`, `github_pat_...`, `sk-...` >= 20 chars, `AKIA...`, private key headers) cause commit assembly to **hard-fail** without printing the sensitive value to logs.
