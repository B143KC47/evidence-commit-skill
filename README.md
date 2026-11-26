# Evidence Commit

[![CI](https://github.com/B143KC47/evidence-commit-skill/actions/workflows/ci.yml/badge.svg)](https://github.com/B143KC47/evidence-commit-skill/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Language:** English | [简体中文](docs/README.zh-CN.md)

Software-engineering-grade atomic commits backed by **tree-bound verbatim execution proof** and **UI visual metadata** for AI coding agents (Google Antigravity, Codex CLI, and Claude Code).

> A commit is not `Ctrl+S`. Every commit should represent one complete, revertable, bisectable engineering transition—carrying a causal explanation of *why* it changed and exact byte-verified output proving the staged tree works.

## Why It Exists

AI coding agents routinely degrade Git history in three ways:
1. **Broken or tangled granularity**: either micro-commits (`WIP` -> `fix typo` -> `add test`) that break `git bisect`, or giant `git add .` sweeps mixing refactors, bugfixes, and stray files.
2. **Staged-tree vs. working-copy drift**: tests pass in a dirty working directory while `git commit` records a broken index (`git write-tree`).
3. **Paraphrased or skipped "proof"**: agents summarize terminal logs from memory or treat `0 passed / 1 skipped` (`exit 0`) as verification.

`evidence-commit` pairs an explicit **Commit Granularity & Contract Skill** (`SKILL.md`) with a **zero-dependency Node.js CLI** (`proof_commit.mjs`) that materializes the exact staged Git tree `T` in an isolated snapshot outside the repo, extracts exact byte-slice terminal quotes, checks public text against home-path/credential patterns, and verifies the resulting commit object via `git cat-file commit`.

## Install

Install via `skills.sh`:

```bash
npx skills add B143KC47/evidence-commit-skill
```

Install into a project workspace:

```bash
# Antigravity / Codex CLI
mkdir -p .agents/skills && cp -R skills/evidence-commit .agents/skills/evidence-commit

# Claude Code
mkdir -p .claude/skills && cp -R skills/evidence-commit .claude/skills/evidence-commit
```

## Quick Start

```bash
# 1. Stage explicit repository-relative paths (wildcards / git add . rejected)
node skills/evidence-commit/scripts/proof_commit.mjs stage \
  --files src/validator.mjs tests/validator.test.mjs

# 2. Initialize an evidence run bound to HEAD (P) and git write-tree (T)
node skills/evidence-commit/scripts/proof_commit.mjs init \
  --case "Zero quantity is accepted by order validator"

# 3. Capture Before on parent P using the staged regression test overlay
node skills/evidence-commit/scripts/proof_commit.mjs record \
  --phase before \
  --overlay tests/validator.test.mjs \
  -- node --test tests/validator.test.mjs

# 4. Capture After against an isolated snapshot of exact staged tree T
node skills/evidence-commit/scripts/proof_commit.mjs record \
  --phase after \
  -- node --test tests/validator.test.mjs

# 5. Assemble, privacy-scan, commit (--cleanup=verbatim), and verify commit object
node skills/evidence-commit/scripts/proof_commit.mjs commit \
  --type fix \
  --scope validator \
  --title "allow zero quantity in boundary check" \
  --why "Validator rejected 0 with strict > 0 comparison despite API contract allowing zero-delta adjustments; relax lower bound to >= 0." \
  --pick-before "accepts zero quantity" \
  --pick-after "accepts zero quantity"
```

## Verification Guarantee

Every `  | <line>` quote in a generated commit message is extracted from recorded raw stream byte offsets without `.trim()` or paraphrasing. Prior to committing, `proof_commit.mjs` scans the rendered commit body against configured local-path and token rules and hard-fails on matches.

## Run Tests

```bash
node --test tests/*.test.mjs
```
