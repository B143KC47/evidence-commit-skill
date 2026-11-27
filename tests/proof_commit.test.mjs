import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  canonicalJson,
  computeEvidenceId,
  decodeStrictUtf8AndValidateDisplay,
  makeSolidPng,
  normalizeReviewers,
  parseImageDimensions,
  parseReviewerSpec,
  scanPublicTextPrivacy,
  splitExactLines,
  validateRunId,
} from "../skills/evidence-commit/scripts/proof_commit.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT_PATH = path.resolve(
  __dirname,
  "..",
  "skills",
  "evidence-commit",
  "scripts",
  "proof_commit.mjs",
);

function makeTempRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "evcommit-test-"));
  const runGit = (...args) => {
    const res = spawnSync("git", args, { cwd: dir, encoding: "utf8", windowsHide: true });
    assert.equal(res.status, 0, `git ${args.join(" ")} failed: ${res.stderr}`);
    return res.stdout.trim();
  };
  runGit("init", "-b", "main");
  runGit("config", "user.name", "Test Author");
  runGit("config", "user.email", "author@example.com");
  return { dir, runGit };
}

function runCli(cwd, args, customScriptPath = SCRIPT_PATH) {
  return spawnSync(process.execPath, [customScriptPath, ...args], {
    cwd,
    encoding: "utf8",
    windowsHide: true,
  });
}

const VALID_PNG_1X1 = makeSolidPng(1, 1, [220, 50, 47, 255]);
const VALID_PNG_2X2 = makeSolidPng(2, 2, [46, 160, 67, 255]);

test("canonical Evidence-ID matches deterministic golden vector", () => {
  const sample = {
    type: "feat",
    scope: "core",
    schema_version: 1,
    parent_oid: null,
    tree_oid: "0123456789abcdef0123456789abcdef01234567",
    verification_mode: "snapshot",
    case_name: "golden vector check",
    overlay: [],
    before: null,
    after: {
      argv_display: "node probe.mjs",
      exit_code: 0,
      mode: "snapshot",
      stdout_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      stderr_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      quotes: [{ stream: "stdout", line: 1, start_byte: 0, end_byte: 7, text: "PASS ok" }],
    },
    ui: null,
  };
  const json = canonicalJson(sample);
  assert.equal(json.startsWith('{"after":{"argv_display":'), true);
  assert.equal(
    computeEvidenceId(sample),
    "sha256:068843fdfc8e70848e65562a48bf162a9eed030482cebfca96ce546e7c84ca10",
  );

  // schema_version 2 golden vector with sorted reviewers
  const sampleV2 = {
    ...sample,
    reviewers: normalizeReviewers([
      "gpt-6.2-astra (xhigh) via Codex CLI",
      "claude-opus-5-5-high via Antigravity CLI",
    ]),
    schema_version: 2,
  };
  assert.equal(
    computeEvidenceId(sampleV2),
    "sha256:38b4014ca2dd8522d9ac429b5faf4db54f03c17cc6641262191bf05e111f08e3",
  );
});

test("CLI entry point runs properly from an installation path containing spaces", () => {
  const dirWithSpaces = fs.mkdtempSync(path.join(os.tmpdir(), "evcommit space dir "));
  try {
    const copiedScript = path.join(dirWithSpaces, "proof_commit.mjs");
    fs.copyFileSync(SCRIPT_PATH, copiedScript);
    const res = spawnSync(process.execPath, [copiedScript, "--help"], {
      encoding: "utf8",
      windowsHide: true,
    });
    assert.equal(res.status, 0);
    assert.match(res.stdout, /Subcommands:/);
  } finally {
    fs.rmSync(dirWithSpaces, { recursive: true, force: true });
  }
});

test("counterexample 1: unstaged working-copy fix CANNOT certify a broken staged tree", () => {
  const { dir } = makeTempRepo();
  try {
    fs.writeFileSync(
      path.join(dir, "validator.mjs"),
      "export const acceptsZero = (n) => n > 0;\n",
      "utf8",
    );
    fs.writeFileSync(
      path.join(dir, "probe.mjs"),
      [
        'import { acceptsZero } from "./validator.mjs";',
        "const actual = acceptsZero(0);",
        'console.log(`accepts-zero | expected=true actual=${actual}`);',
        "process.exit(actual ? 0 : 1);",
      ].join("\n"),
      "utf8",
    );

    assert.equal(runCli(dir, ["stage", "--files", "validator.mjs", "probe.mjs"]).status, 0);
    assert.equal(runCli(dir, ["init", "--case", "zero boundary"]).status, 0);

    // Fix ONLY in the working copy without re-staging
    fs.writeFileSync(
      path.join(dir, "validator.mjs"),
      "export const acceptsZero = (n) => n >= 0;\n",
      "utf8",
    );

    const rec = runCli(dir, ["record", "--phase", "after", "--", "node", "probe.mjs"]);
    assert.equal(rec.status, 0);
    assert.match(rec.stdout, /exit=1/);

    const commitRes = runCli(dir, [
      "commit",
      "--type",
      "feat",
      "--scope",
      "validator",
      "--title",
      "attempt to certify broken staged tree",
      "--why",
      "Attempted commit where only unstaged working tree fixed the bug while staged index is broken.",
    ]);
    assert.notEqual(commitRes.status, 0);
    assert.match(commitRes.stderr, /non-zero code 1/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("counterexample 2: skipped tests exiting 0 are rejected as invalid After proof", () => {
  const { dir } = makeTempRepo();
  try {
    fs.writeFileSync(
      path.join(dir, "skipped.test.mjs"),
      'import test from "node:test";\ntest("placeholder", { skip: true }, () => {});\n',
      "utf8",
    );
    assert.equal(runCli(dir, ["stage", "--files", "skipped.test.mjs"]).status, 0);
    assert.equal(runCli(dir, ["init", "--case", "skip guard"]).status, 0);
    const rec = runCli(dir, ["record", "--phase", "after", "--", "node", "--test", "skipped.test.mjs"]);
    assert.equal(rec.status, 0);
    assert.match(rec.stdout, /exit=0/);

    const verifyRes = runCli(dir, [
      "verify",
      "--type",
      "test",
      "--title",
      "add skipped test",
      "--why",
      "Verify that a test suite with zero executed passing tests is rejected even when exiting 0.",
    ]);
    assert.notEqual(verifyRes.status, 0);
    assert.match(verifyRes.stderr, /zero passing tests|SKIP\/TODO/i);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("counterexample 3: retroactive --overlay captures genuine Before failure on P, blocks mismatching probe cmd, and passes After on T", () => {
  const { dir, runGit } = makeTempRepo();
  try {
    fs.writeFileSync(
      path.join(dir, "math.mjs"),
      "export function clampNonNegative(x) { return x > 0 ? x : 1; }\n",
      "utf8",
    );
    runGit("add", "math.mjs");
    runGit("commit", "-m", "initial buggy math");
    const parentOid = runGit("rev-parse", "HEAD");

    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(
      path.join(dir, "math.mjs"),
      "export function clampNonNegative(x) { return x >= 0 ? x : 0; }\n",
      "utf8",
    );
    fs.writeFileSync(
      path.join(dir, "tests", "math.test.mjs"),
      [
        'import { clampNonNegative } from "../math.mjs";',
        "const got = clampNonNegative(0);",
        'console.log(`clamp-zero #expected=0 #actual=${got}`);',
        "process.exit(got === 0 ? 0 : 1);",
      ].join("\n"),
      "utf8",
    );

    assert.equal(runCli(dir, ["stage", "--files", "math.mjs", "tests/math.test.mjs"]).status, 0);
    const stagedTree = runGit("write-tree");
    assert.equal(runCli(dir, ["init", "--case", "clampNonNegative preserves 0"]).status, 0);

    const bef = runCli(dir, [
      "record",
      "--phase",
      "before",
      "--overlay",
      "tests/math.test.mjs",
      "--",
      "node",
      "tests/math.test.mjs",
    ]);
    assert.equal(bef.status, 0, bef.stderr);
    assert.match(bef.stdout, /exit=1/);

    const aft = runCli(dir, ["record", "--phase", "after", "--", "node", "tests/math.test.mjs"]);
    assert.equal(aft.status, 0, aft.stderr);
    assert.match(aft.stdout, /exit=0/);

    const com = runCli(dir, [
      "commit",
      "--type",
      "fix",
      "--scope",
      "math",
      "--title",
      "preserve zero in clampNonNegative boundary",
      "--why",
      "clampNonNegative used strict x > 0 and fallback 1, corrupting zero inputs into 1; use x >= 0 and fallback 0.",
      "--pick-before",
      "clamp-zero",
      "--pick-after",
      "clamp-zero",
    ]);
    assert.equal(com.status, 0, com.stderr);
    assert.match(com.stdout, /COMMIT_VERIFIED/);

    const rawCommit = runGit("cat-file", "commit", "HEAD");
    assert.match(rawCommit, new RegExp(`^tree ${stagedTree}$`, "m"));
    assert.match(rawCommit, new RegExp(`^parent ${parentOid}$`, "m"));
    assert.match(rawCommit, /\| clamp-zero #expected=0 #actual=1/);
    assert.match(rawCommit, /\| clamp-zero #expected=0 #actual=0/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("privacy, byte-fidelity, run-id containment, and directory-stage guards hold", () => {
  // Normal word 'task-runner' AND REST route 'GET /users/octocat' MUST pass
  assert.doesNotThrow(() => {
    scanPublicTextPrivacy(
      "ok 1 - task-runner GET /users/octocat returned 200",
      "unit_test",
      "C:\\Users\\demo_user",
    );
  });

  // Home path variants & non-ASCII Windows usernames MUST throw without echoing username
  for (const leak of [
    "at C:\\Users\\demo_user\\project\\app.mjs:10:2",
    "at C:\\Users\\张三\\project\\app.mjs:10:2",
    "at /Users/alice/project/app.mjs:10:2",
  ]) {
    assert.throws(
      () => scanPublicTextPrivacy(leak, "unit_test", "C:\\Users\\demo_user"),
      /Privacy gate blocked/,
    );
  }

  // Trailing bare CR and UTF-8 BOM MUST fail verbatim display check
  const bareCrLines = splitExactLines(Buffer.from("spoof\roverwrite", "utf8"));
  assert.throws(
    () => decodeStrictUtf8AndValidateDisplay(bareCrLines[0].buf, "cr_test"),
    /bare CR/,
  );
  const trailingCrLines = splitExactLines(Buffer.from("trailing\r", "utf8"));
  assert.throws(
    () => decodeStrictUtf8AndValidateDisplay(trailingCrLines[0].buf, "trailing_cr"),
    /bare CR/,
  );
  const bomBuf = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("hello", "utf8")]);
  assert.throws(() => decodeStrictUtf8AndValidateDisplay(bomBuf, "bom_test"), /BOM/);

  // Traversal run-id MUST fail
  assert.throws(() => validateRunId("../escape"), /Invalid run-id/);
});

test("PNG CRC/IDAT integrity validation rejects corrupted images while accepting valid PNGs", () => {
  assert.deepEqual(parseImageDimensions(VALID_PNG_1X1), { format: "png", width: 1, height: 1 });
  assert.deepEqual(parseImageDimensions(VALID_PNG_2X2), { format: "png", width: 2, height: 2 });

  const corrupted = Buffer.from(VALID_PNG_2X2);
  corrupted[corrupted.length - 16] ^= 0xff; // flip byte in IDAT
  assert.throws(() => parseImageDimensions(corrupted), /CRC mismatch|Corrupted PNG/);
});

test("reviewer model + harness provenance validates syntax, deduplicates, blocks spoofing/leaks without echoing secrets, and binds into commit & Evidence-ID", () => {
  assert.deepEqual(parseReviewerSpec("claude-opus-5-5-high via Antigravity CLI"), {
    harness: "Antigravity CLI",
    model: "claude-opus-5-5-high",
  });
  assert.deepEqual(parseReviewerSpec("claude-opus@20250514 via Vertex AI"), {
    harness: "Vertex AI",
    model: "claude-opus@20250514",
  });
  assert.deepEqual(parseReviewerSpec("claude-opus@20250514 @ Vertex AI"), {
    harness: "Vertex AI",
    model: "claude-opus@20250514",
  });
  assert.deepEqual(parseReviewerSpec("gpt-6.2-astra (xhigh) @ Codex CLI"), {
    harness: "Codex CLI",
    model: "gpt-6.2-astra (xhigh)",
  });
  assert.deepEqual(parseReviewerSpec("model (high) [Claude Code CLI]"), {
    harness: "Claude Code CLI",
    model: "model (high)",
  });

  // Canonical order-independent sorting & case-insensitive deduplication
  const dedupedA = normalizeReviewers([
    "gpt-6.2-astra (xhigh) [Codex CLI]",
    "claude-opus-5-5-high via Antigravity CLI",
    "CLAUDE-OPUS-5-5-HIGH @ antigravity cli",
  ]);
  const dedupedB = normalizeReviewers([
    "claude-opus-5-5-high via Antigravity CLI",
    "gpt-6.2-astra (xhigh) via Codex CLI",
  ]);
  assert.deepEqual(dedupedA, dedupedB);
  // Order-independent canonical casing deduplication
  assert.deepEqual(
    normalizeReviewers(["opus via agy", "Opus via AGY"]),
    normalizeReviewers(["Opus via AGY", "opus via agy"]),
  );
  assert.throws(() => normalizeReviewers([""]), /Invalid --reviewed-by/);

  // Reject missing harness, multi-separator ambiguity, bidi/zero-width overrides, backticks, HTML markers, trailer spoofing, and secret leaks — NEVER echoing secrets!
  const fakeSecret = `ghp_${"A1b2C3d4E5f6G7h8I9j0K1l2M3n4"}`;
  for (const bad of [
    "claude-opus-5-5",
    `claude-opus-5-5 ${fakeSecret}`,
    "via Claude Code CLI",
    "A via via B",
    "A @ @ B",
    "claude-opus-5 @ Claude Code via Bedrock",
    "foo via bar [Codex CLI]",
    "claude-opus-5-5 \u202ehigh via Antigravity CLI",
    "claude-opus-5-5 \u200bhigh via Antigravity CLI",
    "claude-opus-5-5-α via Antigravity CLI",
    "claude-opus-5-5 `high` via Antigravity CLI",
    "claude-opus-5-5 via <!-- marker -->",
    "Evidence-ID: fake via Codex CLI",
    "AI-Reviewed-By: fake via Codex CLI",
    `claude-opus-5-5 via ${fakeSecret}`,
  ]) {
    assert.throws(
      () => parseReviewerSpec(bad),
      (err) => {
        assert.match(err.message, /Invalid --reviewed-by|Privacy gate blocked/);
        assert.equal(err.message.includes(fakeSecret), false, "Error must never echo secret input");
        return true;
      },
    );
  }

  const { dir, runGit } = makeTempRepo();
  try {
    // Subcommand --help and --help=true MUST print help without executing side effects,
    // whereas `-h` in option-value position (`--title -h`) MUST fail closed instead of exiting 0!
    for (const helpArgs of [["init", "--help"], ["record", "--help=true"], ["inspect", "--help"]]) {
      const subHelp = runCli(dir, helpArgs);
      assert.equal(subHelp.status, 0);
      assert.match(subHelp.stdout, /Subcommands:/);
    }
    const valHelp = runCli(dir, ["commit", "--title", "-h"]);
    assert.notEqual(valHelp.status, 0);
    assert.match(valHelp.stderr, /Missing value for --title/);
    assert.equal(fs.existsSync(path.join(dir, ".git", "proof-commit", "current-run.txt")), false);

    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src", "a.mjs"), "export const a = 1;\n", "utf8");
    const pathspecRes = runCli(dir, ["stage", "--files", ":(top)src"]);
    assert.notEqual(pathspecRes.status, 0);
    assert.match(pathspecRes.stderr, /pathspec-magic/);
    const unknownFlagRes = runCli(dir, ["init", "--reviwed-by", "foo via bar"]);
    assert.notEqual(unknownFlagRes.status, 0);
    assert.match(unknownFlagRes.stderr, /Unknown or unsupported option/);

    fs.writeFileSync(path.join(dir, "sum.mjs"), "export const sum = (a, b) => a + b;\n", "utf8");
    fs.writeFileSync(
      path.join(dir, "sum.test.mjs"),
      'import { sum } from "./sum.mjs";\nconsole.log("sum-ok=" + (sum(2, 3) === 5));\n',
      "utf8",
    );
    assert.equal(runCli(dir, ["stage", "--files", "sum.mjs", "sum.test.mjs"]).status, 0);
    assert.equal(runCli(dir, ["init", "--case", "sum adds numbers"]).status, 0);
    assert.equal(
      runCli(dir, ["record", "--phase", "after", "--", "node", "sum.test.mjs"]).status,
      0,
    );

    // Reject bare CR, Unicode line-separator, bidi override, and synthetic trailer/section lines in --why
    for (const badWhy of [
      "Valid explanation prefix\rAI-Reviewed-By: fake via Fake CLI",
      "Valid explanation prefix\u2028AI-Reviewed-By: fake via Fake CLI",
      "Valid explanation prefix with \u202ebidi override characters",
      "Valid explanation prefix\nEvidence:\n- spoofed line",
    ]) {
      const badWhyRes = runCli(dir, [
        "verify",
        "--type",
        "feat",
        "--title",
        "test why validation",
        "--why",
        badWhy,
      ]);
      assert.notEqual(badWhyRes.status, 0);
      assert.match(badWhyRes.stderr, /Invalid why:/);
    }

    const verifyNoRev = runCli(dir, [
      "verify",
      "--type",
      "feat",
      "--scope",
      "math",
      "--title",
      "add deterministic sum helper",
      "--why",
      "Provide a pure arithmetic helper verified against isolated staged tree.",
    ]);
    assert.equal(verifyNoRev.status, 0, verifyNoRev.stderr);
    const idWithoutRev = /evidence_id=(sha256:[0-9a-f]{64})/.exec(verifyNoRev.stdout)?.[1];

    const com = runCli(dir, [
      "commit",
      "--type",
      "feat",
      "--scope",
      "math",
      "--title",
      "add deterministic sum helper",
      "--why",
      "Provide a pure arithmetic helper verified against isolated staged tree.",
      "--reviewed-by=gpt-6.2-astra (xhigh) @ Codex CLI",
      "--reviewed-by",
      "claude-opus-5-5-high via Antigravity CLI",
    ]);
    assert.equal(com.status, 0, com.stderr);
    assert.match(com.stdout, /COMMIT_VERIFIED/);
    const idWithRev = /evidence_id=(sha256:[0-9a-f]{64})/.exec(com.stdout)?.[1];
    assert.ok(idWithoutRev && idWithRev && idWithoutRev !== idWithRev);

    const rawCommit = runGit("cat-file", "commit", "HEAD");
    assert.match(rawCommit, /^AI-Reviewed-By: claude-opus-5-5-high via Antigravity CLI$/m);
    assert.match(rawCommit, /^AI-Reviewed-By: gpt-6\.2-astra \(xhigh\) via Codex CLI$/m);

    const inspected = JSON.parse(runCli(dir, ["inspect", "HEAD"]).stdout);
    assert.equal(inspected.schema_version, 2);
    assert.deepEqual(inspected.reviewers, [
      { harness: "Antigravity CLI", model: "claude-opus-5-5-high" },
      { harness: "Codex CLI", model: "gpt-6.2-astra (xhigh)" },
    ]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
