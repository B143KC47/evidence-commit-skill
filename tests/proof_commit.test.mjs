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
  parseImageDimensions,
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
