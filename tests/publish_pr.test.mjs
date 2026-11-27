import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  computeEvidenceId,
  makeSolidPng,
  normalizeRepoSlugInput,
  parseOriginRepoSlugFromUrl,
  parseRepoTargetInput,
  safeFenceForText,
  sha256Hex,
  verifyHostedAssetBytes,
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

const PNG_BEFORE = makeSolidPng(4, 4, [248, 81, 73, 255]);
const PNG_AFTER = makeSolidPng(4, 4, [46, 160, 67, 255]);

function createRepoWithUiCommit() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "evcommit-pub-"));
  const runGit = (...args) => {
    const res = spawnSync("git", args, { cwd: dir, encoding: "utf8", windowsHide: true });
    assert.equal(res.status, 0, `git ${args.join(" ")} failed: ${res.stderr}`);
    return res.stdout.trim();
  };
  const runCli = (args, envExtra = {}) =>
    spawnSync(process.execPath, [SCRIPT_PATH, ...args], {
      cwd: dir,
      env: { ...process.env, ...envExtra },
      encoding: "utf8",
      windowsHide: true,
    });

  runGit("init", "-b", "main");
  runGit("config", "user.name", "Test Author");
  runGit("config", "user.email", "author@example.com");

  fs.writeFileSync(path.join(dir, "card.html"), "<div style='width:680px'>overflow</div>\n", "utf8");
  runGit("add", "card.html");
  runGit("commit", "-m", "seed main");

  runGit("checkout", "-b", "fix/mobile-card");
  fs.writeFileSync(
    path.join(dir, "card.html"),
    "<div style='max-width:100%'>responsive</div>\n",
    "utf8",
  );
  fs.mkdirSync(path.join(dir, "probes"), { recursive: true });
  fs.writeFileSync(
    path.join(dir, "probes", "card.probe.mjs"),
    [
      'import fs from "node:fs";',
      'const html = fs.readFileSync("card.html", "utf8");',
      "const ok = html.includes('max-width:100%');",
      'console.log("mobile-card-check | responsive=" + ok + " | sample=```tick```");',
      "process.exit(ok ? 0 : 1);",
    ].join("\n"),
    "utf8",
  );

  assert.equal(runCli(["stage", "--files", "card.html", "probes/card.probe.mjs"]).status, 0);
  assert.equal(runCli(["init", "--case", "Mobile card fits viewport"]).status, 0);
  const bRec = runCli([
    "record",
    "--phase",
    "before",
    "--overlay",
    "probes/card.probe.mjs",
    "--",
    "node",
    "probes/card.probe.mjs",
  ]);
  assert.equal(bRec.status, 0, bRec.stderr);
  const aRec = runCli(["record", "--phase", "after", "--", "node", "probes/card.probe.mjs"]);
  assert.equal(aRec.status, 0, aRec.stderr);

  const bFile = path.join(dir, "tmp-before.png");
  const aFile = path.join(dir, "tmp-after.png");
  fs.writeFileSync(bFile, PNG_BEFORE);
  fs.writeFileSync(aFile, PNG_AFTER);
  assert.equal(
    runCli([
      "attach-ui",
      "--before",
      bFile,
      "--after",
      aFile,
      "--route",
      "/card",
      "--viewport",
      "390x844",
      "--notes",
      "Card wraps cleanly inside 390px mobile width",
    ]).status,
    0,
  );
  fs.unlinkSync(bFile);
  fs.unlinkSync(aFile);

  const cRes = runCli([
    "commit",
    "--type",
    "fix",
    "--scope",
    "ui",
    "--title",
    "prevent card overflow on 390px viewport",
    "--why",
    "Hardcoded 680px width forced horizontal scrolling on 390px screens; replace with max-width:100%.",
    "--pick-before",
    "mobile-card-check",
    "--pick-after",
    "mobile-card-check",
    "--reviewed-by",
    "claude-opus-5-5-high via Antigravity CLI",
  ]);
  assert.equal(cRes.status, 0, cRes.stderr);
  const headOid = runGit("rev-parse", "HEAD");
  const baseOid = runGit("rev-parse", "main");
  return { baseOid, dir, headOid, runCli, runGit };
}

test("safeFenceForText, repo target host parsers, and verifyHostedAssetBytes validate strictly", async () => {
  assert.equal(safeFenceForText("plain log line"), "```");
  assert.equal(safeFenceForText("contains ``` triple ticks"), "````");
  assert.equal(normalizeRepoSlugInput("B143KC47/evidence-commit-skill"), "B143KC47/evidence-commit-skill");
  assert.deepEqual(
    parseRepoTargetInput("ghe.corp.example.com/org/proj", { allowCustomHost: true }),
    { host: "ghe.corp.example.com", slug: "org/proj" },
  );
  assert.throws(
    () => parseRepoTargetInput("ghe.corp.example.com/org/proj", { allowCustomHost: false }),
    /Invalid --repo slug/,
  );

  // verifyHostedAssetBytes checks exact SHA-256 bytes, blocks untrusted redirect hosts, and fails closed on 404
  const expectedSha = sha256Hex(PNG_BEFORE);
  const okFetch = async () => ({
    arrayBuffer: async () => PNG_BEFORE,
    headers: new Map(),
    status: 200,
  });
  const okRes = await verifyHostedAssetBytes(
    "https://github.com/user-attachments/assets/11111111-1111-1111-1111-111111111111",
    expectedSha,
    { fetchFn: okFetch },
  );
  assert.equal(okRes.verifiedBytes, true);

  const swappedFetch = async () => ({
    arrayBuffer: async () => PNG_AFTER,
    headers: new Map(),
    status: 200,
  });
  await assert.rejects(
    () =>
      verifyHostedAssetBytes(
        "https://github.com/user-attachments/assets/11111111-1111-1111-1111-111111111111",
        expectedSha,
        { fetchFn: swappedFetch },
      ),
    /Hosted screenshot SHA-256 mismatch/,
  );

  const evilRedirectFetch = async () => ({
    headers: new Map([["location", "https://evil.example.com/payload.png"]]),
    status: 302,
  });
  await assert.rejects(
    () =>
      verifyHostedAssetBytes(
        "https://github.com/user-attachments/assets/11111111-1111-1111-1111-111111111111",
        expectedSha,
        { fetchFn: evilRedirectFetch },
      ),
    /untrusted host/,
  );

  // Allowed 302 redirect to raw.githubusercontent.com, 404 fail-closed vs allowPrivateUnverifiedAssets, HTML login gate, redirect loop, and >64 MiB cap
  let hopCall = 0;
  const allowedRedirectFetch = async () => {
    hopCall += 1;
    if (hopCall === 1) {
      return {
        headers: new Map([["location", "https://private-user-images.githubusercontent.com/1/asset.png"]]),
        status: 302,
      };
    }
    return { arrayBuffer: async () => PNG_BEFORE, headers: new Map([["content-type", "image/png"]]), status: 200 };
  };
  const redirOk = await verifyHostedAssetBytes(
    "https://github.com/user-attachments/assets/11111111-1111-1111-1111-111111111111",
    expectedSha,
    { fetchFn: allowedRedirectFetch },
  );
  assert.equal(redirOk.verifiedBytes, true);

  const notFoundFetch = async () => ({ headers: new Map(), status: 404 });
  await assert.rejects(
    () =>
      verifyHostedAssetBytes(
        "https://github.com/user-attachments/assets/11111111-1111-1111-1111-111111111111",
        expectedSha,
        { fetchFn: notFoundFetch },
      ),
    /HTTP 404/,
  );
  const privSkip = await verifyHostedAssetBytes(
    "https://github.com/user-attachments/assets/11111111-1111-1111-1111-111111111111",
    expectedSha,
    { allowPrivateUnverifiedAssets: true, fetchFn: notFoundFetch },
  );
  assert.equal(privSkip.verifiedBytes, false);

  const htmlLoginFetch = async () => ({
    arrayBuffer: async () => Buffer.from("<html>login</html>"),
    headers: new Map([["content-type", "text/html; charset=utf-8"]]),
    status: 200,
  });
  await assert.rejects(
    () =>
      verifyHostedAssetBytes(
        "https://github.com/user-attachments/assets/11111111-1111-1111-1111-111111111111",
        expectedSha,
        { fetchFn: htmlLoginFetch },
      ),
    /received HTML login gate/,
  );

  const infiniteRedirFetch = async () => ({
    headers: new Map([["location", "https://github.com/user-attachments/assets/11111111-1111-1111-1111-111111111111"]]),
    status: 302,
  });
  await assert.rejects(
    () =>
      verifyHostedAssetBytes(
        "https://github.com/user-attachments/assets/11111111-1111-1111-1111-111111111111",
        expectedSha,
        { fetchFn: infiniteRedirFetch },
      ),
    /exceeded maximum redirect hops/,
  );

  const hugeFetch = async () => ({
    arrayBuffer: async () => Buffer.alloc(0),
    headers: new Map([["content-length", String(70 * 1024 * 1024)], ["content-type", "image/png"]]),
    status: 200,
  });
  await assert.rejects(
    () =>
      verifyHostedAssetBytes(
        "https://github.com/user-attachments/assets/11111111-1111-1111-1111-111111111111",
        expectedSha,
        { fetchFn: hugeFetch },
      ),
    /exceeds 64 MiB limit/,
  );

  assert.equal(
    normalizeRepoSlugInput("https://github.com/B143KC47/evidence-commit-skill.git/"),
    "B143KC47/evidence-commit-skill",
  );
  assert.equal(
    parseOriginRepoSlugFromUrl("git@github.com:B143KC47/evidence-commit-skill.git"),
    "B143KC47/evidence-commit-skill",
  );
  assert.equal(
    parseOriginRepoSlugFromUrl("https://octocat@github.com/B143KC47/evidence-commit-skill.git"),
    "B143KC47/evidence-commit-skill",
  );
  assert.equal(
    parseOriginRepoSlugFromUrl("ssh://git@github.com:22/B143KC47/evidence-commit-skill.git"),
    "B143KC47/evidence-commit-skill",
  );
  assert.equal(parseOriginRepoSlugFromUrl("https://fakegithub.com/evil/repo.git"), null);
  assert.equal(parseOriginRepoSlugFromUrl("https://gitlab.com/github.com/evil.git"), null);
  assert.equal(parseOriginRepoSlugFromUrl("https://github.com/../.."), null);
  const fakeCred = `ghp_${"S3cR3tT0k3nV4lU3X9y8Z7w6V5u4"}`;
  assert.throws(
    () => normalizeRepoSlugInput("../.."),
    /Invalid --repo slug/,
  );
  assert.throws(
    () => normalizeRepoSlugInput(`https://${fakeCred}@evil.example.com/a/b`),
    (err) => {
      assert.match(err.message, /Invalid --repo slug/);
      assert.equal(err.message.includes(fakeCred), false);
      return true;
    },
  );
});

test("counterexample 4: publish-pr resolves attachments from cwd, detects partial upload, preserves reviewer relative links, and recovers on retry", () => {
  const { baseOid, dir, headOid, runCli } = createRepoWithUiCommit();
  const mockDir = fs.mkdtempSync(path.join(os.tmpdir(), "evcommit-mockgh-"));
  const stateFile = path.join(mockDir, "gh_state.json");
  const assetMapFile = path.join(mockDir, "asset_map.json");
  const mockCdnDir = path.join(mockDir, "cdn");
  fs.mkdirSync(mockCdnDir, { recursive: true });
  const mockGhScript = path.join(mockDir, "mock_gh.mjs");
  const runPubCli = (args, extra = {}) =>
    runCli(args, { PROOF_COMMIT_MOCK_ASSET_MAP: assetMapFile, ...extra });

  // Realistic gh mock verifying cwd-relative file resolution + writing uploaded bytes to mockCdnDir for end-to-end SHA-256 verification!
  fs.writeFileSync(
    mockGhScript,
    `import fs from "node:fs";
import path from "node:path";
const stateFile = ${JSON.stringify(stateFile)};
const assetMapFile = ${JSON.stringify(assetMapFile)};
const mockCdnDir = ${JSON.stringify(mockCdnDir)};
const args = process.argv.slice(2);
const state = fs.existsSync(stateFile)
  ? JSON.parse(fs.readFileSync(stateFile, "utf8"))
  : { pr: null, createCalls: 0, editCalls: 0 };
const assetMap = fs.existsSync(assetMapFile)
  ? JSON.parse(fs.readFileSync(assetMapFile, "utf8"))
  : {};

if (args[0] === "pr" && args[1] === "list") {
  if (process.env.MOCK_GH_FAIL_LIST_ONCE === "1" && !state.failedListOnce) {
    state.failedListOnce = true;
    fs.writeFileSync(stateFile, JSON.stringify(state));
    process.stderr.write("simulated transient gh pr list network error\\n");
    process.exit(1);
  }
  process.stdout.write(JSON.stringify(state.pr ? [state.pr] : []));
  process.exit(0);
}
if (args[0] === "pr" && args[1] === "view") {
  if (!state.pr || String(state.pr.number) !== String(args[2])) process.exit(1);
  process.stdout.write(JSON.stringify(state.pr));
  process.exit(0);
}

const bodyIdx = args.indexOf("--body-file");
const bodyPath = path.resolve(process.cwd(), args[bodyIdx + 1]);
let body = fs.readFileSync(bodyPath, "utf8");
const attaches = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--attach") {
    const rel = args[++i];
    // Assert file actually exists relative to process.cwd() (gh 2.99 semantics)
    if (!fs.existsSync(path.resolve(process.cwd(), rel))) {
      process.stderr.write("attachment missing from cwd: " + rel + "\\n");
      process.exit(2);
    }
    attaches.push(rel);
  }
}

if (args[0] === "pr" && args[1] === "create") {
  state.createCalls += 1;
  if (attaches.length > 0) {
    const firstBase = path.basename(attaches[0]);
    const hostedBefore = "https://github.com/user-attachments/assets/uploaded-before-111";
    const cdnDest = path.join(mockCdnDir, "uploaded-before-111.png");
    fs.copyFileSync(path.resolve(process.cwd(), attaches[0]), cdnDest);
    assetMap[hostedBefore] = cdnDest;
    fs.writeFileSync(assetMapFile, JSON.stringify(assetMap));
    body = body.replaceAll("./" + firstBase, hostedBefore);
  }
  state.pr = {
    number: 1,
    url: "https://github.com/example/repo/pull/1",
    body: "Reviewer note with legitimate relative doc image ![diagram](./docs/arch.png)\\n\\n" + body,
    headRefOid: ${JSON.stringify(headOid)},
    baseRefName: "main",
    baseRefOid: ${JSON.stringify(baseOid)},
    headRefName: "fix/mobile-card",
    state: "OPEN",
    isCrossRepository: false,
    headRepositoryOwner: { login: "example" },
    headRepository: { name: "repo" },
  };
  fs.writeFileSync(stateFile, JSON.stringify(state));
  process.stdout.write(state.pr.url + "\\n");
  process.stderr.write("failed to upload second attachment\\n");
  process.exit(1);
}

    if (args[0] === "pr" && args[1] === "edit") {
      state.editCalls += 1;
      if (process.env.MOCK_GH_FAIL_EDIT === "1") {
        process.stderr.write("simulated gh pr edit failure\\n");
        process.exit(1);
      }
      for (const att of attaches) {
        const base = path.basename(att);
        const hostedUrl = "https://github.com/user-attachments/assets/uploaded-" + base;
        const cdnDest = path.join(mockCdnDir, "uploaded-" + base);
        fs.copyFileSync(path.resolve(process.cwd(), att), cdnDest);
        assetMap[hostedUrl] = cdnDest;
        body = body.replaceAll("./" + base, hostedUrl);
      }
      fs.writeFileSync(assetMapFile, JSON.stringify(assetMap));
      state.pr.body = body;
      fs.writeFileSync(stateFile, JSON.stringify(state));
      process.stdout.write(state.pr.url + "\\n");
      process.exit(0);
    }
process.exit(2);
`,
    "utf8",
  );

  try {
    // Missing origin without --skip-push-check MUST fail before calling gh
    const noOriginCheck = runCli([
      "publish-pr",
      "--repo",
      "example/repo",
      "--base",
      "main",
      "--gh-bin",
      mockGhScript,
    ]);
    assert.notEqual(noOriginCheck.status, 0);
    assert.match(noOriginCheck.stderr, /No git remote "origin"/);

    // Pass branch-level --reviewed-by on attempt 1 (which partially fails), then retry WITHOUT --reviewed-by!
    const attempt1 = runPubCli([
      "publish-pr",
      "--repo",
      "example/repo",
      "--base",
      "main",
      "--skip-push-check",
      "--reviewed-by",
      "gpt-6.2-astra (xhigh) via Codex CLI",
      "--gh-bin",
      mockGhScript,
    ]);
    assert.notEqual(attempt1.status, 0);
    assert.match(attempt1.stderr, /PARTIAL_PUBLISH_INCOMPLETE/);

    const attempt2 = runPubCli([
      "publish-pr",
      "--repo",
      "example/repo",
      "--base",
      "main",
      "--skip-push-check",
      "--gh-bin",
      mockGhScript,
    ]);
    assert.equal(attempt2.status, 0, attempt2.stderr);
    assert.match(attempt2.stdout, /PUBLISH_PR_VERIFIED number=1 .* ui_attachments=2/);

    const finalState = JSON.parse(fs.readFileSync(stateFile, "utf8"));
    assert.equal(finalState.createCalls, 1);
    assert.equal(finalState.editCalls, 1);
    assert.match(
      finalState.pr.body,
      /- \*\*Branch AI-Reviewed-By:\*\* `gpt-6\.2-astra \(xhigh\)` via `Codex CLI` _\(self-attested\)_/,
    );
    assert.match(
      finalState.pr.body,
      /- \*\*AI-Reviewed-By:\*\* `claude-opus-5-5-high` via `Antigravity CLI`\n\n\*\*Before\*\*/,
    );

    // --clear-reviewers on publish-pr removes stored local branch-level reviewers while preserving commit-level reviewers
    const attemptClear = runPubCli([
      "publish-pr",
      "--repo",
      "example/repo",
      "--base",
      "main",
      "--skip-push-check",
      "--clear-reviewers",
      "--gh-bin",
      mockGhScript,
    ]);
    assert.equal(attemptClear.status, 0, attemptClear.stderr);
    const clearedState = JSON.parse(fs.readFileSync(stateFile, "utf8"));
    assert.doesNotMatch(clearedState.pr.body, /Branch AI-Reviewed-By:/);
    assert.match(
      clearedState.pr.body,
      /- \*\*AI-Reviewed-By:\*\* `claude-opus-5-5-high` via `Antigravity CLI`/,
    );
    assert.match(
      clearedState.pr.body,
      /- \*\*Inspection notes:\*\* `Card wraps cleanly inside 390px mobile width`/,
    );

    // Swapping a hosted screenshot URL in the editable PR body:
    // 1) A transient gh pr list failure MUST fail closed immediately (no gh pr create fallback, no receipt poisoning)!
    // 2) A failed gh pr edit MUST NOT poison local upload-receipts.json with the swapped URL!
    // 3) End-to-end byte-check inside publish-pr MUST reject corrupted/swapped hosted image bytes even with --gh-bin!
    // 4) A subsequent successful gh pr edit MUST overwrite the swapped URL with a genuine fresh upload!
    const receiptsPath = path.join(dir, ".git", "proof-commit", "pr", "upload-receipts.json");
    const origReceiptsBytes = fs.readFileSync(receiptsPath, "utf8");
    clearedState.pr.body = clearedState.pr.body.replace(
      "https://github.com/user-attachments/assets/uploaded-before-111",
      "https://github.com/user-attachments/assets/99999999-9999-9999-9999-999999999999",
    );
    fs.writeFileSync(stateFile, JSON.stringify(clearedState));
    const failedListOnSwap = runPubCli(
      [
        "publish-pr",
        "--repo",
        "example/repo",
        "--base",
        "main",
        "--skip-push-check",
        "--gh-bin",
        mockGhScript,
      ],
      { MOCK_GH_FAIL_LIST_ONCE: "1" },
    );
    assert.notEqual(failedListOnSwap.status, 0);
    assert.match(failedListOnSwap.stderr, /gh pr list failed/);
    const afterListFailState = JSON.parse(fs.readFileSync(stateFile, "utf8"));
    assert.equal(afterListFailState.createCalls, 1, "Transient list failure must never fall through to gh pr create");
    assert.equal(fs.readFileSync(receiptsPath, "utf8"), origReceiptsBytes);

    const failedSwapEdit = runPubCli(
      [
        "publish-pr",
        "--repo",
        "example/repo",
        "--base",
        "main",
        "--skip-push-check",
        "--gh-bin",
        mockGhScript,
      ],
      { MOCK_GH_FAIL_EDIT: "1" },
    );
    assert.notEqual(failedSwapEdit.status, 0);
    assert.match(failedSwapEdit.stderr, /simulated gh pr edit failure/);
    assert.equal(fs.readFileSync(receiptsPath, "utf8"), origReceiptsBytes);

    const reuploadAfterSwap = runPubCli([
      "publish-pr",
      "--repo",
      "example/repo",
      "--base",
      "main",
      "--skip-push-check",
      "--gh-bin",
      mockGhScript,
    ]);
    assert.equal(reuploadAfterSwap.status, 0, reuploadAfterSwap.stderr);

    // Tamper the hosted CDN file bytes directly to prove publish-pr runs verifyHostedAssetBytes even when --gh-bin is set!
    const currentAssetMap = JSON.parse(fs.readFileSync(assetMapFile, "utf8"));
    const afterUrls = Object.keys(currentAssetMap).filter((u) => u.includes("-after-"));
    fs.writeFileSync(currentAssetMap[afterUrls[0]], PNG_BEFORE);
    const byteTamperRes = runPubCli([
      "publish-pr",
      "--repo",
      "example/repo",
      "--base",
      "main",
      "--skip-push-check",
      "--gh-bin",
      mockGhScript,
    ]);
    assert.notEqual(byteTamperRes.status, 0);
    assert.match(byteTamperRes.stderr, /Hosted screenshot SHA-256 mismatch/);
    fs.writeFileSync(currentAssetMap[afterUrls[0]], PNG_AFTER);
    const healedState = JSON.parse(fs.readFileSync(stateFile, "utf8"));
    assert.doesNotMatch(healedState.pr.body, /99999999-9999-9999-9999-999999999999/);
    assert.match(
      healedState.pr.body,
      /https:\/\/github\.com\/user-attachments\/assets\/uploaded-evc-[0-9a-f]{8}-before-[0-9a-f]{12}\.png/,
    );
    assert.match(finalState.pr.body, /!\[diagram\]\(\.\/docs\/arch\.png\)/);
    assert.match(
      finalState.pr.body,
      /https:\/\/github\.com\/user-attachments\/assets\/uploaded-before-111/,
    );
    assert.match(
      finalState.pr.body,
      /https:\/\/github\.com\/user-attachments\/assets\/uploaded-evc-[0-9a-f]{8}-after-[0-9a-f]{12}\.png/,
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(mockDir, { recursive: true, force: true });
  }
});

test("publish-pr rejects secret leaks in PR title, tampered stored bundles, and partial commit ranges", () => {
  const { dir, runCli, runGit } = createRepoWithUiCommit();
  const mockDir = fs.mkdtempSync(path.join(os.tmpdir(), "evcommit-unver-"));
  const mockGh = path.join(mockDir, "noop_gh.mjs");
  fs.writeFileSync(mockGh, 'console.log("[]");\n', "utf8");
  try {
    // Secret in PR title MUST be blocked before calling gh
    const fakeToken = `ghp_${"Z9y8X7w6V5u4T3s2R1q0P9o8N7m6"}`;
    const leakTitle = runCli([
      "publish-pr",
      "--repo",
      "example/repo",
      "--base",
      "main",
      "--skip-push-check",
      "--title",
      `fix: test with ${fakeToken}`,
      "--gh-bin",
      mockGh,
    ]);
    assert.notEqual(leakTitle.status, 0);
    assert.match(leakTitle.stderr, /Privacy gate blocked pr_title/);
    assert.equal(leakTitle.stderr.includes(fakeToken), false);

    // Tampering stored bundle (e.g. stripping ui_details or spoofing manifest reviewers/evidence_id) MUST fail reverifyStoredBundle
    const mapPath = path.join(dir, ".git", "proof-commit", "commits", `${runGit("rev-parse", "HEAD")}.json`);
    const mapping = JSON.parse(fs.readFileSync(mapPath, "utf8"));
    const bundleManifestPath = path.join(
      dir,
      ".git",
      "proof-commit",
      "bundles",
      mapping.evidence_id.replace(/^sha256:/, ""),
      "manifest.json",
    );
    const origManifest = fs.readFileSync(bundleManifestPath, "utf8");
    const tamperedUi = JSON.parse(origManifest);
    delete tamperedUi.ui_details;
    fs.writeFileSync(bundleManifestPath, JSON.stringify(tamperedUi, null, 2), "utf8");
    const uiTamperRes = runCli([
      "publish-pr",
      "--repo",
      "example/repo",
      "--base",
      "main",
      "--skip-push-check",
      "--gh-bin",
      mockGh,
    ]);
    assert.notEqual(uiTamperRes.status, 0);
    assert.match(uiTamperRes.stderr, /Stored UI metadata mismatch/);

    const origMapText = fs.readFileSync(mapPath, "utf8");
    const tamperedRev = JSON.parse(origManifest);
    tamperedRev.reviewers = [
      { harness: "Antigravity CLI", model: "claude-opus-5-5-high" },
      { harness: "Spoofed Harness", model: "spoofed-model" },
    ];
    tamperedRev.evidence_id = computeEvidenceId({
      after: tamperedRev.after,
      before: tamperedRev.before,
      case_name: tamperedRev.case_name,
      overlay: tamperedRev.overlay || [],
      parent_oid: tamperedRev.parent_oid,
      reviewers: tamperedRev.reviewers,
      schema_version: tamperedRev.schema_version,
      scope: tamperedRev.scope ?? null,
      tree_oid: tamperedRev.tree_oid,
      type: tamperedRev.type,
      ui: tamperedRev.ui ?? null,
      verification_mode: tamperedRev.verification_mode,
    });
    const tamperedMap = JSON.parse(origMapText);
    tamperedMap.evidence_id = tamperedRev.evidence_id;
    const spoofBundleDir = path.join(
      dir,
      ".git",
      "proof-commit",
      "bundles",
      tamperedRev.evidence_id.replace(/^sha256:/, ""),
    );
    fs.mkdirSync(spoofBundleDir, { recursive: true });
    fs.writeFileSync(
      path.join(spoofBundleDir, "manifest.json"),
      JSON.stringify(tamperedRev, null, 2),
      "utf8",
    );
    fs.writeFileSync(mapPath, JSON.stringify(tamperedMap, null, 2), "utf8");
    const revTamperRes = runCli([
      "publish-pr",
      "--repo",
      "example/repo",
      "--base",
      "main",
      "--skip-push-check",
      "--gh-bin",
      mockGh,
    ]);
    assert.notEqual(revTamperRes.status, 0);
    assert.match(revTamperRes.stderr, /Evidence-ID trailer|AI-Reviewed-By trailers disagree/i);
    fs.writeFileSync(mapPath, origMapText, "utf8");
    fs.rmSync(spoofBundleDir, { recursive: true, force: true });

    const tamperedMsg = JSON.parse(origManifest);
    delete tamperedMsg.commit_message;
    fs.writeFileSync(bundleManifestPath, JSON.stringify(tamperedMsg, null, 2), "utf8");
    const msgTamperRes = runCli([
      "publish-pr",
      "--repo",
      "example/repo",
      "--base",
      "main",
      "--skip-push-check",
      "--gh-bin",
      mockGh,
    ]);
    assert.notEqual(msgTamperRes.status, 0);
    assert.match(msgTamperRes.stderr, /message bytes missing or drifted/);
    fs.writeFileSync(bundleManifestPath, origManifest, "utf8");

    // --no-ui-impact combined with attach-ui MUST fail at commit/verify; standalone --no-ui-impact commit MUST certify cleanly in publish-pr!
    fs.writeFileSync(
      path.join(dir, "card.html"),
      "<div style='max-width:100%' data-id='1'>tweak</div>\n",
      "utf8",
    );
    assert.equal(runCli(["stage", "--files", "card.html"]).status, 0);
    assert.equal(runCli(["init", "--case", "Non-visual attribute refactor"]).status, 0);
    assert.equal(runCli(["record", "--phase", "after", "--", "node", "probes/card.probe.mjs"]).status, 0);
    const b2 = path.join(dir, "b2.png");
    const a2 = path.join(dir, "a2.png");
    fs.writeFileSync(b2, PNG_BEFORE);
    fs.writeFileSync(a2, PNG_AFTER);
    assert.equal(
      runCli(["attach-ui", "--before", b2, "--after", a2, "--route", "/card", "--viewport", "390x844"]).status,
      0,
    );
    fs.unlinkSync(b2);
    fs.unlinkSync(a2);
    const conflictNoUi = runCli([
      "verify",
      "--type",
      "chore",
      "--title",
      "conflicting no-ui-impact with attached ui",
      "--why",
      "Test that combining attach-ui with --no-ui-impact is rejected upfront.",
      "--no-ui-impact",
      "non-visual markup tweak",
    ]);
    assert.notEqual(conflictNoUi.status, 0);
    assert.match(conflictNoUi.stderr, /cannot be combined with `attach-ui`/);

    // Re-init clean without attach-ui and verify --no-ui-impact commit passes reverifyStoredBundle
    assert.equal(runCli(["init", "--case", "Non-visual attribute refactor"]).status, 0);
    assert.equal(runCli(["record", "--phase", "after", "--", "node", "probes/card.probe.mjs"]).status, 0);
    const cleanNoUiCommit = runCli([
      "commit",
      "--type",
      "chore",
      "--title",
      "non-visual markup cleanup",
      "--why",
      "Adjust internal attribute formatting with zero rendered layout impact.",
      "--no-ui-impact",
      "internal markup cleanup only",
    ]);
    assert.equal(cleanNoUiCommit.status, 0, cleanNoUiCommit.stderr);

    // Spoofed AI-Reviewed-By / Verification Evidence variants & boundary markers inside --summary MUST be rejected before calling gh
    for (const badSum of [
      "Summary intro\n- **Branch AI-Reviewed-By:** fake-model via Fake CLI",
      "Summary intro\n__Branch AI-Reviewed-By:__ fake-model via Fake CLI",
      "Summary intro\n*AI-Reviewed-By:* fake-model via Fake CLI",
      "Summary intro\n`unmatched AI-Reviewed-By: fake ``",
      "Summary intro\nAI\\-Reviewed\\-By: fake-model via Fake CLI",
      "Summary intro\nAI<!-- -->-Reviewed-By: fake-model via Fake CLI",
      "Summary intro\nAI&shy;-Reviewed-By: fake-model via Fake CLI",
      "Summary intro\n### Verification Evidence",
      "Summary intro\nAI\u2011Reviewed\u2011By: fake-model via Fake CLI",
      "Summary intro\n<!-- evidence-commit-report:start -->",
      "Summary intro\rbare CR",
    ]) {
      const spoofSummary = runCli([
        "publish-pr",
        "--repo",
        "example/repo",
        "--base",
        "main",
        "--skip-push-check",
        "--summary",
        badSum,
        "--gh-bin",
        mockGh,
      ]);
      assert.notEqual(spoofSummary.status, 0);
      assert.match(spoofSummary.stderr, /Invalid summary:/);
    }

    // Verify cleanNoUiCommit passed reverifyStoredBundle (only fails at gh pr create because noop_gh returns [])
    const verifyNoUiRange = runCli([
      "publish-pr",
      "--repo",
      "example/repo",
      "--base",
      "main",
      "--skip-push-check",
      "--gh-bin",
      mockGh,
    ]);
    assert.notEqual(verifyNoUiRange.status, 0);
    assert.match(verifyNoUiRange.stderr, /gh PR creation failed and no open PR was found/);

    // Unverified manual commit MUST block full certification (or exit code 4 under --allow-partial-commits)
    fs.writeFileSync(path.join(dir, "extra.txt"), "unverified\n", "utf8");
    runGit("add", "extra.txt");
    runGit("commit", "-m", "manual bypass commit without proof");

    const blocked = runCli([
      "publish-pr",
      "--repo",
      "example/repo",
      "--base",
      "main",
      "--skip-push-check",
      "--gh-bin",
      mockGh,
    ]);
    assert.notEqual(blocked.status, 0);
    assert.match(blocked.stderr, /unverified commits/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(mockDir, { recursive: true, force: true });
  }
});

test("publish-pr live ls-remote push check accepts orthogonal main advance on baseRefOid and rejects divergent base or fork PRs", () => {
  const { baseOid, dir, headOid, runCli, runGit } = createRepoWithUiCommit();
  const bareOrigin = fs.mkdtempSync(path.join(os.tmpdir(), "evcommit-bare-"));
  const mockDir = fs.mkdtempSync(path.join(os.tmpdir(), "evcommit-livegh-"));
  const stateFile = path.join(mockDir, "live_gh_state.json");
  const assetMapFile = path.join(mockDir, "live_asset_map.json");
  const mockCdnDir = path.join(mockDir, "cdn");
  fs.mkdirSync(mockCdnDir, { recursive: true });
  const mockGh = path.join(mockDir, "live_gh.mjs");
  const runLiveCli = (args) => runCli(args, { PROOF_COMMIT_MOCK_ASSET_MAP: assetMapFile });

  try {
    spawnSync("git", ["init", "--bare", bareOrigin], { encoding: "utf8", windowsHide: true });
    runGit("remote", "add", "origin", bareOrigin);
    runGit("push", "origin", "main");
    runGit("push", "origin", "fix/mobile-card");

    // Advance origin/main with an orthogonal commit AND create a nested refs/heads/aaa/main ref
    // that sorts before refs/heads/main so resolveExactRemoteBranchOid is proven not to match suffix refs!
    runGit("checkout", "main");
    fs.writeFileSync(path.join(dir, "orthogonal.txt"), "busy repo commit\n", "utf8");
    runGit("add", "orthogonal.txt");
    runGit("commit", "-m", "orthogonal main advance");
    runGit("push", "origin", "main");
    runGit("push", "origin", `${baseOid}:refs/heads/aaa/main`);
    runGit("push", "origin", `${baseOid}:refs/heads/aaa/fix/mobile-card`);
    // Also create a real local non-ancestor side commit to test isAncestor rejection directly!
    runGit("checkout", "-b", "unrelated-side", baseOid);
    fs.writeFileSync(path.join(dir, "side.txt"), "side\n", "utf8");
    runGit("add", "side.txt");
    runGit("commit", "-m", "unrelated side base");
    const sideCommitOid = runGit("rev-parse", "HEAD");
    runGit("checkout", "fix/mobile-card");

    fs.writeFileSync(
      mockGh,
      `import fs from "node:fs";
import path from "node:path";
const stateFile = ${JSON.stringify(stateFile)};
const assetMapFile = ${JSON.stringify(assetMapFile)};
const mockCdnDir = ${JSON.stringify(mockCdnDir)};
const args = process.argv.slice(2);
const s = JSON.parse(fs.readFileSync(stateFile, "utf8"));
const assetMap = fs.existsSync(assetMapFile) ? JSON.parse(fs.readFileSync(assetMapFile, "utf8")) : {};
if (args[0] === "pr" && args[1] === "list") {
  process.stdout.write(JSON.stringify(s.listPrs));
  process.exit(0);
}
if (args[0] === "pr" && args[1] === "view") {
  process.stdout.write(JSON.stringify(s.pr));
  process.exit(0);
}
const bodyIdx = args.indexOf("--body-file");
let body = fs.readFileSync(path.resolve(process.cwd(), args[bodyIdx + 1]), "utf8");
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--attach") {
    const rel = args[++i];
    const base = path.basename(rel);
    const hosted = "https://github.com/user-attachments/assets/live-" + base;
    const cdnDest = path.join(mockCdnDir, "live-" + base);
    fs.copyFileSync(path.resolve(process.cwd(), rel), cdnDest);
    assetMap[hosted] = cdnDest;
    body = body.replaceAll("./" + base, hosted);
  }
}
fs.writeFileSync(assetMapFile, JSON.stringify(assetMap));
s.pr.body = body;
s.listPrs = [s.pr];
fs.writeFileSync(stateFile, JSON.stringify(s));
process.stdout.write(s.pr.url + "\\n");
process.exit(0);
`,
      "utf8",
    );

    // 0) Local bare origin without host-qualified --repo MUST fail closed under --allow-custom-origin!
    const missingHostRes = runLiveCli([
      "publish-pr",
      "--allow-custom-origin",
      "--repo",
      "example/repo",
      "--base",
      "main",
      "--gh-bin",
      mockGh,
    ]);
    assert.notEqual(missingHostRes.status, 0);
    assert.match(missingHostRes.stderr, /host-qualified --repo/);

    // 1) Stale ancestor baseRefOid (baseOid = M1 while origin/main = M2) MUST succeed without --skip-push-check!
    const validPrObj = {
      number: 7,
      url: "https://github.com/example/repo/pull/7",
      body: "",
      headRefOid: headOid,
      baseRefName: "main",
      baseRefOid: baseOid,
      headRefName: "fix/mobile-card",
      state: "OPEN",
      isCrossRepository: false,
      headRepositoryOwner: { login: "example" },
      headRepository: { name: "repo" },
    };
    fs.writeFileSync(
      stateFile,
      JSON.stringify({
        // Include a cross-repository fork PR with identical branch names to prove findOpenPrByPair ignores forks!
        listPrs: [{ ...validPrObj, number: 6, isCrossRepository: true, headRepositoryOwner: { login: "forker" } }, validPrObj],
        pr: validPrObj,
      }),
    );

    const livePass = runLiveCli([
      "publish-pr",
      "--allow-custom-origin",
      "--repo",
      "github.com/example/repo",
      "--base",
      "main",
      "--gh-bin",
      mockGh,
    ]);
    assert.equal(livePass.status, 0, livePass.stderr);
    assert.match(livePass.stdout, /PUBLISH_PR_VERIFIED number=7/);

    // 2) Real local non-ancestor commit as baseRefOid MUST fail closed at merge-base --is-ancestor!
    const badBasePr = { ...validPrObj, baseRefOid: sideCommitOid };
    fs.writeFileSync(stateFile, JSON.stringify({ listPrs: [badBasePr], pr: badBasePr }));
    const liveBadBase = runLiveCli([
      "publish-pr",
      "--allow-custom-origin",
      "--repo",
      "github.com/example/repo",
      "--base",
      "main",
      "--gh-bin",
      mockGh,
    ]);
    assert.notEqual(liveBadBase.status, 0);
    assert.match(liveBadBase.stderr, /diverges from verified origin\/main/);

    // 3) Missing state or missing baseRefOid MUST fail closed!
    const missingStatePr = { ...validPrObj, state: "" };
    fs.writeFileSync(stateFile, JSON.stringify({ listPrs: [missingStatePr], pr: missingStatePr }));
    const missingStateRes = runLiveCli([
      "publish-pr",
      "--allow-custom-origin",
      "--repo",
      "github.com/example/repo",
      "--base",
      "main",
      "--gh-bin",
      mockGh,
    ]);
    assert.notEqual(missingStateRes.status, 0);
    assert.match(missingStateRes.stderr, /expected OPEN/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(bareOrigin, { recursive: true, force: true });
    fs.rmSync(mockDir, { recursive: true, force: true });
  }
});
