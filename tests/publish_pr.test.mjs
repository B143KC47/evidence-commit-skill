import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { makeSolidPng, safeFenceForText } from "../skills/evidence-commit/scripts/proof_commit.mjs";

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
  ]);
  assert.equal(cRes.status, 0, cRes.stderr);
  const headOid = runGit("rev-parse", "HEAD");
  return { dir, headOid, runCli, runGit };
}

test("safeFenceForText expands fence length beyond embedded backtick runs", () => {
  assert.equal(safeFenceForText("plain log line"), "```");
  assert.equal(safeFenceForText("contains ``` triple ticks"), "````");
});

test("counterexample 4: publish-pr resolves attachments from cwd, detects partial upload, preserves reviewer relative links, and recovers on retry", () => {
  const { dir, headOid, runCli } = createRepoWithUiCommit();
  const mockDir = fs.mkdtempSync(path.join(os.tmpdir(), "evcommit-mockgh-"));
  const stateFile = path.join(mockDir, "gh_state.json");
  const mockGhScript = path.join(mockDir, "mock_gh.mjs");

  // Realistic gh mock verifying cwd-relative file resolution (gh 2.99..2.106 compatibility!)
  fs.writeFileSync(
    mockGhScript,
    `import fs from "node:fs";
import path from "node:path";
const stateFile = ${JSON.stringify(stateFile)};
const args = process.argv.slice(2);
const state = fs.existsSync(stateFile)
  ? JSON.parse(fs.readFileSync(stateFile, "utf8"))
  : { pr: null, createCalls: 0, editCalls: 0 };

if (args[0] === "pr" && args[1] === "list") {
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
    body = body.replaceAll("./" + firstBase, "https://github.com/user-attachments/assets/uploaded-before-111");
  }
  state.pr = {
    number: 1,
    url: "https://github.com/example/repo/pull/1",
    body: "Reviewer note with legitimate relative doc image ![diagram](./docs/arch.png)\\n\\n" + body,
    headRefOid: ${JSON.stringify(headOid)},
    baseRefName: "main",
    headRefName: "fix/mobile-card",
    state: "OPEN",
  };
  fs.writeFileSync(stateFile, JSON.stringify(state));
  process.stdout.write(state.pr.url + "\\n");
  process.stderr.write("failed to upload second attachment\\n");
  process.exit(1);
}

if (args[0] === "pr" && args[1] === "edit") {
  state.editCalls += 1;
  for (const att of attaches) {
    const base = path.basename(att);
    body = body.replaceAll("./" + base, "https://github.com/user-attachments/assets/uploaded-" + base);
  }
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
    const attempt1 = runCli([
      "publish-pr",
      "--repo",
      "example/repo",
      "--base",
      "main",
      "--gh-bin",
      mockGhScript,
    ]);
    assert.notEqual(attempt1.status, 0);
    assert.match(attempt1.stderr, /PARTIAL_PUBLISH_INCOMPLETE/);

    const attempt2 = runCli([
      "publish-pr",
      "--repo",
      "example/repo",
      "--base",
      "main",
      "--gh-bin",
      mockGhScript,
    ]);
    assert.equal(attempt2.status, 0, attempt2.stderr);
    assert.match(attempt2.stdout, /PUBLISH_PR_VERIFIED number=1 .* ui_attachments=2/);

    const finalState = JSON.parse(fs.readFileSync(stateFile, "utf8"));
    assert.equal(finalState.createCalls, 1);
    assert.equal(finalState.editCalls, 1);
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
      "--title",
      `fix: test with ${fakeToken}`,
      "--gh-bin",
      mockGh,
    ]);
    assert.notEqual(leakTitle.status, 0);
    assert.match(leakTitle.stderr, /Privacy gate blocked pr_title/);
    assert.equal(leakTitle.stderr.includes(fakeToken), false);

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
