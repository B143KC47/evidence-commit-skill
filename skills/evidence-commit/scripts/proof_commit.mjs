#!/usr/bin/env node
/**
 * proof_commit.mjs — Deterministic, tree-bound evidence recorder & atomic commit tool.
 * Zero external dependencies (Node.js >= 20 built-ins + Git CLI).
 */

import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";

const ALLOWED_TYPES = new Set([
  "feat",
  "fix",
  "refactor",
  "perf",
  "ui",
  "docs",
  "test",
  "chore",
]);
const ALLOWED_MODES = new Set(["snapshot", "workspace"]);
const RUN_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const UI_EXT_RE = /\.(tsx|jsx|vue|svelte|css|scss|less|html)$/i;
const FORBIDDEN_STAGE_PATTERNS = [
  /(^|\/)\.env(\..+)?$/i,
  /\.(pem|key|p12|pfx)$/i,
  /(^|\/)id_(rsa|ed25519)$/i,
];
const SECRET_PATTERNS = [
  { category: "openai_or_api_secret", re: /\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b/ },
  { category: "github_token", re: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/ },
  { category: "github_fine_grained_pat", re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/ },
  { category: "aws_access_key", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { category: "private_key_block", re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/ },
  { category: "bearer_token", re: /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b/ },
];

export function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item ?? null)).join(",")}]`;
  }
  const keys = Object.keys(value)
    .filter((k) => value[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
}

export function sha256Hex(bufOrStr) {
  return crypto.createHash("sha256").update(bufOrStr).digest("hex");
}

export function computeEvidenceId(canonicalPayload) {
  return `sha256:${sha256Hex(Buffer.from(canonicalJson(canonicalPayload), "utf8"))}`;
}

export function validateRunId(runId) {
  if (!runId || !RUN_ID_RE.test(runId) || runId.includes("..")) {
    throw new Error(
      `Invalid run-id "${runId}": must be 1..80 safe characters ([A-Za-z0-9._-]) with no path separators.`,
    );
  }
  return runId;
}

function fail(msg, code = 1) {
  process.stderr.write(`ERROR: ${msg}\n`);
  process.exit(code);
}

function cleanGitEnv(extra = {}) {
  const env = { ...process.env };
  delete env.GIT_DIR;
  delete env.GIT_WORK_TREE;
  delete env.GIT_INDEX_FILE;
  delete env.NODE_TEST_CONTEXT;
  return { ...env, ...extra };
}

function git(cwd, args, { allowFail = false, envExtra = {}, encoding = "utf8" } = {}) {
  const res = spawnSync("git", args, {
    cwd,
    env: cleanGitEnv(envExtra),
    encoding,
    maxBuffer: 32 * 1024 * 1024,
    windowsHide: true,
  });
  if (res.error) throw res.error;
  if (res.status !== 0 && !allowFail) {
    const stderr = Buffer.isBuffer(res.stderr) ? res.stderr.toString("utf8") : res.stderr;
    throw new Error(`git ${args.join(" ")} failed (exit ${res.status}): ${(stderr || "").trim()}`);
  }
  return res;
}

function splitNul(str) {
  return str ? str.split("\0").filter(Boolean) : [];
}

function listStagedPaths(repoRoot, parentOid) {
  const out = parentOid
    ? git(repoRoot, ["diff", "--cached", "--name-only", "-z"]).stdout
    : git(repoRoot, ["ls-files", "--cached", "-z"]).stdout;
  return splitNul(out);
}

function listLsTreeEntries(repoRoot, treeish) {
  const out = git(repoRoot, ["ls-tree", "-r", "-z", treeish]).stdout;
  const entries = [];
  for (const rec of splitNul(out)) {
    const tabIdx = rec.indexOf("\t");
    if (tabIdx === -1) continue;
    const meta = rec.slice(0, tabIdx).trim().split(/\s+/);
    const filePath = rec.slice(tabIdx + 1);
    entries.push({ mode: meta[0], type: meta[1], oid: meta[2], path: filePath });
  }
  return entries;
}

function assertSnapshotSafeTree(repoRoot, treeish, label) {
  const entries = listLsTreeEntries(repoRoot, treeish);
  for (const e of entries) {
    if (e.mode === "120000") {
      throw new Error(
        `${label} contains symlink "${e.path}" (mode 120000), which is disallowed in snapshot verification because it can dereference external files.`,
      );
    }
    if (e.mode === "160000" || e.type === "commit") {
      throw new Error(
        `${label} contains submodule "${e.path}" (mode 160000), which is not materialized by tree snapshot checkout.`,
      );
    }
  }
  return entries;
}

function resolveRepoContext(startDir = process.cwd()) {
  const top = git(startDir, ["rev-parse", "--show-toplevel"]).stdout.trim();
  const gitDir = git(startDir, ["rev-parse", "--path-format=absolute", "--git-dir"]).stdout.trim();
  const commonDir = git(startDir, [
    "rev-parse",
    "--path-format=absolute",
    "--git-common-dir",
  ]).stdout.trim();
  const headRes = git(top, ["rev-parse", "--verify", "HEAD"], { allowFail: true });
  const parentOid = headRes.status === 0 ? headRes.stdout.trim() : null;
  return {
    repoRoot: path.resolve(top),
    gitDir: path.resolve(gitDir),
    commonDir: path.resolve(commonDir),
    parentOid,
  };
}

function normalizeRepoRelPath(rawPath) {
  if (
    !rawPath ||
    rawPath === "." ||
    rawPath === "-A" ||
    rawPath === "--all" ||
    rawPath.includes("*") ||
    rawPath.includes("?")
  ) {
    throw new Error(
      `Wildcard or whole-tree staging ("${rawPath}") is forbidden; list explicit file paths.`,
    );
  }
  if (path.isAbsolute(rawPath) || /^[A-Za-z]:/.test(rawPath)) {
    throw new Error("Path must be repository-relative, got absolute or drive-qualified path.");
  }
  const norm = rawPath.replace(/\\/g, "/").replace(/^\.\//, "");
  const parts = norm.split("/");
  if (parts.some((p) => !p || p === "." || p === "..")) {
    throw new Error(`Invalid relative path segment in "${rawPath}".`);
  }
  return norm;
}

function checkHiddenIndexFlags(repoRoot) {
  const out = git(repoRoot, ["ls-files", "-v", "-z"]).stdout;
  const flagged = [];
  for (const entry of splitNul(out)) {
    const tag = entry[0];
    if (tag === "h" || tag === "S" || tag === "s") {
      flagged.push(`${tag}:${entry.slice(2)}`);
    }
  }
  if (flagged.length > 0) {
    throw new Error(
      `Tracked files carry assume-unchanged/skip-worktree flags (${flagged.join(", ")}), which can hide working-tree divergence.`,
    );
  }
}

function checkUnmergedEntries(repoRoot) {
  const unmerged = git(repoRoot, ["ls-files", "-u"]).stdout.trim();
  if (unmerged) {
    throw new Error(
      "Index contains unresolved merge entries (`git ls-files -u`). Resolve conflicts first.",
    );
  }
}

export function splitExactLines(buffer) {
  const lines = [];
  let start = 0;
  let lineNo = 1;
  for (let i = 0; i < buffer.length; i++) {
    if (buffer[i] === 0x0a) {
      const end = i > start && buffer[i - 1] === 0x0d ? i - 1 : i;
      const slice = buffer.subarray(start, end);
      lines.push({ line: lineNo++, start_byte: start, end_byte: end, buf: slice });
      start = i + 1;
    }
  }
  if (start < buffer.length) {
    // Intentionally keep trailing bare \r if no \n followed so display validator rejects it
    const slice = buffer.subarray(start, buffer.length);
    lines.push({ line: lineNo++, start_byte: start, end_byte: buffer.length, buf: slice });
  }
  return lines;
}

export function decodeStrictUtf8AndValidateDisplay(buf, contextLabel) {
  const dec = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  let text;
  try {
    text = dec.decode(buf);
  } catch {
    throw new Error(`${contextLabel} contains invalid UTF-8 bytes and cannot be embedded verbatim.`);
  }
  if (text.includes("\uFEFF")) {
    throw new Error(`${contextLabel} contains a UTF-8 BOM (\\uFEFF); select clean lines without BOM.`);
  }
  if (text.includes("\r")) {
    throw new Error(`${contextLabel} contains bare CR (\\r) terminal overwrite characters.`);
  }
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/.test(text)) {
    throw new Error(
      `${contextLabel} contains ANSI escape, C0/C1 control, or Unicode bidi-override characters.`,
    );
  }
  if (Buffer.byteLength(text, "utf8") !== buf.length) {
    throw new Error(`${contextLabel} decoded UTF-8 length drifted from raw byte slice length.`);
  }
  return text;
}

export function scanPublicTextPrivacy(text, sectionLabel, homedir = os.homedir()) {
  const lines = text.split(/\r?\n/);
  const homeVariants = [];
  if (homedir && homedir.length >= 4) {
    const fwd = homedir.replace(/\\/g, "/").toLowerCase();
    const bwd = homedir.replace(/\//g, "\\").toLowerCase();
    const bwdEsc = bwd.replace(/\\/g, "\\\\");
    homeVariants.push(fwd, bwd, bwdEsc, `file:///${fwd.replace(/^\//, "")}`);
  }

  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx];
    const lower = line.toLowerCase();
    let decodedLower = lower;
    try {
      decodedLower = decodeURIComponent(lower);
    } catch {
      // ignore malformed percent sequences
    }

    for (const hv of homeVariants) {
      if (hv && (lower.includes(hv) || decodedLower.includes(hv))) {
        throw new Error(
          `Privacy gate blocked ${sectionLabel} at line ${idx + 1}: matched category [local_home_path]. Use repo-relative paths or select another verbatim line.`,
        );
      }
    }

    // Platform-specific user-home patterns (avoids false positives on REST routes like `GET /users/octocat`)
    if (
      /[A-Za-z]:(?:\\+|\/+)Users(?:\\+|\/+)[^\\/\s"']+/i.test(line) ||
      /(?:^|[\s"'=(])file:\/\/\/[A-Za-z]:\/users\/[^/\s"']+/i.test(line) ||
      /(?:^|[\s"'=(])\/Users\/[^/\s"']+\//.test(line) ||
      /(?:^|[\s"'=(])\/home\/[^/\s"']+\//.test(line)
    ) {
      throw new Error(
        `Privacy gate blocked ${sectionLabel} at line ${idx + 1}: matched category [user_directory_path].`,
      );
    }

    for (const pat of SECRET_PATTERNS) {
      if (pat.re.test(line)) {
        throw new Error(
          `Privacy gate blocked ${sectionLabel} at line ${idx + 1}: matched category [${pat.category}].`,
        );
      }
    }
  }
}

function validatePngStructure(buf) {
  if (buf.length < 33) throw new Error("Truncated PNG image.");
  let offset = 8;
  let width = 0;
  let height = 0;
  let bitDepth = 0;
  let colorType = 0;
  let sawIhdr = false;
  let sawIend = false;
  const idatParts = [];

  while (offset + 8 <= buf.length) {
    const length = buf.readUInt32BE(offset);
    const type = buf.toString("ascii", offset + 4, offset + 8);
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    const crcEnd = dataEnd + 4;
    if (crcEnd > buf.length) {
      throw new Error(`Truncated PNG chunk "${type}".`);
    }
    const expectedCrc = buf.readUInt32BE(dataEnd);
    const actualCrc = zlib.crc32(buf.subarray(offset + 4, dataEnd)) >>> 0;
    if (actualCrc !== expectedCrc) {
      throw new Error(`Corrupted PNG: CRC mismatch in chunk "${type}".`);
    }

    if (type === "IHDR") {
      if (length !== 13) throw new Error("Invalid PNG IHDR length.");
      width = buf.readUInt32BE(dataStart);
      height = buf.readUInt32BE(dataStart + 4);
      bitDepth = buf[dataStart + 8];
      colorType = buf[dataStart + 9];
      if (width <= 0 || height <= 0) throw new Error("Invalid PNG zero dimensions.");
      sawIhdr = true;
    } else if (type === "IDAT") {
      idatParts.push(buf.subarray(dataStart, dataEnd));
    } else if (type === "IEND") {
      sawIend = true;
      break;
    }
    offset = crcEnd;
  }

  if (!sawIhdr || !sawIend || idatParts.length === 0) {
    throw new Error("Incomplete PNG stream (missing IHDR, IDAT, or IEND).");
  }
  const inflated = zlib.inflateSync(Buffer.concat(idatParts));
  if (inflated.length < height) {
    throw new Error("Corrupted PNG: decompressed IDAT payload is smaller than image height.");
  }
  return { format: "png", width, height, bitDepth, colorType };
}

export function makeSolidPng(width, height, [r, g, b, a = 255] = [34, 139, 34, 255]) {
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const makeChunk = (typeStr, dataBuf) => {
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(dataBuf.length, 0);
    const typeBuf = Buffer.from(typeStr, "ascii");
    const crcVal = zlib.crc32(Buffer.concat([typeBuf, dataBuf])) >>> 0;
    const crcBuf = Buffer.alloc(4);
    crcBuf.writeUInt32BE(crcVal, 0);
    return Buffer.concat([lenBuf, typeBuf, dataBuf, crcBuf]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // 8-bit
  ihdr[9] = 6; // RGBA
  const rowLen = 1 + width * 4;
  const raw = Buffer.alloc(rowLen * height);
  for (let y = 0; y < height; y++) {
    const rowStart = y * rowLen;
    raw[rowStart] = 0; // filter None
    for (let x = 0; x < width; x++) {
      const p = rowStart + 1 + x * 4;
      raw[p] = r;
      raw[p + 1] = g;
      raw[p + 2] = b;
      raw[p + 3] = a;
    }
  }
  const idat = zlib.deflateSync(raw);
  return Buffer.concat([
    sig,
    makeChunk("IHDR", ihdr),
    makeChunk("IDAT", idat),
    makeChunk("IEND", Buffer.alloc(0)),
  ]);
}

export function parseImageDimensions(buf) {
  if (
    buf.length >= 33 &&
    buf[0] === 0x89 &&
    buf[1] === 0x50 &&
    buf[2] === 0x4e &&
    buf[3] === 0x47 &&
    buf[4] === 0x0d &&
    buf[5] === 0x0a &&
    buf[6] === 0x1a &&
    buf[7] === 0x0a
  ) {
    const { format, width, height } = validatePngStructure(buf);
    return { format, width, height };
  }
  if (buf.length >= 4 && buf[0] === 0xff && buf[1] === 0xd8 && buf[buf.length - 2] === 0xff && buf[buf.length - 1] === 0xd9) {
    let i = 2;
    while (i + 9 < buf.length) {
      if (buf[i] !== 0xff) {
        i++;
        continue;
      }
      const marker = buf[i + 1];
      if (marker === 0xff) {
        i++;
        continue;
      }
      if (marker === 0xd9 || marker === 0xda) break;
      const len = buf.readUInt16BE(i + 2);
      if (len < 2 || i + 2 + len > buf.length) break;
      if (
        (marker >= 0xc0 && marker <= 0xc3) ||
        (marker >= 0xc5 && marker <= 0xc7) ||
        (marker >= 0xc9 && marker <= 0xcb) ||
        (marker >= 0xcd && marker <= 0xcf)
      ) {
        const height = buf.readUInt16BE(i + 5);
        const width = buf.readUInt16BE(i + 7);
        if (width > 0 && height > 0) return { format: "jpeg", height, width };
      }
      i += 2 + len;
    }
  }
  if (
    buf.length >= 30 &&
    buf.toString("ascii", 0, 4) === "RIFF" &&
    buf.toString("ascii", 8, 12) === "WEBP"
  ) {
    const chunk = buf.toString("ascii", 12, 16);
    if (chunk === "VP8X") {
      return {
        format: "webp",
        width: 1 + buf.readUIntLE(24, 3),
        height: 1 + buf.readUIntLE(27, 3),
      };
    }
  }
  throw new Error("Unsupported or corrupted image file (expected valid, decodable PNG, JPEG, or WebP).");
}

function materializeTreeToDir(repoRoot, treeish, destDir, label) {
  assertSnapshotSafeTree(repoRoot, treeish, label);
  fs.mkdirSync(destDir, { recursive: true });
  const tmpIdxDir = fs.mkdtempSync(path.join(os.tmpdir(), "evcommit-idx-"));
  const tmpIndex = path.join(tmpIdxDir, "index");
  try {
    git(repoRoot, ["read-tree", treeish], { envExtra: { GIT_INDEX_FILE: tmpIndex } });
    const prefix = destDir.endsWith(path.sep) ? destDir : `${destDir}${path.sep}`;
    git(repoRoot, ["checkout-index", "--all", `--prefix=${prefix}`], {
      envExtra: { GIT_INDEX_FILE: tmpIndex },
    });
  } finally {
    fs.rmSync(tmpIdxDir, { recursive: true, force: true });
  }
}

function applyOverlayFromTree(repoRoot, parentOid, candidateTreeOid, overlayPaths, baselineDir) {
  const parentEntries = listLsTreeEntries(repoRoot, parentOid);
  const parentFiles = new Map(parentEntries.map((e) => [e.path, e]));
  const parentDirs = new Set();
  for (const e of parentEntries) {
    const parts = e.path.split("/");
    for (let i = 1; i < parts.length; i++) {
      parentDirs.add(parts.slice(0, i).join("/"));
    }
  }

  const candidateEntries = new Map(
    listLsTreeEntries(repoRoot, candidateTreeOid).map((e) => [e.path, e]),
  );
  const modifiedSet = new Set(
    splitNul(
      git(repoRoot, ["diff-tree", "--no-commit-id", "--name-only", "-r", "-z", parentOid, candidateTreeOid]).stdout,
    ),
  );

  const tmpIdxDir = fs.mkdtempSync(path.join(os.tmpdir(), "evcommit-ovl-"));
  const tmpIndex = path.join(tmpIdxDir, "index");
  const overlayRecords = [];

  try {
    for (const raw of overlayPaths) {
      const rel = normalizeRepoRelPath(raw);
      const isTestOrFixture =
        /(^|\/)(tests?|__tests__|spec|probes?|fixtures?)\//i.test(rel) ||
        /\.(test|spec|probe)\.[a-z0-9]+$/i.test(rel);
      if (!isTestOrFixture && (modifiedSet.has(rel) || parentFiles.has(rel))) {
        throw new Error(
          `Overlay path "${rel}" targets a non-test file; overlay may only introduce test, probe, or fixture files.`,
        );
      }

      // Prevent overlay from replacing an existing directory in P or traversing a file/symlink ancestor in P
      if (parentDirs.has(rel)) {
        throw new Error(
          `Overlay path "${rel}" collides with an existing directory in parent commit ${parentOid.slice(0, 12)}.`,
        );
      }
      const segments = rel.split("/");
      for (let i = 1; i < segments.length; i++) {
        const prefix = segments.slice(0, i).join("/");
        if (parentFiles.has(prefix)) {
          throw new Error(
            `Overlay path "${rel}" has ancestor "${prefix}" that is a file/symlink in parent commit ${parentOid.slice(0, 12)}.`,
          );
        }
      }

      const cand = candidateEntries.get(rel);
      if (!cand) {
        throw new Error(
          `Overlay path "${rel}" does not exist as a file in staged tree ${candidateTreeOid.slice(0, 12)}.`,
        );
      }
      if (cand.type !== "blob" || (cand.mode !== "100644" && cand.mode !== "100755")) {
        throw new Error(
          `Overlay path "${rel}" has unsupported Git mode ${cand.mode} (symlinks/submodules forbidden).`,
        );
      }

      git(repoRoot, ["update-index", "--add", "--cacheinfo", `${cand.mode},${cand.oid},${cand.path}`], {
        envExtra: { GIT_INDEX_FILE: tmpIndex },
      });
      const prefix = baselineDir.endsWith(path.sep) ? baselineDir : `${baselineDir}${path.sep}`;
      git(repoRoot, ["checkout-index", "--force", `--prefix=${prefix}`, "--", cand.path], {
        envExtra: { GIT_INDEX_FILE: tmpIndex },
      });

      const diskPath = path.join(baselineDir, cand.path);
      const diskBytes = fs.readFileSync(diskPath);
      overlayRecords.push({
        blob_oid: cand.oid,
        disk_sha256: sha256Hex(diskBytes),
        path: cand.path,
      });
    }
  } finally {
    fs.rmSync(tmpIdxDir, { recursive: true, force: true });
  }

  return overlayRecords.sort((a, b) => a.path.localeCompare(b.path));
}

function runCommandCapture(argv, cwd, timeoutMs = 300000) {
  return new Promise((resolve, reject) => {
    let exe = argv[0];
    const args = argv.slice(1);
    if (exe === "node" || exe === "node.exe") {
      exe = process.execPath;
    } else if (process.platform === "win32" && /\.(cmd|bat)$/i.test(exe)) {
      reject(
        new Error(
          `Direct .cmd/.bat execution ("${exe}") is blocked with shell=false; invoke the underlying interpreter (e.g., node <script>) explicitly.`,
        ),
      );
      return;
    }

    const isPosix = process.platform !== "win32";
    const startMs = Date.now();
    const child = spawn(exe, args, {
      cwd,
      detached: isPosix,
      env: cleanGitEnv({ NO_COLOR: "1", FORCE_COLOR: "0", CI: "true" }),
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });

    const outChunks = [];
    const errChunks = [];
    let timedOut = false;

    child.stdout.on("data", (c) => outChunks.push(c));
    child.stderr.on("data", (c) => errChunks.push(c));

    const timer = setTimeout(() => {
      timedOut = true;
      if (process.platform === "win32" && child.pid) {
        spawnSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], {
          stdio: "ignore",
          windowsHide: true,
        });
      } else if (child.pid) {
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch {
          child.kill("SIGKILL");
        }
      }
      child.stdout.destroy();
      child.stderr.destroy();
    }, timeoutMs);
    timer.unref();

    let stdoutDone = false;
    let stderrDone = false;
    let exitInfo = null;

    const maybeFinish = () => {
      if (!stdoutDone || !stderrDone || !exitInfo) return;
      clearTimeout(timer);
      resolve({
        stdout: Buffer.concat(outChunks),
        stderr: Buffer.concat(errChunks),
        exitCode: exitInfo.code,
        signal: exitInfo.signal,
        timedOut,
        durationMs: Date.now() - startMs,
      });
    };

    child.stdout.on("close", () => {
      stdoutDone = true;
      maybeFinish();
    });
    child.stderr.on("close", () => {
      stderrDone = true;
      maybeFinish();
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on("close", (code, signal) => {
      exitInfo = { code: code ?? 1, signal: signal ?? null };
      maybeFinish();
    });
  });
}

function getRunPaths(gitDir, rawRunId) {
  const base = path.resolve(gitDir, "proof-commit");
  const currentPtr = path.join(base, "current-run.txt");
  const candidateId =
    rawRunId || (fs.existsSync(currentPtr) ? fs.readFileSync(currentPtr, "utf8").trim() : null);
  if (!candidateId) {
    throw new Error("No active run found. Run `proof_commit.mjs init` first or pass `--run-id`.");
  }
  const resolvedId = validateRunId(candidateId);
  const runsRoot = path.join(base, "runs");
  const runDir = path.resolve(runsRoot, resolvedId);
  if (path.dirname(runDir) !== runsRoot) {
    throw new Error("Run directory containment check failed.");
  }
  return { base, currentPtr, runId: resolvedId, runDir, statePath: path.join(runDir, "state.json") };
}

function loadRunState(gitDir, runId) {
  const paths = getRunPaths(gitDir, runId);
  if (!fs.existsSync(paths.statePath)) {
    throw new Error(`Run state not found at ${paths.statePath}.`);
  }
  return { ...paths, state: JSON.parse(fs.readFileSync(paths.statePath, "utf8")) };
}

function writeFileAtomic(targetPath, data) {
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  const tmp = `${targetPath}.tmp-${process.pid}-${crypto.randomBytes(4).toString("hex")}`;
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, targetPath);
}

function saveRunState(statePath, state) {
  writeFileAtomic(statePath, Buffer.from(`${JSON.stringify(state, null, 2)}\n`, "utf8"));
}

function selectQuotesFromPhase(runDir, phaseName, phaseMeta, selector, maxLines = 3) {
  const streams = ["stdout", "stderr"];
  const decodedByStream = {};
  for (const s of streams) {
    const p = path.join(runDir, `${phaseName}.${s}.log`);
    const buf = fs.existsSync(p) ? fs.readFileSync(p) : Buffer.alloc(0);
    const actualSha = sha256Hex(buf);
    const expectedSha = phaseMeta[`${s}_sha256`];
    if (actualSha !== expectedSha) {
      throw new Error(
        `Integrity mismatch on ${phaseName}.${s}.log (expected ${expectedSha?.slice(0, 12)}, got ${actualSha.slice(0, 12)}). Re-run record.`,
      );
    }
    decodedByStream[s] = splitExactLines(buf).map((entry) => ({
      ...entry,
      stream: s,
      text: decodeStrictUtf8AndValidateDisplay(entry.buf, `${phaseName}.${s}:${entry.line}`),
    }));
  }

  const allNonEmpty = [...decodedByStream.stdout, ...decodedByStream.stderr].filter(
    (l) => l.text.trim().length > 0,
  );
  if (allNonEmpty.length === 0) {
    throw new Error(`Phase "${phaseName}" produced zero non-empty output lines; cannot extract verbatim proof.`);
  }

  let picked = [];
  if (selector) {
    const rangeMatch = /^(stdout|stderr):(\d+)(?:-(\d+))?$/.exec(selector);
    if (rangeMatch) {
      const [, st, aStr, bStr] = rangeMatch;
      const a = Number(aStr);
      const b = bStr ? Number(bStr) : a;
      picked = decodedByStream[st].filter((l) => l.line >= a && l.line <= b);
    } else {
      const re = new RegExp(selector);
      picked = allNonEmpty.filter((l) => re.test(l.text)).slice(0, maxLines);
    }
    if (picked.length === 0) {
      throw new Error(`Selector "${selector}" matched zero lines in ${phaseName} output.`);
    }
  } else {
    const informative = allNonEmpty.filter(
      (l) =>
        !/^TAP version \d+/i.test(l.text) &&
        !/^1\.\.\d+$/.test(l.text) &&
        !/^# Subtest:/i.test(l.text),
    );
    picked = (informative.length > 0 ? informative : allNonEmpty).slice(-maxLines);
  }

  return {
    allLines: allNonEmpty,
    quotes: picked.map((l) => ({
      end_byte: l.end_byte,
      line: l.line,
      start_byte: l.start_byte,
      stream: l.stream,
      text: l.text,
    })),
  };
}

function isNonAssertionLine(lineText) {
  return (
    /#\s*(SKIP|TODO)\b/i.test(lineText) ||
    /^[ー﹣-]\s+.*\((?:skipped|todo)\)/i.test(lineText) ||
    /^#\s*Subtest:/i.test(lineText) ||
    /^TAP version \d+/i.test(lineText) ||
    /^1\.\.\d+$/.test(lineText)
  );
}

function assertNotSkippedOrZeroTests(allLines, quotes, phaseLabel) {
  const fullText = allLines.map((l) => l.text).join("\n");
  if (
    /^(?:#|ℹ|i)\s*pass\s+0$/im.test(fullText) ||
    /\b0\s+passed\b/i.test(fullText) ||
    /\bran\s+0\s+tests\b/i.test(fullText) ||
    /\bno\s+tests\s+found\b/i.test(fullText)
  ) {
    throw new Error(
      `${phaseLabel} output indicates zero passing tests executed; skipped or empty test runs cannot certify a commit.`,
    );
  }
  const hasConcreteLine = quotes.some((q) => !isNonAssertionLine(q.text));
  if (!hasConcreteLine) {
    throw new Error(
      `${phaseLabel} selected quote lines contain only SKIP/TODO/heading directives rather than an executed assertion.`,
    );
  }
}

function formatDisplayCmd(argv) {
  return argv
    .map((a, idx) => {
      let tok = a;
      if (idx === 0 && (path.basename(a).toLowerCase() === "node.exe" || path.basename(a) === "node")) {
        tok = "node";
      }
      return /\s/.test(tok) ? JSON.stringify(tok) : tok;
    })
    .join(" ");
}

function parseFlags(argv) {
  const flags = {};
  const multi = { files: [], overlay: [] };
  let cmdAfterDashDash = null;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--") {
      cmdAfterDashDash = argv.slice(i + 1);
      break;
    }
    if (arg === "--files" || arg === "--overlay") {
      const key = arg.slice(2);
      while (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        multi[key].push(argv[++i]);
      }
    } else if (
      arg === "--reset-index" ||
      arg === "--help" ||
      arg === "-h" ||
      arg === "--draft" ||
      arg === "--allow-partial-commits" ||
      arg === "--skip-push-check"
    ) {
      flags[arg.replace(/^-+/, "")] = true;
    } else if (arg.startsWith("--")) {
      const key = arg.slice(2);
      if (i + 1 >= argv.length) throw new Error(`Missing value for ${arg}`);
      flags[key] = argv[++i];
    } else {
      throw new Error(`Unexpected positional argument "${arg}".`);
    }
  }
  return { flags, multi, cmdAfterDashDash };
}

function printHelp() {
  process.stdout.write(`Usage: node proof_commit.mjs <subcommand> [options]

Subcommands:
  stage       --files <relpath...> [--reset-index]
  init        [--case "<acceptance condition>"] [--mode snapshot|workspace] [--run-id <id>]
  record      --phase before|after [--overlay <test-relpath...>] [--mode snapshot|workspace] -- <exe> [args...]
  attach-ui   [--before <imgPath>] --after <imgPath> --route <route> --viewport <WxH> [--notes "<text>"]
  verify      --type <feat|fix|refactor|perf|ui|docs|test|chore> [--scope <s>] --title <t> --why <w> [...]
  commit      --type <feat|fix|refactor|perf|ui|docs|test|chore> [--scope <s>] --title <t> --why <w> [...]
  publish-pr  [--base <branch>] [--title "<title>"] [--summary "<text>"] [--closes <n>] [--draft]
  inspect     [<commit-oid>]
`);
}

export function safeFenceForText(text) {
  let maxTicks = 2;
  for (const m of String(text || "").matchAll(/`+/g)) {
    if (m[0].length > maxTicks) maxTicks = m[0].length;
  }
  return "`".repeat(maxTicks + 1);
}

const REPORT_START_MARKER = "<!-- evidence-commit-report:start -->";
const REPORT_END_MARKER = "<!-- evidence-commit-report:end -->";
const MAX_ATTACH_PER_CALL = 40;

function countOccurrences(haystack, needle) {
  let count = 0;
  let idx = 0;
  while ((idx = haystack.indexOf(needle, idx)) !== -1) {
    count += 1;
    idx += needle.length;
  }
  return count;
}

function extractSingleReportBlock(bodyText) {
  if (!bodyText) return null;
  const sc = countOccurrences(bodyText, REPORT_START_MARKER);
  const ec = countOccurrences(bodyText, REPORT_END_MARKER);
  if (sc === 0 && ec === 0) return null;
  if (sc !== 1 || ec !== 1) {
    throw new Error(
      `Ambiguous or corrupted report markers in PR body (start=${sc}, end=${ec}); inspect PR description manually.`,
    );
  }
  const s = bodyText.indexOf(REPORT_START_MARKER);
  const e = bodyText.indexOf(REPORT_END_MARKER);
  if (e <= s) {
    throw new Error("Corrupted report markers in PR body (end marker precedes start marker).");
  }
  return {
    endIdx: e + REPORT_END_MARKER.length,
    inner: bodyText.slice(s + REPORT_START_MARKER.length, e).trim(),
    startIdx: s,
  };
}

function parseExistingHostedUiUrls(existingBody) {
  const map = new Map();
  const parsed = extractSingleReportBlock(existingBody);
  if (!parsed) return map;
  const re = /!\[(evc-[0-9a-f]{8}-(?:before|after)-[0-9a-f]{12})\]\((https:\/\/[^)\s]+)\)/g;
  for (const m of parsed.inner.matchAll(re)) {
    map.set(m[1], m[2]);
  }
  return map;
}

function mergeReportBlockIntoBody(existingBody, summaryText, closesIssue, reportInner) {
  if (
    reportInner.includes(REPORT_START_MARKER) ||
    reportInner.includes(REPORT_END_MARKER)
  ) {
    throw new Error("Evidence report inner content must not contain report boundary markers.");
  }
  const wrapped = `${REPORT_START_MARKER}\n${reportInner.trim()}\n${REPORT_END_MARKER}`;
  const parsed = extractSingleReportBlock(existingBody);
  if (parsed) {
    return `${existingBody.slice(0, parsed.startIdx)}${wrapped}${existingBody.slice(parsed.endIdx)}`.replace(
      /\s*$/,
      "\n",
    );
  }
  const parts = [];
  if (existingBody && existingBody.trim()) {
    parts.push(existingBody.trim());
  } else {
    parts.push("## Summary", "", (summaryText || "Evidence-backed pull request.").trim());
    if (closesIssue) {
      parts.push("", `Closes #${String(closesIssue).replace(/^#/, "")}`);
    }
  }
  parts.push("", wrapped, "");
  return parts.join("\n");
}

function parseOriginRepoSlug(repoRoot) {
  const r = git(repoRoot, ["remote", "get-url", "origin"], { allowFail: true });
  if (r.status !== 0) return null;
  const url = r.stdout.trim();
  const httpsMatch = /github\.com[/:]([^/\s]+\/[^/\s]+?)(?:\.git)?$/i.exec(url);
  return httpsMatch ? httpsMatch[1] : null;
}

function invokeGhCli(cwd, ghArgs, ghOverride) {
  const bin = ghOverride || process.env.PROOF_COMMIT_GH_BIN || "gh";
  let exe = bin;
  let fullArgs = ghArgs;
  if (bin.endsWith(".mjs") || bin.endsWith(".js") || bin.endsWith(".cjs")) {
    exe = process.execPath;
    fullArgs = [bin, ...ghArgs];
  }
  const res = spawnSync(exe, fullArgs, {
    cwd,
    env: cleanGitEnv(),
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    windowsHide: true,
  });
  if (res.error) throw res.error;
  return res;
}

function reverifyStoredBundle(repoRoot, oid, bundleDir, manifest) {
  if (manifest.commit_oid !== oid) {
    throw new Error(`Bundle commit_oid (${manifest.commit_oid}) != ${oid}`);
  }
  const rawCommit = git(repoRoot, ["cat-file", "commit", oid]).stdout;
  const { actualTree, actualParent, bodyBlock, parentCount } =
    parseCommitObjectHeaderAndBody(rawCommit);
  if (parentCount > 1) {
    throw new Error(`Merge commit ${oid.slice(0, 12)} cannot be certified as atomic.`);
  }
  if (actualTree !== manifest.tree_oid || actualParent !== manifest.parent_oid) {
    throw new Error(`Commit ${oid.slice(0, 12)} tree/parent drifted from stored manifest.`);
  }
  if (manifest.commit_message && bodyBlock !== manifest.commit_message) {
    throw new Error(`Commit ${oid.slice(0, 12)} message bytes drifted from stored manifest.`);
  }

  const canonicalPayload = {
    after: manifest.after,
    before: manifest.before,
    case_name: manifest.case_name,
    overlay: manifest.overlay || [],
    parent_oid: manifest.parent_oid,
    schema_version: manifest.schema_version,
    scope: manifest.scope ?? null,
    tree_oid: manifest.tree_oid,
    type: manifest.type,
    ui: manifest.ui ?? null,
    verification_mode: manifest.verification_mode,
  };
  const recomputedId = computeEvidenceId(canonicalPayload);
  if (recomputedId !== manifest.evidence_id) {
    throw new Error(
      `Bundle Evidence-ID mismatch on ${oid.slice(0, 12)}: expected ${manifest.evidence_id}, recomputed ${recomputedId}.`,
    );
  }

  for (const phaseName of ["before", "after"]) {
    const pm = manifest[phaseName];
    if (!pm) continue;
    for (const stream of ["stdout", "stderr"]) {
      const logFile = path.join(bundleDir, `${phaseName}.${stream}.log`);
      const buf = fs.existsSync(logFile) ? fs.readFileSync(logFile) : Buffer.alloc(0);
      if (sha256Hex(buf) !== pm[`${stream}_sha256`]) {
        throw new Error(`Raw log digest mismatch on ${oid.slice(0, 12)} ${phaseName}.${stream}.log.`);
      }
    }
    for (const q of pm.quotes || []) {
      const logFile = path.join(bundleDir, `${phaseName}.${q.stream}.log`);
      const buf = fs.readFileSync(logFile);
      const slice = buf.subarray(q.start_byte, q.end_byte);
      const decoded = decodeStrictUtf8AndValidateDisplay(slice, `${oid.slice(0, 8)}:${phaseName}`);
      if (decoded !== q.text) {
        throw new Error(`Stored quote slice mismatch on ${oid.slice(0, 12)} ${phaseName}.`);
      }
    }
  }

  if (manifest.ui_details) {
    for (const kind of ["before", "after"]) {
      const meta = manifest.ui_details[kind];
      if (!meta) continue;
      const imgPath = path.join(bundleDir, "ui", `${kind}.${meta.ext}`);
      if (!fs.existsSync(imgPath)) {
        throw new Error(`Missing stored UI screenshot ${imgPath}.`);
      }
      const bytes = fs.readFileSync(imgPath);
      parseImageDimensions(bytes);
      if (sha256Hex(bytes) !== meta.sha256) {
        throw new Error(`Stored UI ${kind} screenshot digest mismatch on ${oid.slice(0, 12)}.`);
      }
    }
  }
}

function normalizeHostedUrlsForComparison(reportInner) {
  return reportInner
    .replace(
      /!\[(evc-[0-9a-f]{8}-(?:before|after)-[0-9a-f]{12})\]\((?:https:\/\/[^)\s]+|\.\/[^)\s]+)\)/g,
      "![$1](<HOSTED_ASSET>)",
    )
    .replace(/\r\n/g, "\n")
    .trim();
}

async function cmdPublishPr(argv) {
  const { flags } = parseFlags(argv);
  const { repoRoot, commonDir } = resolveRepoContext();
  const ghOverride = flags["gh-bin"] || null;

  const headOid = git(repoRoot, ["rev-parse", "HEAD"]).stdout.trim();
  const headBranch = git(repoRoot, ["rev-parse", "--abbrev-ref", "HEAD"]).stdout.trim();
  if (!headBranch || headBranch === "HEAD") {
    throw new Error("`publish-pr` must be run from a named feature/fix branch, not detached HEAD.");
  }

  const baseBranch = (flags.base || "main").replace(/^origin\//, "");
  if (headBranch === baseBranch) {
    throw new Error(`Refusing to run \`publish-pr\` directly on base branch "${baseBranch}".`);
  }

  const repoSlug = flags.repo || parseOriginRepoSlug(repoRoot);
  if (!repoSlug) {
    throw new Error("Could not determine GitHub repository slug (`owner/repo`). Pass `--repo owner/repo` or configure `origin`.");
  }

  const hasOrigin = git(repoRoot, ["remote", "get-url", "origin"], { allowFail: true }).status === 0;
  let baseRangeRef = baseBranch;
  if (hasOrigin && !flags["skip-push-check"] && !ghOverride) {
    const lsHead = git(repoRoot, ["ls-remote", "--heads", "origin", headBranch]).stdout.trim();
    const remoteHeadOid = lsHead ? lsHead.split(/\s+/)[0] : null;
    if (remoteHeadOid !== headOid) {
      throw new Error(
        `Local HEAD (${headOid.slice(0, 12)}) does not match remote origin/${headBranch} (${remoteHeadOid ? remoteHeadOid.slice(0, 12) : "unpushed"}). Push your branch before running \`publish-pr\`.`,
      );
    }
    const lsBase = git(repoRoot, ["ls-remote", "--heads", "origin", baseBranch]).stdout.trim();
    const remoteBaseOid = lsBase ? lsBase.split(/\s+/)[0] : null;
    if (!remoteBaseOid) {
      throw new Error(`Base branch "${baseBranch}" was not found on remote origin.`);
    }
    baseRangeRef = remoteBaseOid;
  } else {
    const originBase = git(repoRoot, ["rev-parse", "--verify", `origin/${baseBranch}`], {
      allowFail: true,
    });
    if (originBase.status === 0) baseRangeRef = `origin/${baseBranch}`;
  }

  const commitsOut = git(repoRoot, ["rev-list", "--reverse", `${baseRangeRef}..HEAD`]).stdout.trim();
  const commitOids = commitsOut ? commitsOut.split(/\r?\n/).filter(Boolean) : [];
  if (commitOids.length === 0) {
    throw new Error(`No commits found in range ${baseRangeRef.slice(0, 12)}..HEAD.`);
  }

  const verifiedBundles = [];
  const missingCommits = [];

  for (const oid of commitOids) {
    const mapFile = path.join(commonDir, "proof-commit", "commits", `${oid}.json`);
    if (!fs.existsSync(mapFile)) {
      missingCommits.push(`${oid.slice(0, 12)} (no local proof-commit bundle)`);
      continue;
    }
    const mapping = JSON.parse(fs.readFileSync(mapFile, "utf8"));
    const digestHex = mapping.evidence_id.replace(/^sha256:/, "");
    const bundleDir = path.join(commonDir, "proof-commit", "bundles", digestHex);
    const manifestPath = path.join(bundleDir, "manifest.json");
    if (!fs.existsSync(manifestPath)) {
      missingCommits.push(`${oid.slice(0, 12)} (bundle manifest missing for ${mapping.evidence_id})`);
      continue;
    }
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    try {
      reverifyStoredBundle(repoRoot, oid, bundleDir, manifest);
    } catch (err) {
      missingCommits.push(`${oid.slice(0, 12)} (${err.message})`);
      continue;
    }
    const subject = git(repoRoot, ["log", "-1", "--format=%s", oid]).stdout.trim();
    verifiedBundles.push({ bundleDir, manifest, oid, subject });
  }

  if (missingCommits.length > 0 && !flags["allow-partial-commits"]) {
    throw new Error(
      `Cannot certify PR: unverified commits in range: ${missingCommits.join("; ")}`,
    );
  }

  const repoArgs = ["--repo", repoSlug];
  const findOpenPrByPair = () => {
    const r = invokeGhCli(
      repoRoot,
      [
        "pr",
        "list",
        ...repoArgs,
        "--state",
        "open",
        "--base",
        baseBranch,
        "--head",
        headBranch,
        "--json",
        "number,url,body,headRefOid,baseRefName,headRefName,state",
      ],
      ghOverride,
    );
    if (r.status !== 0) return null;
    try {
      const arr = JSON.parse(r.stdout);
      if (!Array.isArray(arr) || arr.length === 0) return null;
      return (
        arr.find((p) => p.baseRefName === baseBranch && p.headRefName === headBranch) || null
      );
    } catch {
      return null;
    }
  };

  const viewPrByNumber = (num) => {
    const r = invokeGhCli(
      repoRoot,
      [
        "pr",
        "view",
        String(num),
        ...repoArgs,
        "--json",
        "number,url,body,headRefOid,baseRefName,headRefName,state",
      ],
      ghOverride,
    );
    if (r.status !== 0) return null;
    try {
      return JSON.parse(r.stdout);
    } catch {
      return null;
    }
  };

  let existingPr = findOpenPrByPair();
  if (existingPr && existingPr.headRefOid && existingPr.headRefOid !== headOid) {
    throw new Error(
      `Open PR #${existingPr.number} remote headRefOid (${existingPr.headRefOid.slice(0, 12)}) != local HEAD (${headOid.slice(0, 12)}). Push branch before updating PR evidence.`,
    );
  }

  const existingHosted = parseExistingHostedUiUrls(existingPr ? existingPr.body : "");
  const stageDir = fs.mkdtempSync(path.join(os.tmpdir(), "evcommit-pr-"));

  try {
    const pendingAttachments = [];
    const expectedUiAltTags = [];
    const sectionLines = [
      "## Verification Evidence (`evidence-commit`)",
      "",
      `- **Base branch:** \`${baseBranch}\` | **Head OID:** \`${headOid}\``,
      `- **Verified commits:** ${verifiedBundles.length} / ${commitOids.length}`,
    ];
    if (missingCommits.length > 0) {
      sectionLines.push(`- **Unverified gaps:** ${missingCommits.join("; ")}`);
    }

    for (const item of verifiedBundles) {
      const { bundleDir, manifest, oid, subject } = item;
      const shortSha = oid.slice(0, 8);
      sectionLines.push(
        "",
        `### \`${shortSha}\` — ${subject}`,
        `- **Tree:** \`${manifest.tree_oid.slice(0, 12)}\` | **Mode:** \`${manifest.verification_mode}\` | **Evidence-ID:** \`${manifest.evidence_id}\``,
        `- **Case:** ${manifest.case_name}`,
        `- **Why:** ${manifest.why}`,
      );

      if (manifest.before) {
        const bText = manifest.before.quotes.map((q) => q.text).join("\n");
        const fence = safeFenceForText(bText);
        sectionLines.push(
          "",
          `**Before** (\`${manifest.before.argv_display}\`, exit \`${manifest.before.exit_code}\`):`,
          `${fence}text`,
          bText,
          fence,
        );
      }

      if (manifest.after) {
        const aText = manifest.after.quotes.map((q) => q.text).join("\n");
        const fence = safeFenceForText(aText);
        sectionLines.push(
          "",
          `**After** (\`${manifest.after.argv_display}\`, exit \`${manifest.after.exit_code}\`):`,
          `${fence}text`,
          aText,
          fence,
        );
      }

      if (manifest.ui_details) {
        const ui = manifest.ui_details;
        const resolveSlotRef = (kind, metaObj) => {
          if (!metaObj) return "_N/A (new surface)_";
          const altTag = `evc-${shortSha}-${kind}-${metaObj.sha256.slice(0, 12)}`;
          expectedUiAltTags.push(altTag);
          if (existingHosted.has(altTag)) {
            return `![${altTag}](${existingHosted.get(altTag)})`;
          }
          const srcImg = path.join(bundleDir, "ui", `${kind}.${metaObj.ext}`);
          const bytes = fs.readFileSync(srcImg);
          const fileName = `${altTag}.${metaObj.ext}`;
          fs.writeFileSync(path.join(stageDir, fileName), bytes);
          pendingAttachments.push({ altTag, fileName });
          return `![${altTag}](./${fileName})`;
        };

        const beforeCell = resolveSlotRef("before", ui.before);
        const afterCell = resolveSlotRef("after", ui.after);
        sectionLines.push(
          "",
          `**Visual Verification** (route \`${ui.route}\`, viewport \`${ui.viewport}\`, theme \`${ui.theme}\`):`,
          "",
          "| Before | After |",
          "| :---: | :---: |",
          `| ${beforeCell} | ${afterCell} |`,
        );
        if (ui.notes) {
          sectionLines.push("", `- **Inspection notes:** ${ui.notes}`);
        }
      }
    }

    const expectedReportInner = sectionLines.join("\n");
    const prTitle =
      flags.title || verifiedBundles[verifiedBundles.length - 1]?.subject || headBranch;
    scanPublicTextPrivacy(prTitle, "pr_title");

    // Batch attachments in <= MAX_ATTACH_PER_CALL chunks from cwd=stageDir so ./<fileName> resolves on all gh >= 2.99+
    const batches = [];
    if (pendingAttachments.length === 0) {
      batches.push([]);
    } else {
      for (let i = 0; i < pendingAttachments.length; i += MAX_ATTACH_PER_CALL) {
        batches.push(pendingAttachments.slice(i, i + MAX_ATTACH_PER_CALL));
      }
    }

    let targetPrNumber = existingPr ? existingPr.number : null;
    let lastGhRes = null;
    let latestBody = existingPr ? existingPr.body : null;

    for (let bIdx = 0; bIdx < batches.length; bIdx++) {
      const batch = batches[bIdx];
      const currentHosted = parseExistingHostedUiUrls(latestBody || "");
      let batchInner = expectedReportInner;
      for (const [altTag, url] of currentHosted.entries()) {
        batchInner = batchInner.replaceAll(`![${altTag}](./${altTag}.png)`, `![${altTag}](${url})`);
        batchInner = batchInner.replaceAll(`![${altTag}](./${altTag}.jpg)`, `![${altTag}](${url})`);
        batchInner = batchInner.replaceAll(`![${altTag}](./${altTag}.webp)`, `![${altTag}](${url})`);
      }

      const bodyText = mergeReportBlockIntoBody(
        latestBody,
        flags.summary || verifiedBundles.map((b) => `- ${b.subject}: ${b.manifest.why}`).join("\n"),
        flags.closes,
        batchInner,
      );
      scanPublicTextPrivacy(bodyText, "rendered_pr_body");

      const bodyFile = path.join(stageDir, "pr_body.md");
      fs.writeFileSync(bodyFile, bodyText, "utf8");
      const attachArgs = batch.flatMap((item) => ["--attach", `./${item.fileName}`]);

      if (!targetPrNumber) {
        lastGhRes = invokeGhCli(
          stageDir,
          [
            "pr",
            "create",
            ...repoArgs,
            "--base",
            baseBranch,
            "--head",
            headBranch,
            "--title",
            prTitle,
            "--body-file",
            "pr_body.md",
            ...(flags.draft ? ["--draft"] : []),
            ...attachArgs,
          ],
          ghOverride,
        );
        const discovered = findOpenPrByPair();
        if (discovered) {
          targetPrNumber = discovered.number;
          latestBody = discovered.body;
        }
      } else {
        const freshBeforeEdit = viewPrByNumber(targetPrNumber);
        if (freshBeforeEdit) latestBody = freshBeforeEdit.body;
        const refreshedBody = mergeReportBlockIntoBody(
          latestBody,
          flags.summary,
          flags.closes,
          batchInner,
        );
        scanPublicTextPrivacy(refreshedBody, "rendered_pr_body");
        fs.writeFileSync(bodyFile, refreshedBody, "utf8");

        lastGhRes = invokeGhCli(
          stageDir,
          [
            "pr",
            "edit",
            String(targetPrNumber),
            ...repoArgs,
            "--body-file",
            "pr_body.md",
            ...attachArgs,
          ],
          ghOverride,
        );
        const afterBatchView = viewPrByNumber(targetPrNumber);
        if (afterBatchView) latestBody = afterBatchView.body;
      }
    }

    if (!targetPrNumber) {
      throw new Error(
        `gh PR creation failed and no open PR was found for ${headBranch} -> ${baseBranch}: ${(lastGhRes?.stderr || lastGhRes?.stdout || "").trim()}`,
      );
    }

    const remotePr = viewPrByNumber(targetPrNumber);
    if (!remotePr) {
      throw new Error(`Could not read back PR #${targetPrNumber} from GitHub.`);
    }
    if (remotePr.baseRefName && remotePr.baseRefName !== baseBranch) {
      throw new Error(
        `Remote PR #${remotePr.number} targets base "${remotePr.baseRefName}", expected "${baseBranch}".`,
      );
    }
    if (remotePr.headRefOid !== headOid) {
      throw new Error(
        `Remote PR #${remotePr.number} headRefOid (${remotePr.headRefOid}) != local HEAD (${headOid}).`,
      );
    }

    const remoteBlock = extractSingleReportBlock(remotePr.body || "");
    if (!remoteBlock) {
      throw new Error(
        `Remote PR #${remotePr.number} body is missing the evidence-commit report block.`,
      );
    }

    const residualLocal = [...remoteBlock.inner.matchAll(/!\[evc-[^\]]+\]\(\.\/[^)]+\)/g)].map(
      (m) => m[0],
    );
    if (residualLocal.length > 0) {
      throw new Error(
        `PARTIAL_PUBLISH_INCOMPLETE: PR ${remotePr.url} exists, but ${residualLocal.length} image attachment(s) remain un-hosted (${residualLocal.join(", ")}). Re-run \`publish-pr\` to recover.`,
      );
    }

    const remoteHosted = parseExistingHostedUiUrls(remotePr.body || "");
    for (const altTag of expectedUiAltTags) {
      if (!remoteHosted.has(altTag)) {
        throw new Error(
          `PARTIAL_PUBLISH_INCOMPLETE: PR ${remotePr.url} is missing hosted asset URL for ${altTag}.`,
        );
      }
    }

    if (
      normalizeHostedUrlsForComparison(remoteBlock.inner) !==
      normalizeHostedUrlsForComparison(expectedReportInner)
    ) {
      throw new Error(
        `Remote PR #${remotePr.number} evidence block content drifted from expected verified report.`,
      );
    }

    if (lastGhRes && lastGhRes.status !== 0) {
      throw new Error(
        `gh exited with non-zero code ${lastGhRes.status}: ${(lastGhRes.stderr || "").trim()}`,
      );
    }

    if (missingCommits.length > 0 || verifiedBundles.length === 0) {
      process.stdout.write(
        `PUBLISH_PR_PARTIAL_GAPS number=${remotePr.number} url=${remotePr.url} verified=${verifiedBundles.length}/${commitOids.length}\n`,
      );
      process.exit(4);
    }

    process.stdout.write(
      `PUBLISH_PR_VERIFIED number=${remotePr.number} url=${remotePr.url} head=${remotePr.headRefOid} ui_attachments=${expectedUiAltTags.length}\n`,
    );
  } finally {
    fs.rmSync(stageDir, { recursive: true, force: true });
  }
}

async function cmdStage(argv) {
  const { flags, multi } = parseFlags(argv);
  if (multi.files.length === 0) {
    throw new Error("`stage` requires `--files <path1> [path2 ...]`.");
  }
  const { repoRoot, parentOid } = resolveRepoContext();
  checkUnmergedEntries(repoRoot);
  checkHiddenIndexFlags(repoRoot);

  const requestedNorm = multi.files.map((raw) => {
    const rel = normalizeRepoRelPath(raw);
    for (const pat of FORBIDDEN_STAGE_PATTERNS) {
      if (pat.test(rel)) {
        throw new Error(`Refusing to stage sensitive file pattern "${rel}".`);
      }
    }
    const diskPath = path.join(repoRoot, rel);
    if (fs.existsSync(diskPath)) {
      const st = fs.lstatSync(diskPath);
      if (st.isDirectory()) {
        throw new Error(
          `Directory staging ("${rel}") is forbidden because it can sweep in unrequested files; list explicit file paths.`,
        );
      }
      if (st.isSymbolicLink()) {
        throw new Error(`Staging symlink "${rel}" is forbidden; stage regular files only.`);
      }
    }
    return rel;
  });

  const existingStaged = listStagedPaths(repoRoot, parentOid);
  if (existingStaged.length > 0 && !flags["reset-index"]) {
    const extra = existingStaged.filter((f) => !requestedNorm.includes(f));
    if (extra.length > 0) {
      throw new Error(
        `Index already contains unrelated staged files (${extra.join(", ")}). Inspect before staging or pass --reset-index if intentional.`,
      );
    }
  }
  if (flags["reset-index"] && parentOid) {
    git(repoRoot, ["reset", "-q", "HEAD", "--"]);
  } else if (flags["reset-index"] && !parentOid) {
    git(repoRoot, ["rm", "-r", "-f", "--cached", "-q", "--ignore-unmatch", "."]);
  }

  git(repoRoot, ["add", "--", ...requestedNorm]);
  const postStaged = listStagedPaths(repoRoot, parentOid);
  for (const sFile of postStaged) {
    for (const pat of FORBIDDEN_STAGE_PATTERNS) {
      if (pat.test(sFile)) {
        throw new Error(`Staged index contains forbidden sensitive path "${sFile}".`);
      }
    }
  }

  const stagedDiff = git(repoRoot, ["diff", "--cached", "-U0"]).stdout;
  for (const line of stagedDiff.split(/\r?\n/)) {
    if (line.startsWith("+") && !line.startsWith("+++")) {
      if (/^\+(<{7}|={7}|>{7})(?:\s|$)/.test(line)) {
        throw new Error("Staged diff introduces unresolved Git conflict markers.");
      }
    }
  }
  const treeOid = git(repoRoot, ["write-tree"]).stdout.trim();
  process.stdout.write(`STAGED_OK files=${postStaged.length} tree=${treeOid}\n`);
}

async function cmdInit(argv) {
  const { flags } = parseFlags(argv);
  const mode = flags.mode || "snapshot";
  if (!ALLOWED_MODES.has(mode)) throw new Error(`Invalid --mode "${mode}".`);

  const { repoRoot, gitDir, parentOid } = resolveRepoContext();
  checkUnmergedEntries(repoRoot);
  checkHiddenIndexFlags(repoRoot);

  const stagedFiles = listStagedPaths(repoRoot, parentOid);
  if (stagedFiles.length === 0) {
    throw new Error("Nothing is staged in the Git index. Stage exact files before `init`.");
  }

  const treeOid = git(repoRoot, ["write-tree"]).stdout.trim();
  if (mode === "snapshot") {
    assertSnapshotSafeTree(repoRoot, treeOid, "Staged candidate tree");
  }

  const rawId = flags["run-id"] || `${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
  const runId = validateRunId(rawId);
  const base = path.resolve(gitDir, "proof-commit");
  const runDir = path.join(base, "runs", runId);
  fs.mkdirSync(runDir, { recursive: true });
  writeFileAtomic(path.join(base, "current-run.txt"), Buffer.from(`${runId}\n`, "utf8"));

  const state = {
    schema_version: 1,
    run_id: runId,
    created_at: new Date().toISOString(),
    parent_oid: parentOid,
    tree_oid: treeOid,
    staged_files: [...stagedFiles].sort(),
    verification_mode: mode,
    case_name: flags.case || "",
    overlay: [],
    before: null,
    after: null,
    ui: null,
  };
  saveRunState(path.join(runDir, "state.json"), state);
  process.stdout.write(
    `INIT_OK run_id=${runId} parent=${parentOid || "root:none"} tree=${treeOid} mode=${mode}\n`,
  );
}

async function cmdRecord(argv) {
  const { flags, multi, cmdAfterDashDash } = parseFlags(argv);
  const phase = flags.phase;
  if (phase !== "before" && phase !== "after") {
    throw new Error("`record` requires `--phase before|after`.");
  }
  if (!cmdAfterDashDash || cmdAfterDashDash.length === 0) {
    throw new Error("`record` requires `-- <executable> [args...]`.");
  }

  const { repoRoot, gitDir, parentOid } = resolveRepoContext();
  const { runDir, statePath, state } = loadRunState(gitDir, flags["run-id"]);
  const currentTree = git(repoRoot, ["write-tree"]).stdout.trim();

  if (state.parent_oid !== parentOid) {
    throw new Error(
      `HEAD drifted since init (expected ${state.parent_oid}, got ${parentOid}). Re-run init.`,
    );
  }
  if (state.tree_oid !== currentTree) {
    throw new Error(
      `Staged tree drifted since init (expected ${state.tree_oid.slice(0, 12)}, got ${currentTree.slice(0, 12)}). Re-run init so evidence binds to the exact staged tree.`,
    );
  }

  const mode = flags.mode || state.verification_mode || "snapshot";
  if (!ALLOWED_MODES.has(mode)) throw new Error(`Invalid --mode "${mode}".`);

  let execDir = repoRoot;
  let tempRoot = null;
  let overlayRecords = [];

  try {
    if (phase === "before") {
      if (!parentOid) {
        throw new Error("Cannot record `before` on an unborn root repository (`parent = null`).");
      }
      if (mode === "snapshot") {
        tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "evcommit-before-"));
        execDir = path.join(tempRoot, "checkout");
        materializeTreeToDir(repoRoot, parentOid, execDir, "Parent baseline tree");
        if (multi.overlay.length > 0) {
          overlayRecords = applyOverlayFromTree(
            repoRoot,
            parentOid,
            currentTree,
            multi.overlay,
            execDir,
          );
        }
      } else {
        if (multi.overlay.length > 0) {
          throw new Error("`--overlay` requires `--mode snapshot` so parent tree P is isolated.");
        }
        checkHiddenIndexFlags(repoRoot);
      }
    } else {
      if (mode === "snapshot") {
        tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "evcommit-after-"));
        execDir = path.join(tempRoot, "checkout");
        materializeTreeToDir(repoRoot, currentTree, execDir, "Staged candidate tree");
      } else {
        checkHiddenIndexFlags(repoRoot);
      }
    }

    const result = await runCommandCapture(
      cmdAfterDashDash,
      execDir,
      flags["timeout-ms"] ? Number(flags["timeout-ms"]) : 300000,
    );
    if (result.timedOut) {
      throw new Error(`Command timed out after ${result.durationMs}ms.`);
    }

    const postTree = git(repoRoot, ["write-tree"]).stdout.trim();
    if (postTree !== currentTree) {
      throw new Error("Staged index tree changed while verification command was running.");
    }

    // Invalidate stale phase metadata before writing logs, then atomically persist logs + metadata
    if (phase === "before") state.before = null;
    else state.after = null;
    saveRunState(statePath, state);

    writeFileAtomic(path.join(runDir, `${phase}.stdout.log`), result.stdout);
    writeFileAtomic(path.join(runDir, `${phase}.stderr.log`), result.stderr);

    const displayCmd = formatDisplayCmd(cmdAfterDashDash);
    const phaseRecord = {
      argv_display: displayCmd,
      duration_ms: result.durationMs,
      exit_code: result.exitCode,
      mode,
      recorded_at: new Date().toISOString(),
      signal: result.signal,
      stderr_bytes: result.stderr.length,
      stderr_sha256: sha256Hex(result.stderr),
      stdout_bytes: result.stdout.length,
      stdout_sha256: sha256Hex(result.stdout),
    };

    if (phase === "before") {
      state.overlay = overlayRecords;
      state.before = phaseRecord;
    } else {
      state.after = phaseRecord;
    }

    const modesUsed = new Set(
      [state.before?.mode, state.after?.mode].filter(Boolean),
    );
    state.verification_mode =
      modesUsed.size === 1 && modesUsed.has("snapshot") ? "snapshot" : "workspace";

    saveRunState(statePath, state);
    process.stdout.write(
      `RECORD_OK phase=${phase} mode=${mode} exit=${result.exitCode} stdout_bytes=${result.stdout.length} stderr_bytes=${result.stderr.length}\n`,
    );
  } finally {
    if (tempRoot) {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
  }
}

async function cmdAttachUi(argv) {
  const { flags } = parseFlags(argv);
  if (!flags.after || !flags.route || !flags.viewport) {
    throw new Error("`attach-ui` requires `--after <imgPath> --route <route> --viewport <WxH>`.");
  }
  if (!/^\d+x\d+$/i.test(flags.viewport)) {
    throw new Error(`Invalid --viewport "${flags.viewport}" (expected WxH, e.g., 1440x900).`);
  }

  const { gitDir } = resolveRepoContext();
  const { runDir, statePath, state } = loadRunState(gitDir, flags["run-id"]);
  const uiDir = path.join(runDir, "ui");
  fs.mkdirSync(uiDir, { recursive: true });

  const afterBytes = fs.readFileSync(path.resolve(flags.after));
  const afterInfo = parseImageDimensions(afterBytes);
  const afterHash = sha256Hex(afterBytes);
  const afterExt = afterInfo.format === "jpeg" ? "jpg" : afterInfo.format;
  writeFileAtomic(path.join(uiDir, `after.${afterExt}`), afterBytes);

  let beforeEntry = null;
  if (flags.before) {
    const beforeBytes = fs.readFileSync(path.resolve(flags.before));
    const beforeInfo = parseImageDimensions(beforeBytes);
    const beforeHash = sha256Hex(beforeBytes);
    const beforeExt = beforeInfo.format === "jpeg" ? "jpg" : beforeInfo.format;
    writeFileAtomic(path.join(uiDir, `before.${beforeExt}`), beforeBytes);
    beforeEntry = {
      ext: beforeExt,
      format: beforeInfo.format,
      height: beforeInfo.height,
      sha256: beforeHash,
      width: beforeInfo.width,
    };
  } else if (state.parent_oid && !flags["new-surface-reason"]) {
    throw new Error(
      "Existing repository commits with UI evidence require `--before <imgPath>` unless `--new-surface-reason` explains why no prior surface existed.",
    );
  }

  state.ui = {
    after: {
      ext: afterExt,
      format: afterInfo.format,
      height: afterInfo.height,
      sha256: afterHash,
      width: afterInfo.width,
    },
    before: beforeEntry,
    new_surface_reason: flags["new-surface-reason"] || null,
    notes: flags.notes || "",
    route: flags.route,
    theme: flags.theme || "default",
    viewport: flags.viewport.toLowerCase(),
  };
  saveRunState(statePath, state);
  process.stdout.write(
    `ATTACH_UI_OK route=${state.ui.route} viewport=${state.ui.viewport} after_sha256=${afterHash.slice(0, 12)}\n`,
  );
}

function buildValidatedCommitPlan(repoCtx, runBundle, flags) {
  const { repoRoot, parentOid } = repoCtx;
  const { runDir, state } = runBundle;

  const type = flags.type;
  if (!ALLOWED_TYPES.has(type)) {
    throw new Error(`Invalid or missing --type "${type}". Allowed: ${[...ALLOWED_TYPES].join(", ")}`);
  }
  const title = (flags.title || "").trim();
  const why = flags["why-file"]
    ? fs.readFileSync(path.resolve(flags["why-file"]), "utf8").trim()
    : (flags.why || "").trim();
  if (!title) throw new Error("`--title` is required.");
  if (title.length > 72 || /\r|\n/.test(title)) {
    throw new Error("`--title` must be a single line <= 72 chars.");
  }
  if (why.length < 20) {
    throw new Error("`--why` must provide a substantive causal explanation (>= 20 chars).");
  }

  checkUnmergedEntries(repoRoot);
  checkHiddenIndexFlags(repoRoot);
  const liveTree = git(repoRoot, ["write-tree"]).stdout.trim();
  if (state.parent_oid !== parentOid) {
    throw new Error(`HEAD changed since evidence was recorded (${state.parent_oid} != ${parentOid}).`);
  }
  if (state.tree_oid !== liveTree) {
    throw new Error(
      `Staged tree (${liveTree.slice(0, 12)}) does not match verified tree (${state.tree_oid.slice(0, 12)}). Re-record evidence for the current staged tree.`,
    );
  }

  const liveStagedFiles = listStagedPaths(repoRoot, parentOid).sort();
  if (!state.after) {
    throw new Error("Missing `after` verification record. Run `record --phase after` first.");
  }
  if (state.after.exit_code !== 0) {
    throw new Error(`Candidate \`after\` verification exited with non-zero code ${state.after.exit_code}.`);
  }

  const needsBefore =
    type === "fix" ||
    type === "perf" ||
    (type === "refactor" && parentOid !== null);
  if (needsBefore && !state.before) {
    throw new Error(`Commit type "${type}" requires a recorded \`before\` baseline on parent commit.`);
  }

  if (
    (type === "fix" || type === "refactor") &&
    state.before &&
    state.before.argv_display !== state.after.argv_display &&
    !flags["allow-different-probe-cmd"]
  ) {
    throw new Error(
      `Commit type "${type}" requires \`before\` and \`after\` to execute the identical probe command ("${state.before.argv_display}" != "${state.after.argv_display}").`,
    );
  }

  const touchesUiPath = liveStagedFiles.some((f) => UI_EXT_RE.test(f));
  if ((type === "ui" || (touchesUiPath && !flags["no-ui-impact"])) && !state.ui) {
    throw new Error(
      `Staged UI changes require \`attach-ui\` visual proof (or explicit \`--no-ui-impact "<reason>"\` if non-visual).`,
    );
  }

  const maxLines = flags["max-lines"] ? Number(flags["max-lines"]) : 3;
  const afterSel = selectQuotesFromPhase(runDir, "after", state.after, flags["pick-after"], maxLines);
  assertNotSkippedOrZeroTests(afterSel.allLines, afterSel.quotes, "After");

  let beforeQuotes = null;
  if (state.before) {
    const beforeSel = selectQuotesFromPhase(
      runDir,
      "before",
      state.before,
      flags["pick-before"],
      maxLines,
    );
    beforeQuotes = beforeSel.quotes;
    if (type === "fix" && state.before.exit_code === 0) {
      const bTxt = beforeQuotes.map((q) => q.text).join("\n");
      const aTxt = afterSel.quotes.map((q) => q.text).join("\n");
      if (bTxt === aTxt) {
        throw new Error(
          "Bugfix `before` exited 0 and its selected verbatim quote is identical to `after`; select lines showing the prior defect vs fixed behavior.",
        );
      }
    }
  }

  const effectiveMode =
    (!state.before || state.before.mode === "snapshot") && state.after.mode === "snapshot"
      ? "snapshot"
      : "workspace";

  const caseName = (flags.case || state.case_name || title).trim();
  const scope = flags.scope ? flags.scope.trim() : null;

  const canonicalPayload = {
    after: {
      argv_display: state.after.argv_display,
      exit_code: state.after.exit_code,
      mode: state.after.mode,
      quotes: afterSel.quotes,
      stderr_sha256: state.after.stderr_sha256,
      stdout_sha256: state.after.stdout_sha256,
    },
    before: state.before
      ? {
          argv_display: state.before.argv_display,
          exit_code: state.before.exit_code,
          mode: state.before.mode,
          quotes: beforeQuotes,
          stderr_sha256: state.before.stderr_sha256,
          stdout_sha256: state.before.stdout_sha256,
        }
      : null,
    case_name: caseName,
    overlay: state.overlay || [],
    parent_oid: parentOid,
    schema_version: 1,
    scope,
    tree_oid: liveTree,
    type,
    ui: state.ui
      ? {
          after_sha256: state.ui.after.sha256,
          before_sha256: state.ui.before ? state.ui.before.sha256 : null,
          new_surface_reason: state.ui.new_surface_reason,
          route: state.ui.route,
          theme: state.ui.theme,
          viewport: state.ui.viewport,
        }
      : null,
    verification_mode: effectiveMode,
  };

  const evidenceId = computeEvidenceId(canonicalPayload);
  if (/Evidence-ID:/i.test(why) || /Evidence-ID:/i.test(flags.granularity || "")) {
    throw new Error("Author text fields must not inject synthetic `Evidence-ID:` trailers.");
  }

  const header = scope ? `${type}(${scope}): ${title}` : `${type}: ${title}`;
  let baselineDesc = !parentOid
    ? "root: none"
    : state.before?.mode === "workspace"
      ? `workspace@${parentOid.slice(0, 12)}`
      : parentOid.slice(0, 12);
  if (state.overlay && state.overlay.length > 0) {
    const ovlStr = state.overlay
      .map((o) => `${o.path}@blob:${o.blob_oid.slice(0, 10)}`)
      .join(", ");
    baselineDesc += `; overlay [${ovlStr}]`;
  }

  const msgLines = [header, "", "Why:", why];
  if (flags.granularity) {
    msgLines.push("", "Granularity:", flags.granularity.trim());
  }
  msgLines.push(
    "",
    "Evidence:",
    `- Baseline: ${baselineDesc}`,
    `- Verification: ${effectiveMode}; candidate tree ${liveTree.slice(0, 12)}`,
    `- Case: ${caseName}`,
  );

  if (state.before && beforeQuotes) {
    const bStreams = [...new Set(beforeQuotes.map((q) => q.stream))].join("+");
    msgLines.push(
      `- Before (${state.before.argv_display}, exit ${state.before.exit_code}, ${bStreams}):`,
    );
    for (const q of beforeQuotes) {
      msgLines.push(`  | ${q.text}`);
    }
  }

  const aStreams = [...new Set(afterSel.quotes.map((q) => q.stream))].join("+");
  msgLines.push(`- After (${state.after.argv_display}, exit ${state.after.exit_code}, ${aStreams}):`);
  for (const q of afterSel.quotes) {
    msgLines.push(`  | ${q.text}`);
  }

  msgLines.push("");
  if (state.ui) {
    const bRef = state.ui.before
      ? `sha256:${state.ui.before.sha256.slice(0, 16)}`
      : `none(${state.ui.new_surface_reason || "new"})`;
    const aRef = `sha256:${state.ui.after.sha256.slice(0, 16)}`;
    msgLines.push(
      `UI-Evidence: route=${state.ui.route} viewport=${state.ui.viewport} before=${bRef} after=${aRef}`,
    );
  }
  msgLines.push(`Evidence-ID: ${evidenceId}`);

  const commitMessage = `${msgLines.join("\n")}\n`;
  scanPublicTextPrivacy(commitMessage, "rendered_commit_message");
  if (state.ui?.notes) {
    scanPublicTextPrivacy(state.ui.notes, "ui_notes");
  }

  return { canonicalPayload, commitMessage, evidenceId, liveStagedFiles, liveTree, parentOid };
}

async function cmdVerify(argv) {
  const { flags } = parseFlags(argv);
  const repoCtx = resolveRepoContext();
  const runBundle = loadRunState(repoCtx.gitDir, flags["run-id"]);
  const plan = buildValidatedCommitPlan(repoCtx, runBundle, flags);
  process.stdout.write(
    `VERIFY_OK evidence_id=${plan.evidenceId} tree=${plan.liveTree}\n---\n${plan.commitMessage}`,
  );
}

export function parseCommitObjectHeaderAndBody(rawCommitObj) {
  const headerEnd = rawCommitObj.indexOf("\n\n");
  const headerBlock = headerEnd >= 0 ? rawCommitObj.slice(0, headerEnd) : rawCommitObj;
  const bodyBlock = headerEnd >= 0 ? rawCommitObj.slice(headerEnd + 2) : "";
  const treeMatch = /^tree ([0-9a-f]{40,64})$/m.exec(headerBlock);
  const parentMatches = [...headerBlock.matchAll(/^parent ([0-9a-f]{40,64})$/gm)].map((m) => m[1]);
  return {
    actualParent: parentMatches.length === 0 ? null : parentMatches[0],
    actualTree: treeMatch ? treeMatch[1] : null,
    bodyBlock,
    parentCount: parentMatches.length,
  };
}

async function cmdCommit(argv) {
  const { flags } = parseFlags(argv);
  const repoCtx = resolveRepoContext();
  const runBundle = loadRunState(repoCtx.gitDir, flags["run-id"]);
  const plan = buildValidatedCommitPlan(repoCtx, runBundle, flags);

  const msgFile = path.join(runBundle.runDir, "COMMIT_EDITMSG");
  writeFileAtomic(msgFile, Buffer.from(plan.commitMessage, "utf8"));

  const preParent = (() => {
    const r = git(repoCtx.repoRoot, ["rev-parse", "--verify", "HEAD"], { allowFail: true });
    return r.status === 0 ? r.stdout.trim() : null;
  })();
  const preTree = git(repoCtx.repoRoot, ["write-tree"]).stdout.trim();
  if (preParent !== plan.parentOid || preTree !== plan.liveTree) {
    throw new Error("Repository state mutated immediately before `git commit`; aborting safely.");
  }

  git(repoCtx.repoRoot, ["commit", "--cleanup=verbatim", "-F", msgFile]);

  const commitOid = git(repoCtx.repoRoot, ["rev-parse", "HEAD"]).stdout.trim();
  const rawCommitObj = git(repoCtx.repoRoot, ["cat-file", "commit", commitOid]).stdout;
  const { actualTree, actualParent, bodyBlock, parentCount } =
    parseCommitObjectHeaderAndBody(rawCommitObj);

  if (parentCount > 1) {
    throw new Error(`Expected non-merge commit, found ${parentCount} parents on ${commitOid}.`);
  }
  if (actualTree !== plan.liveTree) {
    throw new Error(
      `Post-commit drift detected: commit ${commitOid.slice(0, 12)} recorded tree ${actualTree} instead of verified tree ${plan.liveTree} (likely modified by a pre-commit hook). Do NOT publish unverified drift.`,
    );
  }
  if (actualParent !== plan.parentOid) {
    throw new Error(`Post-commit parent mismatch (${actualParent} != ${plan.parentOid}).`);
  }
  if (bodyBlock !== plan.commitMessage) {
    scanPublicTextPrivacy(bodyBlock, "post_hook_commit_body");
    throw new Error(
      `Post-commit message drift detected on ${commitOid.slice(0, 12)}: a commit-msg hook altered the verified commit message.`,
    );
  }

  const digestHex = plan.evidenceId.replace(/^sha256:/, "");
  const bundleDir = path.join(repoCtx.commonDir, "proof-commit", "bundles", digestHex);
  fs.mkdirSync(bundleDir, { recursive: true });

  const fullManifest = {
    ...plan.canonicalPayload,
    commit_message: plan.commitMessage,
    commit_oid: commitOid,
    committed_at: new Date().toISOString(),
    evidence_id: plan.evidenceId,
    granularity: flags.granularity ? flags.granularity.trim() : null,
    staged_files: plan.liveStagedFiles,
    title: flags.title.trim(),
    ui_details: runBundle.state.ui,
    why: flags["why-file"]
      ? fs.readFileSync(path.resolve(flags["why-file"]), "utf8").trim()
      : flags.why.trim(),
  };

  for (const f of ["before.stdout.log", "before.stderr.log", "after.stdout.log", "after.stderr.log"]) {
    const src = path.join(runBundle.runDir, f);
    if (fs.existsSync(src)) writeFileAtomic(path.join(bundleDir, f), fs.readFileSync(src));
  }
  const srcUi = path.join(runBundle.runDir, "ui");
  if (fs.existsSync(srcUi)) {
    const dstUi = path.join(bundleDir, "ui");
    fs.mkdirSync(dstUi, { recursive: true });
    for (const item of fs.readdirSync(srcUi)) {
      writeFileAtomic(path.join(dstUi, item), fs.readFileSync(path.join(srcUi, item)));
    }
  }
  writeFileAtomic(
    path.join(bundleDir, "manifest.json"),
    Buffer.from(`${JSON.stringify(fullManifest, null, 2)}\n`, "utf8"),
  );

  const commitsMapDir = path.join(repoCtx.commonDir, "proof-commit", "commits");
  fs.mkdirSync(commitsMapDir, { recursive: true });
  writeFileAtomic(
    path.join(commitsMapDir, `${commitOid}.json`),
    Buffer.from(
      `${JSON.stringify({ commit_oid: commitOid, evidence_id: plan.evidenceId, tree_oid: actualTree, parent_oid: actualParent }, null, 2)}\n`,
      "utf8",
    ),
  );

  process.stdout.write(
    `COMMIT_VERIFIED commit=${commitOid} tree=${actualTree} evidence_id=${plan.evidenceId}\n`,
  );
}

async function cmdInspect(argv) {
  const targetRef = argv[0] || "HEAD";
  const { repoRoot, commonDir } = resolveRepoContext();
  const oid = git(repoRoot, ["rev-parse", targetRef]).stdout.trim();
  const mapPath = path.join(commonDir, "proof-commit", "commits", `${oid}.json`);
  if (!fs.existsSync(mapPath)) {
    throw new Error(`No local proof-commit record mapped for commit ${oid}.`);
  }
  const mapping = JSON.parse(fs.readFileSync(mapPath, "utf8"));
  const digestHex = mapping.evidence_id.replace(/^sha256:/, "");
  const manifestPath = path.join(commonDir, "proof-commit", "bundles", digestHex, "manifest.json");
  process.stdout.write(fs.readFileSync(manifestPath, "utf8"));
}

async function main() {
  const [sub, ...rest] = process.argv.slice(2);
  if (!sub || sub === "--help" || sub === "-h") {
    printHelp();
    return;
  }
  if (sub === "stage") await cmdStage(rest);
  else if (sub === "init") await cmdInit(rest);
  else if (sub === "record") await cmdRecord(rest);
  else if (sub === "attach-ui") await cmdAttachUi(rest);
  else if (sub === "verify") await cmdVerify(rest);
  else if (sub === "commit") await cmdCommit(rest);
  else if (sub === "publish-pr") await cmdPublishPr(rest);
  else if (sub === "inspect") await cmdInspect(rest);
  else fail(`Unknown subcommand "${sub}". Run with --help for usage.`, 2);
}

const isDirectRun =
  Boolean(process.argv[1]) &&
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));

if (isDirectRun) {
  main().catch((err) => fail(err?.message || String(err), 1));
}
