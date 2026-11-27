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

const FORBIDDEN_DISPLAY_CTRL_RE =
  /[\x00-\x1f\x7f-\x9f\r\n\u00ad\u034f\u061c\u115f\u1160\u180e\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2069\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff9-\ufffb\u{e0000}-\u{e007f}]/u;
const FORBIDDEN_MULTILINE_CTRL_RE =
  /[\x00-\x08\x0b-\x1f\x7f-\x9f\r\u00ad\u034f\u061c\u115f\u1160\u180e\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2069\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff9-\ufffb\u{e0000}-\u{e007f}]/u;
const RESERVED_TRAILER_LINE_RE =
  /(?:^|\n)\s*(?:Evidence-ID|UI-Evidence|UI-Impact|AI-Reviewed-By):/i;
const RESERVED_SECTION_LINE_RE = /(?:^|\n)\s*(?:Why|Granularity|Evidence):\s*(?:\n|$)/i;
const RESERVED_TRAILER_START_RE =
  /^\s*(?:Evidence-ID|UI-Evidence|UI-Impact|AI-Reviewed-By):/i;
const RESERVED_TRAILER_INLINE_RE =
  /(?:^|\s)(?:Evidence-ID|UI-Evidence|UI-Impact|AI-Reviewed-By):/i;
const RESERVED_SUMMARY_KEYWORD_RE =
  /(?:Evidence-?ID|UI-?Evidence|UI-?Impact|AI-?Reviewed-?By|Verification\s+Evidence)/i;
const EVIDENCE_ID_RE = /^sha256:[0-9a-f]{64}$/;
const ALLOWED_UI_EXTS = new Set(["png", "jpg", "webp"]);
const MAX_REVIEWERS = 16;
const TRUSTED_HOSTED_ASSET_URL_RE =
  /^https:\/\/(?:github\.com\/user-attachments\/assets\/[0-9A-Za-z._-]+|(?:private-)?user-images\.githubusercontent\.com\/[0-9]+\/[0-9A-Za-z._-]+)$/;
const ALLOWED_ASSET_FETCH_HOST_RE =
  /^(?:github\.com|(?:[a-z0-9-]+\.)*githubusercontent\.com|(?:[a-z0-9-]+\.)*amazonaws\.com)$/i;

function collapseInlineWhitespace(text) {
  return String(text ?? "")
    .replace(/[\s\u2028\u2029]+/g, " ")
    .trim();
}

function safeInlineCode(text) {
  const str = String(text ?? "");
  if (str.length === 0) return "";
  let maxTicks = 0;
  for (const m of str.matchAll(/`+/g)) {
    if (m[0].length > maxTicks) maxTicks = m[0].length;
  }
  const delim = "`".repeat(maxTicks + 1);
  const pad = str.startsWith("`") || str.endsWith("`") || str.startsWith(" ") || str.endsWith(" ") ? " " : "";
  return `${delim}${pad}${str}${pad}${delim}`;
}

function canonicalizeSummaryForSpoofCheck(text) {
  return String(text ?? "")
    .normalize("NFKC")
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<[^>]*>/g, "")
    .replace(/&#(\d{1,7});/g, (_, dec) => {
      const cp = Number(dec);
      return cp >= 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : "";
    })
    .replace(/&#x([0-9a-f]{1,6});/gi, (_, hex) => {
      const cp = Number.parseInt(hex, 16);
      return cp >= 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : "";
    })
    .replace(/&shy;/gi, "")
    .replace(/&colon;/gi, ":")
    .replace(/&(?:ndash|mdash|minus|hyphen|dash);/gi, "-")
    .replace(/[\u2010-\u2015\u2212\ufe58\ufe63\uff0d]/g, "-")
    .replace(/[\p{Cf}\p{Cc}*_~`\\]/gu, "");
}

function assertMultilineAuthorField(rawVal, fieldLabel, maxLen = 4000) {
  const normalized = String(rawVal ?? "").replace(/\r\n/g, "\n");
  if (FORBIDDEN_MULTILINE_CTRL_RE.test(normalized)) {
    throw new Error(
      `Invalid ${fieldLabel}: contains bare CR, control, zero-width, line-separator, or Unicode bidi characters.`,
    );
  }
  const trimmed = normalized.trim();
  if (trimmed.length > maxLen) {
    throw new Error(`Invalid ${fieldLabel}: exceeds ${maxLen} characters (${trimmed.length}).`);
  }
  if (RESERVED_TRAILER_LINE_RE.test(trimmed) || RESERVED_SECTION_LINE_RE.test(trimmed)) {
    throw new Error(
      `Invalid ${fieldLabel}: must not inject synthetic section headers (\`Why:\`, \`Granularity:\`, \`Evidence:\`) or commit trailers (\`Evidence-ID:\`, \`UI-Evidence:\`, \`UI-Impact:\`, \`AI-Reviewed-By:\`).`,
    );
  }
  return trimmed;
}

function assertPrSummaryText(rawVal) {
  const normalized = String(rawVal ?? "").replace(/\r\n/g, "\n");
  if (FORBIDDEN_MULTILINE_CTRL_RE.test(normalized)) {
    throw new Error(
      "Invalid summary: contains bare CR, control, zero-width, line-separator, or Unicode bidi characters.",
    );
  }
  const trimmed = normalized.trim();
  if (trimmed.length > 8000) {
    throw new Error(`Invalid summary: exceeds 8000 characters (${trimmed.length}).`);
  }
  if (
    trimmed.includes("<!-- evidence-commit-report:start -->") ||
    trimmed.includes("<!-- evidence-commit-report:end -->")
  ) {
    throw new Error("Invalid summary: must not contain evidence-commit report boundary markers.");
  }
  const skeleton = canonicalizeSummaryForSpoofCheck(trimmed);
  if (RESERVED_SUMMARY_KEYWORD_RE.test(skeleton)) {
    throw new Error(
      "Invalid summary: must not include reserved attribution keywords (AI-Reviewed-By / Evidence-ID / Verification Evidence); pass --reviewed-by to record reviewers.",
    );
  }
  return trimmed;
}

function assertValidEvidenceIdFormat(id, label = "Evidence-ID") {
  if (typeof id !== "string" || !EVIDENCE_ID_RE.test(id)) {
    throw new Error(`Invalid ${label}: expected "sha256:<64 lowercase hex chars>".`);
  }
  return id;
}

function assertPositiveIntFlag(rawVal, flagName, maxVal = 1_000_000_000) {
  const str = String(rawVal ?? "").trim();
  if (!/^[1-9]\d{0,8}$/.test(str)) {
    throw new Error(`Invalid --${flagName}: expected a positive base-10 integer.`);
  }
  const n = Number(str);
  if (!Number.isSafeInteger(n) || n <= 0 || n > maxVal) {
    throw new Error(`Invalid --${flagName}: must be between 1 and ${maxVal}.`);
  }
  return n;
}

function assertSingleLineStructuralField(rawVal, fieldLabel, maxLen = 240) {
  const str = String(rawVal ?? "");
  if (FORBIDDEN_DISPLAY_CTRL_RE.test(str)) {
    throw new Error(
      `Invalid ${fieldLabel}: contains newline, control, zero-width, or Unicode bidi characters.`,
    );
  }
  const trimmed = str.trim();
  if (trimmed.length > maxLen) {
    throw new Error(`Invalid ${fieldLabel}: exceeds ${maxLen} characters (${trimmed.length}).`);
  }
  if (RESERVED_TRAILER_START_RE.test(trimmed)) {
    throw new Error(`Invalid ${fieldLabel}: must not start with a reserved commit trailer keyword.`);
  }
  return trimmed;
}

function cleanReviewerToken(val, fieldLabel) {
  const rawStr = String(val ?? "");
  if (FORBIDDEN_DISPLAY_CTRL_RE.test(rawStr)) {
    throw new Error(
      `Invalid --reviewed-by ${fieldLabel}: contains control, newline, zero-width, or Unicode bidi characters. Expected "<model> via <harness>".`,
    );
  }
  const cleaned = rawStr.replace(/\s+/g, " ").trim();
  if (!cleaned) {
    throw new Error(
      `Invalid --reviewed-by: missing ${fieldLabel}. Expected "<model> via <harness>", "<model> @ <harness>", or "<model> [<harness>]".`,
    );
  }
  if (!/^[\x20-\x7e]+$/.test(cleaned)) {
    throw new Error(
      `Invalid --reviewed-by: ${fieldLabel} must use printable ASCII characters only.`,
    );
  }
  if (cleaned.length > 80) {
    throw new Error(
      `Invalid --reviewed-by: ${fieldLabel} exceeds 80 characters (${cleaned.length}). Keep model and harness concise.`,
    );
  }
  if (/[`|\[\]]/.test(cleaned) || cleaned.includes("<!--") || cleaned.includes("-->")) {
    throw new Error(
      `Invalid --reviewed-by: ${fieldLabel} contains forbidden backtick, pipe, bracket, or HTML comment marker characters.`,
    );
  }
  if (/(?:^|\s)(?:via|@)(?:\s|$)/i.test(cleaned)) {
    throw new Error(
      `Invalid --reviewed-by: ${fieldLabel} contains ambiguous separator tokens ("via" or "@"); pass one "<model> via <harness>" pair per item.`,
    );
  }
  if (RESERVED_TRAILER_INLINE_RE.test(cleaned)) {
    throw new Error(
      `Invalid --reviewed-by: ${fieldLabel} must not contain reserved commit trailer keywords.`,
    );
  }
  scanPublicTextPrivacy(cleaned, `reviewed_by_${fieldLabel}`);
  return cleaned;
}

export function parseReviewerSpec(rawSpec) {
  const rawStr = String(rawSpec ?? "");
  if (FORBIDDEN_DISPLAY_CTRL_RE.test(rawStr)) {
    throw new Error(
      'Invalid --reviewed-by: contains control, newline, zero-width, or Unicode bidi characters. Expected "<model> via <harness>".',
    );
  }
  const trimmed = rawStr.trim();
  if (!trimmed) {
    throw new Error(
      'Invalid --reviewed-by: value cannot be empty. Expected "<model> via <harness>", "<model> @ <harness>", or "<model> [<harness>]".',
    );
  }
  let modelRaw = null;
  let harnessRaw = null;

  const bracketMatch = /^([^\][]+?)\s*\[([^\][]+)\]$/.exec(trimmed);
  const viaMatch = /^(.+?)\s+via\s+(.+)$/i.exec(trimmed);
  const atMatch = /^(.+?)\s+@\s+(.+)$/.exec(trimmed);

  if (bracketMatch) {
    [, modelRaw, harnessRaw] = bracketMatch;
  } else if (viaMatch) {
    [, modelRaw, harnessRaw] = viaMatch;
  } else if (atMatch) {
    [, modelRaw, harnessRaw] = atMatch;
  } else {
    scanPublicTextPrivacy(trimmed, "reviewed_by_spec");
    throw new Error(
      'Invalid --reviewed-by syntax: must specify both model and harness using "<model> via <harness>", "<model> @ <harness>", or "<model> [<harness>]".',
    );
  }

  return {
    harness: cleanReviewerToken(harnessRaw, "harness"),
    model: cleanReviewerToken(modelRaw, "model"),
  };
}

export function normalizeReviewers(entries = []) {
  if (!Array.isArray(entries)) {
    throw new Error("Invalid reviewers collection: expected an array.");
  }
  const parsedList = entries.map((item) => {
    if (item === null || item === undefined) {
      throw new Error("Invalid --reviewed-by: reviewer entry cannot be null or empty.");
    }
    if (typeof item === "string") return parseReviewerSpec(item);
    if (typeof item === "object" && !Array.isArray(item)) {
      return {
        harness: cleanReviewerToken(item.harness, "harness"),
        model: cleanReviewerToken(item.model, "model"),
      };
    }
    throw new Error("Invalid reviewer entry type.");
  });
  const caseRank = (s) =>
    s.replace(/[A-Za-z]/g, (ch) => (ch >= "a" && ch <= "z" ? `0${ch}` : `1${ch}`));
  parsedList.sort((a, b) => {
    const ka = `${a.model.toLowerCase()}\0${a.harness.toLowerCase()}\0${caseRank(a.model)}\0${caseRank(a.harness)}`;
    const kb = `${b.model.toLowerCase()}\0${b.harness.toLowerCase()}\0${caseRank(b.model)}\0${caseRank(b.harness)}`;
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
  const deduped = [];
  const seen = new Set();
  for (const parsed of parsedList) {
    const key = `${parsed.model.toLowerCase()}\0${parsed.harness.toLowerCase()}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(parsed);
    }
  }
  if (deduped.length > MAX_REVIEWERS) {
    throw new Error(`Too many --reviewed-by entries (${deduped.length}); maximum is ${MAX_REVIEWERS}.`);
  }
  return deduped;
}

function formatReviewerTrailer(r) {
  return `AI-Reviewed-By: ${r.model} via ${r.harness}`;
}

function formatReviewerMarkdown(r) {
  return `\`${r.model}\` via \`${r.harness}\``;
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
    ? git(repoRoot, ["diff", "--cached", "--no-renames", "--name-only", "-z"]).stdout
    : git(repoRoot, ["ls-files", "--cached", "-z"]).stdout;
  return [...new Set(splitNul(out))];
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
    rawPath.startsWith(":") ||
    rawPath.includes("*") ||
    rawPath.includes("?")
  ) {
    throw new Error(
      "Wildcard, pathspec-magic, or whole-tree staging is forbidden; list explicit repository-relative file paths.",
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
  const maxExpectedIdatBytes = Math.min(
    256 * 1024 * 1024,
    Math.max(65536, height * (1 + width * 8) * 2),
  );
  const inflated = zlib.inflateSync(Buffer.concat(idatParts), {
    maxOutputLength: maxExpectedIdatBytes,
  });
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
    buf.length >= 21 &&
    buf.toString("ascii", 0, 4) === "RIFF" &&
    buf.toString("ascii", 8, 12) === "WEBP"
  ) {
    const chunk = buf.toString("ascii", 12, 16);
    if (chunk === "VP8X" && buf.length >= 30) {
      return {
        format: "webp",
        width: 1 + buf.readUIntLE(24, 3),
        height: 1 + buf.readUIntLE(27, 3),
      };
    }
    if (chunk === "VP8 " && buf.length >= 30 && buf[23] === 0x9d && buf[24] === 0x01 && buf[25] === 0x2a) {
      const width = buf.readUInt16LE(26) & 0x3fff;
      const height = buf.readUInt16LE(28) & 0x3fff;
      if (width > 0 && height > 0) return { format: "webp", width, height };
    }
    if (chunk === "VP8L" && buf.length >= 25 && buf[20] === 0x2f) {
      const bits = buf.readUInt32LE(21);
      const width = (bits & 0x3fff) + 1;
      const height = ((bits >> 14) & 0x3fff) + 1;
      if (width > 0 && height > 0) return { format: "webp", width, height };
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
      if (process.platform === "win32" && err?.code === "ENOENT" && /^(npm|npx|pnpm|yarn)$/i.test(exe)) {
        reject(
          new Error(
            `spawn ${exe} ENOENT on Windows (shell=false does not resolve .cmd shims); invoke \`node <script>\` directly (e.g. \`node --test\`).`,
          ),
        );
        return;
      }
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
    /^(?:#|ℹ|i)\s*tests\s+0$/im.test(fullText) ||
    /\b0\s+pass(?:ed|ing)\b/i.test(fullText) ||
    /\bran\s+0\s+tests\b/i.test(fullText) ||
    /\bno\s+tests?\s+(?:files?\s+)?found\b/i.test(fullText) ||
    /\[no\s+tests\s+to\s+run\]/i.test(fullText) ||
    /\bcollected\s+0\s+items\b/i.test(fullText)
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

const SUBCOMMAND_FLAGS = {
  "attach-ui": new Set([
    "after",
    "before",
    "new-surface-reason",
    "notes",
    "route",
    "run-id",
    "theme",
    "viewport",
  ]),
  commit: new Set([
    "allow-different-probe-cmd",
    "case",
    "granularity",
    "max-lines",
    "no-ui-impact",
    "pick-after",
    "pick-before",
    "reviewed-by",
    "run-id",
    "scope",
    "title",
    "type",
    "why",
    "why-file",
  ]),
  init: new Set(["case", "mode", "run-id"]),
  "publish-pr": new Set([
    "allow-custom-origin",
    "allow-partial-commits",
    "allow-private-unverified-assets",
    "base",
    "clear-reviewers",
    "closes",
    "draft",
    "gh-bin",
    "repo",
    "reviewed-by",
    "skip-push-check",
    "summary",
    "title",
  ]),
  record: new Set(["mode", "overlay", "phase", "run-id", "timeout-ms"]),
  stage: new Set(["files", "reset-index"]),
  verify: new Set([
    "allow-different-probe-cmd",
    "case",
    "granularity",
    "max-lines",
    "no-ui-impact",
    "pick-after",
    "pick-before",
    "reviewed-by",
    "run-id",
    "scope",
    "title",
    "type",
    "why",
    "why-file",
  ]),
};

function parseFlags(argv, subcommand = null) {
  const flags = {};
  const multi = { files: [], overlay: [], "reviewed-by": [] };
  const boolFlags = new Set([
    "reset-index",
    "help",
    "h",
    "draft",
    "allow-custom-origin",
    "allow-partial-commits",
    "allow-private-unverified-assets",
    "skip-push-check",
    "clear-reviewers",
    "allow-different-probe-cmd",
  ]);
  const allowedSet = subcommand ? SUBCOMMAND_FLAGS[subcommand] : null;
  const checkAllowedKey = (k) => {
    if (allowedSet && !allowedSet.has(k) && k !== "help" && k !== "h") {
      throw new Error(`Unknown or unsupported option "--${k}" for subcommand "${subcommand}".`);
    }
  };
  const preDash = argv.includes("--") ? argv.slice(0, argv.indexOf("--")) : argv;
  for (let hIdx = 0; hIdx < preDash.length; hIdx++) {
    const tok = preDash[hIdx];
    const prev = hIdx > 0 ? preDash[hIdx - 1] : null;
    const prevConsumesValue =
      prev &&
      prev.startsWith("--") &&
      !prev.includes("=") &&
      !boolFlags.has(prev.slice(2));
    if (!prevConsumesValue && (tok === "-h" || tok === "--help" || tok === "--help=true")) {
      printHelp();
      process.exit(0);
    }
  }

  let cmdAfterDashDash = null;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--") {
      cmdAfterDashDash = argv.slice(i + 1);
      break;
    }
    if (arg.startsWith("--") && arg.includes("=")) {
      const eqIdx = arg.indexOf("=");
      const key = arg.slice(2, eqIdx);
      const val = arg.slice(eqIdx + 1);
      checkAllowedKey(key);
      if (key === "files" || key === "overlay" || key === "reviewed-by") {
        multi[key].push(val);
      } else if (boolFlags.has(key)) {
        if (val !== "true" && val !== "false") {
          throw new Error(`Boolean flag --${key} only accepts true or false when given '='.`);
        }
        flags[key] = val === "true";
      } else {
        flags[key] = val;
      }
      continue;
    }
    if (arg === "--files" || arg === "--overlay" || arg === "--reviewed-by") {
      const key = arg.slice(2);
      checkAllowedKey(key);
      const startLen = multi[key].length;
      while (i + 1 < argv.length && !argv[i + 1].startsWith("--") && argv[i + 1] !== "-h") {
        multi[key].push(argv[++i]);
      }
      if (multi[key].length === startLen) {
        throw new Error(`Missing value for ${arg}`);
      }
    } else if (arg.startsWith("--") && boolFlags.has(arg.slice(2))) {
      const key = arg.slice(2);
      checkAllowedKey(key);
      flags[key] = true;
    } else if (arg.startsWith("--")) {
      const key = arg.slice(2);
      checkAllowedKey(key);
      if (i + 1 >= argv.length || argv[i + 1].startsWith("--") || argv[i + 1] === "-h") {
        throw new Error(`Missing value for ${arg}`);
      }
      flags[key] = argv[++i];
    } else {
      throw new Error(
        `Unexpected positional argument at position ${i + 1} (did you forget quotes around an option value or "--" before the command?).`,
      );
    }
  }
  return { flags, multi, cmdAfterDashDash };
}

function printHelp() {
  process.stdout.write(`Usage: node proof_commit.mjs <subcommand> [options]

Subcommands:
  stage       --files <relpath...> [--reset-index]
  init        [--case "<acceptance condition>"] [--mode snapshot|workspace] [--run-id <id>]
  record      --phase before|after [--overlay <test-relpath...>] [--mode snapshot|workspace] [--timeout-ms <n>] [--run-id <id>] -- <exe> [args...]
  attach-ui   [--before <imgPath>] --after <imgPath> --route <route> --viewport <WxH> [--theme <t>] [--notes "<text>"] [--new-surface-reason "<text>"] [--run-id <id>]
  verify      --type <feat|fix|refactor|perf|ui|docs|test|chore> [--scope <s>] --title <t> --why <w> [--why-file <p>] [--case <c>] [--granularity <g>] [--pick-before <re>] [--pick-after <re>] [--max-lines <n>] [--allow-different-probe-cmd] [--no-ui-impact "<reason>"] [--reviewed-by "<model> via <harness>"...] [--run-id <id>]
  commit      --type <feat|fix|refactor|perf|ui|docs|test|chore> [--scope <s>] --title <t> --why <w> [--why-file <p>] [--case <c>] [--granularity <g>] [--pick-before <re>] [--pick-after <re>] [--max-lines <n>] [--allow-different-probe-cmd] [--no-ui-impact "<reason>"] [--reviewed-by "<model> via <harness>"...] [--run-id <id>]
  publish-pr  [--base <branch>] [--repo <[host/]owner/repo>] [--title "<title>"] [--summary "<text>"] [--reviewed-by "<model> via <harness>"...] [--clear-reviewers] [--closes <n>] [--draft] [--allow-custom-origin] [--allow-private-unverified-assets] [--allow-partial-commits] [--skip-push-check] [--gh-bin <path>]
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

function isTrustedHostedAssetUrl(rawUrl, effectiveHost = "github.com") {
  const urlStr = String(rawUrl || "");
  if (urlStr.includes("..")) return false;
  if (TRUSTED_HOSTED_ASSET_URL_RE.test(urlStr)) return true;
  if (effectiveHost && effectiveHost.toLowerCase() !== "github.com") {
    try {
      const u = new URL(urlStr);
      return (
        u.protocol === "https:" &&
        !u.username &&
        !u.password &&
        u.hostname.toLowerCase() === effectiveHost.toLowerCase() &&
        /^\/(?:user-attachments\/assets\/|storage\/user\/)[0-9A-Za-z._/-]+$/.test(u.pathname)
      );
    } catch {
      return false;
    }
  }
  return false;
}

function parseExistingHostedUiUrls(existingBody, effectiveHost = "github.com") {
  const map = new Map();
  const parsed = extractSingleReportBlock(existingBody);
  if (!parsed) return map;
  const seenSlots = new Set();
  const anySlotRe = /!\[(evc-[0-9a-f]{8}-(?:before|after)-[0-9a-f]{12})\]\(([^)\s]+)\)/g;
  for (const m of parsed.inner.matchAll(anySlotRe)) {
    const [, altTag, candidateUrl] = m;
    if (seenSlots.has(altTag)) {
      throw new Error(
        `Corrupted or spoofed PR report block: duplicate UI evidence slot "${altTag}" detected.`,
      );
    }
    seenSlots.add(altTag);
    if (isTrustedHostedAssetUrl(candidateUrl, effectiveHost)) {
      map.set(altTag, candidateUrl);
    }
  }
  return map;
}

function receiptSlotKey(host, repoSlug, altTag) {
  return `${host.toLowerCase()}/${repoSlug.toLowerCase()}#${altTag}`;
}

function resolveAssetFetchFn(explicitFetchFn) {
  if (explicitFetchFn) return explicitFetchFn;
  const mockMapPath = process.env.PROOF_COMMIT_MOCK_ASSET_MAP;
  if (mockMapPath) {
    return async (url) => {
      const mapObj = fs.existsSync(mockMapPath)
        ? JSON.parse(fs.readFileSync(mockMapPath, "utf8"))
        : {};
      const entry = mapObj[url];
      if (!entry || !fs.existsSync(entry)) {
        return { headers: new Map(), status: 404 };
      }
      const bytes = fs.readFileSync(entry);
      return {
        arrayBuffer: async () => bytes,
        headers: new Map([
          ["content-length", String(bytes.length)],
          ["content-type", "image/png"],
        ]),
        status: 200,
      };
    };
  }
  return globalThis.fetch;
}

export async function verifyHostedAssetBytes(
  assetUrl,
  expectedSha256,
  { fetchFn = null, allowPrivateUnverifiedAssets = false, effectiveHost = "github.com" } = {},
) {
  const activeFetch = resolveAssetFetchFn(fetchFn);
  const urlStr = String(assetUrl || "");
  if (!isTrustedHostedAssetUrl(urlStr, effectiveHost)) {
    throw new Error("Untrusted hosted screenshot URL format.");
  }
  let currentUrl = urlStr;
  let res = null;
  for (let hop = 0; ; hop++) {
    let parsedUrl;
    try {
      parsedUrl = new URL(currentUrl);
    } catch {
      throw new Error("Malformed hosted screenshot URL during verification.");
    }
    const hostOk =
      ALLOWED_ASSET_FETCH_HOST_RE.test(parsedUrl.hostname) ||
      (effectiveHost && parsedUrl.hostname.toLowerCase() === effectiveHost.toLowerCase());
    if (parsedUrl.protocol !== "https:" || parsedUrl.username || parsedUrl.password || !hostOk) {
      throw new Error(
        `Refusing to fetch screenshot from untrusted host "${parsedUrl.hostname}".`,
      );
    }
    res = await activeFetch(currentUrl, {
      headers: { Accept: "image/*" },
      redirect: "manual",
      signal: AbortSignal.timeout(15000),
    });
    if (res.status >= 300 && res.status < 400) {
      if (hop >= 5) {
        throw new Error("Hosted screenshot verification exceeded maximum redirect hops.");
      }
      const loc = res.headers?.get?.("location");
      if (!loc) throw new Error("Hosted screenshot redirect missing Location header.");
      currentUrl = new URL(loc, currentUrl).toString();
      continue;
    }
    break;
  }
  const contentType = String(res.headers?.get?.("content-type") || "");
  const isCookieGatedHtml = res.status === 200 && /^text\/html\b/i.test(contentType);
  if (
    (res.status === 401 || res.status === 403 || res.status === 404 || isCookieGatedHtml) &&
    allowPrivateUnverifiedAssets
  ) {
    return { verifiedBytes: false };
  }
  if (isCookieGatedHtml || res.status !== 200) {
    throw new Error(
      `Failed to fetch hosted screenshot for SHA-256 verification (${isCookieGatedHtml ? "received HTML login gate" : `HTTP ${res.status}`}); pass --allow-private-unverified-assets if publishing to a private repository with cookie-gated attachments.`,
    );
  }
  const maxBytes = 64 * 1024 * 1024;
  const declaredLen = Number(res.headers?.get?.("content-length") || 0);
  if (Number.isFinite(declaredLen) && declaredLen > maxBytes) {
    throw new Error("Hosted screenshot exceeds 64 MiB limit.");
  }
  let buf;
  if (res.body && typeof res.body[Symbol.asyncIterator] === "function") {
    const chunks = [];
    let total = 0;
    for await (const chunk of res.body) {
      const b = Buffer.from(chunk);
      total += b.length;
      if (total > maxBytes) {
        throw new Error("Hosted screenshot exceeds 64 MiB limit.");
      }
      chunks.push(b);
    }
    buf = Buffer.concat(chunks, total);
  } else {
    const ab = await res.arrayBuffer();
    buf = Buffer.from(ab);
    if (buf.length > maxBytes) {
      throw new Error("Hosted screenshot exceeds 64 MiB limit.");
    }
  }
  const actualSha = sha256Hex(buf);
  if (actualSha !== expectedSha256) {
    throw new Error(
      `Hosted screenshot SHA-256 mismatch (expected ${expectedSha256.slice(0, 12)}, got ${actualSha.slice(0, 12)}).`,
    );
  }
  return { verifiedBytes: true };
}

function loadTrustedUploadReceipts(commonDir, effectiveHost = "github.com") {
  const receiptsFile = path.join(commonDir, "proof-commit", "pr", "upload-receipts.json");
  if (!fs.existsSync(receiptsFile)) return new Map();
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(receiptsFile, "utf8"));
  } catch {
    throw new Error(`Corrupted upload-receipts.json at ${receiptsFile}; inspect or remove file.`);
  }
  const map = new Map();
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    for (const [k, v] of Object.entries(raw)) {
      if (typeof v === "string" && isTrustedHostedAssetUrl(v, effectiveHost)) {
        map.set(k, v);
      }
    }
  }
  return map;
}

function saveTrustedUploadReceipts(commonDir, receiptsMap) {
  const prDir = path.join(commonDir, "proof-commit", "pr");
  fs.mkdirSync(prDir, { recursive: true });
  const obj = Object.fromEntries([...receiptsMap.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
  writeFileAtomic(
    path.join(prDir, "upload-receipts.json"),
    Buffer.from(`${JSON.stringify(obj, null, 2)}\n`, "utf8"),
  );
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
    parts.push("## Author Summary", "", (summaryText || "Evidence-backed pull request.").trim());
    if (closesIssue) {
      parts.push("", `Closes #${String(closesIssue).replace(/^#/, "")}`);
    }
  }
  parts.push("", wrapped, "");
  return parts.join("\n");
}

function assertSafeOwnerRepoSegments(slug) {
  const m = /^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/.exec(slug);
  if (!m) return null;
  const [, owner, repo] = m;
  if (owner === "." || owner === ".." || repo === "." || repo === "..") return null;
  return `${owner}/${repo}`;
}

export function parseRepoTargetInput(rawSlug, { allowCustomHost = false } = {}) {
  if (!rawSlug) return null;
  const trimmed = String(rawSlug)
    .trim()
    .replace(/^https?:\/\/(?:[^@/\s]+@)?/i, "")
    .replace(/\.git\/?$/i, "")
    .replace(/\/+$/, "");
  const parts = trimmed.split("/");
  let host = null;
  let ownerRepo = null;
  if (parts.length === 2) {
    ownerRepo = assertSafeOwnerRepoSegments(trimmed);
  } else if (parts.length === 3 && /^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(parts[0])) {
    host = parts[0].toLowerCase();
    ownerRepo = assertSafeOwnerRepoSegments(`${parts[1]}/${parts[2]}`);
  }
  if (!ownerRepo) {
    throw new Error('Invalid --repo slug: expected "owner/repo" (or "host/owner/repo" with --allow-custom-origin).');
  }
  if (!allowCustomHost && host && host !== "github.com") {
    throw new Error('Invalid --repo slug: expected "owner/repo" on github.com (or pass --allow-custom-origin).');
  }
  return { host, slug: ownerRepo };
}

export function normalizeRepoSlugInput(rawSlug) {
  const parsed = parseRepoTargetInput(rawSlug, { allowCustomHost: false });
  return parsed ? parsed.slug : null;
}

export function parseOriginHostAndSlugFromUrl(rawUrl) {
  const url = String(rawUrl ?? "").trim();
  if (!url) return null;
  const m =
    /^(?:https:\/\/(?:[^@/\s]+@)?([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::\d+)?\/|ssh:\/\/(?:[^@/\s]+@)?([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::\d+)?\/|git@([A-Za-z0-9.-]+\.[A-Za-z]{2,}):)([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+?)(?:\.git)?\/?$/i.exec(
      url,
    );
  if (!m) return null;
  const host = (m[1] || m[2] || m[3]).toLowerCase();
  const slug = assertSafeOwnerRepoSegments(m[4]);
  return slug ? { host, slug } : null;
}

export function parseOriginRepoSlugFromUrl(rawUrl) {
  const info = parseOriginHostAndSlugFromUrl(rawUrl);
  return info && info.host === "github.com" ? info.slug : null;
}

function parseOriginInfo(repoRoot) {
  const r = git(repoRoot, ["remote", "get-url", "origin"], { allowFail: true });
  if (r.status !== 0) return null;
  return parseOriginHostAndSlugFromUrl(r.stdout);
}

function resolveExactRemoteBranchOid(repoRoot, branchName) {
  const fullRef = `refs/heads/${branchName}`;
  const out = git(repoRoot, ["ls-remote", "--heads", "origin", fullRef]).stdout;
  for (const line of out.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const [oid, ref] = line.trim().split(/\s+/);
    if (ref === fullRef && /^[0-9a-f]{40,64}$/i.test(oid)) {
      return oid;
    }
  }
  return null;
}

function invokeGhCli(cwd, ghArgs, ghOverride, ghHost = "github.com") {
  const bin = ghOverride || process.env.PROOF_COMMIT_GH_BIN || "gh";
  let exe = bin;
  let fullArgs = ghArgs;
  if (bin.endsWith(".mjs") || bin.endsWith(".js") || bin.endsWith(".cjs")) {
    exe = process.execPath;
    fullArgs = [bin, ...ghArgs];
  }
  const res = spawnSync(exe, fullArgs, {
    cwd,
    env: cleanGitEnv({ GH_HOST: ghHost }),
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    windowsHide: true,
  });
  if (res.error) throw res.error;
  return res;
}

function loadLocalPrReviewers(commonDir, repoSlug, baseBranch, headOid) {
  if (!/^[0-9a-f]{40,64}$/.test(headOid)) return [];
  const prStateFile = path.join(commonDir, "proof-commit", "pr", `${headOid}.json`);
  if (!fs.existsSync(prStateFile)) return [];
  let data;
  try {
    data = JSON.parse(fs.readFileSync(prStateFile, "utf8"));
  } catch {
    throw new Error(
      `Corrupted local PR reviewer state at ${prStateFile}; pass --clear-reviewers to reset.`,
    );
  }
  if (data.head_oid !== headOid || !data.entries || typeof data.entries !== "object") {
    throw new Error(`Corrupted local PR reviewer state at ${prStateFile}.`);
  }
  const slotKey = `${repoSlug.toLowerCase()}#${baseBranch}`;
  return normalizeReviewers(data.entries[slotKey] || []);
}

function saveLocalPrReviewers(commonDir, repoSlug, baseBranch, headOid, reviewers) {
  if (!/^[0-9a-f]{40,64}$/.test(headOid)) return;
  const prDir = path.join(commonDir, "proof-commit", "pr");
  const prStateFile = path.join(prDir, `${headOid}.json`);
  let entries = {};
  if (fs.existsSync(prStateFile)) {
    try {
      const existing = JSON.parse(fs.readFileSync(prStateFile, "utf8"));
      if (existing && existing.head_oid === headOid && existing.entries && typeof existing.entries === "object") {
        entries = { ...existing.entries };
      }
    } catch {
      if (reviewers.length > 0) {
        throw new Error(`Corrupted local PR reviewer state at ${prStateFile}; pass --clear-reviewers to reset.`);
      }
    }
  }
  const slotKey = `${repoSlug.toLowerCase()}#${baseBranch}`;
  if (reviewers.length === 0) {
    delete entries[slotKey];
  } else {
    entries[slotKey] = reviewers;
  }
  if (Object.keys(entries).length === 0) {
    fs.rmSync(prStateFile, { force: true });
    return;
  }
  fs.mkdirSync(prDir, { recursive: true });
  writeFileAtomic(
    prStateFile,
    Buffer.from(`${JSON.stringify({ entries, head_oid: headOid }, null, 2)}\n`, "utf8"),
  );
}

function reverifyStoredBundle(repoRoot, oid, bundleDir, manifest, expectedMappingEvidenceId = null) {
  if (manifest.commit_oid !== oid) {
    throw new Error(`Bundle commit_oid (${manifest.commit_oid}) != ${oid}`);
  }
  if (manifest.schema_version !== 1 && manifest.schema_version !== 2) {
    throw new Error(
      `Unsupported bundle schema_version "${manifest.schema_version}" on ${oid.slice(0, 12)}; upgrade proof_commit.mjs.`,
    );
  }
  assertValidEvidenceIdFormat(manifest.evidence_id, "manifest.evidence_id");
  if (expectedMappingEvidenceId) {
    assertValidEvidenceIdFormat(expectedMappingEvidenceId, "mapping.evidence_id");
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
  if (manifest.schema_version >= 2 || manifest.commit_message !== undefined) {
    if (
      !manifest.commit_message ||
      typeof manifest.commit_message !== "string" ||
      bodyBlock !== manifest.commit_message
    ) {
      throw new Error(`Commit ${oid.slice(0, 12)} message bytes missing or drifted from stored manifest.`);
    }
  }
  if (manifest.schema_version >= 2) {
    const whyBlockMatch = /\nWhy:\n([\s\S]*?)\n\n(?:Granularity|Evidence):\n/.exec(bodyBlock);
    if (typeof manifest.why !== "string" || !whyBlockMatch || whyBlockMatch[1] !== manifest.why) {
      throw new Error(`Stored manifest.why on ${oid.slice(0, 12)} drifted from verified commit message.`);
    }
    assertSingleLineStructuralField(manifest.case_name || "", "manifest.case_name", 240);
  } else if (typeof manifest.why === "string" && manifest.why && !bodyBlock.includes(manifest.why)) {
    throw new Error(`Stored manifest.why on ${oid.slice(0, 12)} drifted from verified commit message.`);
  }

  let normalizedManifestReviewers = [];
  if (manifest.reviewers !== undefined) {
    if (!Array.isArray(manifest.reviewers) || manifest.reviewers.length === 0) {
      throw new Error(
        `Stored manifest.reviewers on ${oid.slice(0, 12)} must be a non-empty array when present.`,
      );
    }
    normalizedManifestReviewers = normalizeReviewers(manifest.reviewers);
    if (canonicalJson(manifest.reviewers) !== canonicalJson(normalizedManifestReviewers)) {
      throw new Error(
        `Stored manifest.reviewers on ${oid.slice(0, 12)} is non-canonical (contains duplicates, extra keys, or unsorted entries).`,
      );
    }
  }

  const noUiImpactReason =
    manifest.no_ui_impact_reason !== undefined && manifest.no_ui_impact_reason !== null
      ? assertSingleLineStructuralField(manifest.no_ui_impact_reason, "manifest.no_ui_impact_reason", 200)
      : null;

  const hasV2UiNotes = Boolean(manifest.ui && typeof manifest.ui.notes === "string" && manifest.ui.notes.length > 0);
  const expectedSchemaVersion =
    normalizedManifestReviewers.length > 0 || Boolean(noUiImpactReason) || hasV2UiNotes ? 2 : 1;
  if (manifest.schema_version !== expectedSchemaVersion) {
    throw new Error(
      `Stored schema_version (${manifest.schema_version}) on ${oid.slice(0, 12)} disagrees with payload fields (expected ${expectedSchemaVersion}).`,
    );
  }

  const canonicalPayload = {
    after: manifest.after,
    before: manifest.before,
    case_name: manifest.case_name,
    ...(noUiImpactReason ? { no_ui_impact_reason: noUiImpactReason } : {}),
    overlay: manifest.overlay || [],
    parent_oid: manifest.parent_oid,
    ...(normalizedManifestReviewers.length > 0 ? { reviewers: normalizedManifestReviewers } : {}),
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
  if (expectedMappingEvidenceId && recomputedId !== expectedMappingEvidenceId) {
    throw new Error(
      `Commit mapping Evidence-ID mismatch on ${oid.slice(0, 12)}: mapping=${expectedMappingEvidenceId}, recomputed=${recomputedId}.`,
    );
  }

  const evMatches = [...bodyBlock.matchAll(/^Evidence-ID:\s*(\S+)\s*$/gm)];
  if (evMatches.length !== 1 || evMatches[0][1] !== recomputedId) {
    throw new Error(
      `Git commit ${oid.slice(0, 12)} Evidence-ID trailer missing, duplicated, or mismatched with recomputed digest.`,
    );
  }
  const gitRevLines = [...bodyBlock.matchAll(/^AI-Reviewed-By:\s*(.+?)\s*$/gm)].map(
    (m) => `AI-Reviewed-By: ${m[1]}`,
  );
  const expectedRevLines = normalizedManifestReviewers.map(formatReviewerTrailer);
  if (
    gitRevLines.length !== expectedRevLines.length ||
    gitRevLines.some((line, idx) => line !== expectedRevLines[idx])
  ) {
    throw new Error(
      `Git commit ${oid.slice(0, 12)} AI-Reviewed-By trailers disagree with verified manifest reviewers.`,
    );
  }
  if (noUiImpactReason) {
    const expectedNoUiLine = `UI-Impact: none (${noUiImpactReason})`;
    if (!bodyBlock.split(/\r?\n/).includes(expectedNoUiLine)) {
      throw new Error(`Git commit ${oid.slice(0, 12)} missing expected UI-Impact trailer.`);
    }
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

  const hasCanonicalUi = manifest.ui !== null && manifest.ui !== undefined;
  const hasUiDetails = manifest.ui_details !== null && manifest.ui_details !== undefined;
  if (hasCanonicalUi !== hasUiDetails) {
    throw new Error(
      `Stored UI metadata mismatch on ${oid.slice(0, 12)}: canonical ui presence (${hasCanonicalUi}) != ui_details presence (${hasUiDetails}).`,
    );
  }
  if (hasCanonicalUi) {
    const cu = manifest.ui;
    const ud = manifest.ui_details;
    if (
      ud.route !== cu.route ||
      ud.viewport !== cu.viewport ||
      ud.theme !== cu.theme ||
      (ud.new_surface_reason ?? null) !== (cu.new_surface_reason ?? null) ||
      (ud.after?.sha256 ?? null) !== (cu.after_sha256 ?? null) ||
      (ud.before?.sha256 ?? null) !== (cu.before_sha256 ?? null) ||
      (manifest.schema_version >= 2 && (ud.notes || "") !== (cu.notes || ""))
    ) {
      throw new Error(
        `Stored ui_details on ${oid.slice(0, 12)} drifted from canonical hashed ui payload.`,
      );
    }
    if (ud.notes) {
      if (manifest.schema_version >= 2) {
        assertSingleLineStructuralField(String(ud.notes), "stored_ui_notes", 240);
      }
      scanPublicTextPrivacy(String(ud.notes), "stored_ui_notes");
    }
    for (const kind of ["before", "after"]) {
      const meta = ud[kind];
      if (!meta) continue;
      if (!ALLOWED_UI_EXTS.has(meta.ext)) {
        throw new Error(`Invalid stored UI screenshot extension "${meta.ext}" on ${oid.slice(0, 12)}.`);
      }
      const imgPath = path.join(bundleDir, "ui", `${kind}.${meta.ext}`);
      if (!fs.existsSync(imgPath)) {
        throw new Error(`Missing stored UI screenshot ui/${kind}.${meta.ext} on ${oid.slice(0, 12)}.`);
      }
      const bytes = fs.readFileSync(imgPath);
      parseImageDimensions(bytes);
      if (sha256Hex(bytes) !== meta.sha256) {
        throw new Error(`Stored UI ${kind} screenshot digest mismatch on ${oid.slice(0, 12)}.`);
      }
    }
  }
}

function normalizeHostedUrlsForComparison(reportInner, expectedAltTags = []) {
  let out = reportInner.replace(/\r\n/g, "\n");
  for (const altTag of expectedAltTags) {
    const escaped = altTag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const slotRe = new RegExp(`!\\[(${escaped})\\]\\((?:https:\\/\\/[^)\\s]+|\\.\\/[^)\\s]+)\\)`, "g");
    out = out.replace(slotRe, "![$1](<HOSTED_ASSET>)");
  }
  return out.trim();
}

async function cmdPublishPr(argv) {
  const { flags, multi } = parseFlags(argv, "publish-pr");
  const prExtraReviewers = normalizeReviewers(multi["reviewed-by"]);
  const validatedExplicitTitle = flags.title
    ? assertSingleLineStructuralField(flags.title, "pr_title", 240)
    : null;
  if (validatedExplicitTitle) {
    scanPublicTextPrivacy(validatedExplicitTitle, "pr_title");
  }
  const validatedSummary =
    flags.summary !== undefined ? assertPrSummaryText(flags.summary) : null;
  if (validatedSummary) {
    scanPublicTextPrivacy(validatedSummary, "pr_summary");
  }
  const { repoRoot, commonDir } = resolveRepoContext();
  const ghOverride = flags["gh-bin"] || null;

  const headOid = git(repoRoot, ["rev-parse", "HEAD"]).stdout.trim();
  const headBranch = git(repoRoot, ["rev-parse", "--abbrev-ref", "HEAD"]).stdout.trim();
  if (!headBranch || headBranch === "HEAD") {
    throw new Error("`publish-pr` must be run from a named feature/fix branch, not detached HEAD.");
  }

  const baseBranch = (flags.base || "main").replace(/^origin\//, "");
  if (
    !baseBranch ||
    baseBranch.startsWith("-") ||
    git(repoRoot, ["check-ref-format", "--branch", baseBranch], { allowFail: true }).status !== 0
  ) {
    throw new Error(`Invalid --base branch name "${baseBranch}".`);
  }
  if (headBranch === baseBranch) {
    throw new Error(`Refusing to run \`publish-pr\` directly on base branch "${baseBranch}".`);
  }

  if (flags.closes !== undefined) {
    assertPositiveIntFlag(String(flags.closes).replace(/^#/, ""), "closes");
  }
  const originInfo = parseOriginInfo(repoRoot);
  const originSlug = originInfo && originInfo.host === "github.com" ? originInfo.slug : null;
  const repoTarget = flags.repo
    ? parseRepoTargetInput(flags.repo, { allowCustomHost: Boolean(flags["allow-custom-origin"]) })
    : null;
  const repoSlug = repoTarget ? repoTarget.slug : flags["allow-custom-origin"] ? originInfo?.slug || null : originSlug;
  if (!repoSlug) {
    throw new Error("Could not determine GitHub repository slug (`owner/repo`). Pass `--repo owner/repo` or configure `origin`.");
  }
  if (
    flags["allow-custom-origin"] &&
    originInfo?.host &&
    repoTarget?.host &&
    originInfo.host.toLowerCase() !== repoTarget.host.toLowerCase()
  ) {
    throw new Error(
      `Target --repo host "${repoTarget.host}" differs from git remote origin host "${originInfo.host}".`,
    );
  }
  if (flags["allow-custom-origin"] && !originInfo?.host && !repoTarget?.host) {
    throw new Error(
      'When --allow-custom-origin is used with a local or non-URL origin, pass an explicit host-qualified --repo "<host>/<owner>/<repo>".',
    );
  }
  const effectiveHost = flags["allow-custom-origin"]
    ? (repoTarget?.host || originInfo?.host).toLowerCase()
    : "github.com";

  const hasOrigin = git(repoRoot, ["remote", "get-url", "origin"], { allowFail: true }).status === 0;
  let baseRangeRef = baseBranch;
  let remoteBaseOid = null;
  if (!flags["skip-push-check"]) {
    if (!hasOrigin) {
      throw new Error(
        "No git remote \"origin\" configured; configure `origin` and push your branch before running `publish-pr`.",
      );
    }
    if (!flags["allow-custom-origin"]) {
      if (!originSlug) {
        throw new Error(
          "Git remote \"origin\" is not a recognized github.com repository URL; configure github.com origin or pass `--allow-custom-origin --repo [host/]owner/repo` for enterprise remotes.",
        );
      }
      if (originSlug.toLowerCase() !== repoSlug.toLowerCase()) {
        throw new Error(
          `Target --repo "${repoSlug}" differs from git remote origin "${originSlug}". Configure matching origin or pass --allow-custom-origin if intentional.`,
        );
      }
    } else if (originInfo?.slug && originInfo.slug.toLowerCase() !== repoSlug.toLowerCase()) {
      throw new Error(
        `Target --repo "${repoSlug}" differs from git remote origin "${originInfo.slug}".`,
      );
    }
    const remoteHeadOid = resolveExactRemoteBranchOid(repoRoot, headBranch);
    if (remoteHeadOid !== headOid) {
      throw new Error(
        `Local HEAD (${headOid.slice(0, 12)}) does not match remote origin/refs/heads/${headBranch} (${remoteHeadOid ? remoteHeadOid.slice(0, 12) : "unpushed"}). Push your branch before running \`publish-pr\`.`,
      );
    }
    remoteBaseOid = resolveExactRemoteBranchOid(repoRoot, baseBranch);
    if (!remoteBaseOid) {
      throw new Error(`Base branch "refs/heads/${baseBranch}" was not found on remote origin.`);
    }
    if (git(repoRoot, ["cat-file", "-e", `${remoteBaseOid}^{commit}`], { allowFail: true }).status !== 0) {
      git(repoRoot, ["fetch", "--no-tags", "--quiet", "origin", `refs/heads/${baseBranch}`]);
    }
    baseRangeRef = remoteBaseOid;
  } else {
    const originBase = git(repoRoot, ["rev-parse", "--verify", `origin/${baseBranch}`], {
      allowFail: true,
    });
    if (originBase.status === 0) baseRangeRef = `origin/${baseBranch}`;
  }

  const commitsOut = git(repoRoot, ["rev-list", "--reverse", `${baseRangeRef}..${headOid}`]).stdout.trim();
  const commitOids = commitsOut ? commitsOut.split(/\r?\n/).filter(Boolean) : [];
  if (commitOids.length === 0) {
    throw new Error(`No commits found in range ${baseRangeRef.slice(0, 12)}..${headOid.slice(0, 12)}.`);
  }

  const verifiedBundles = [];
  const missingCommits = [];

  for (const oid of commitOids) {
    const mapFile = path.join(commonDir, "proof-commit", "commits", `${oid}.json`);
    if (!fs.existsSync(mapFile)) {
      missingCommits.push(`${oid.slice(0, 12)} (no local proof-commit bundle)`);
      continue;
    }
    let mapping;
    try {
      mapping = JSON.parse(fs.readFileSync(mapFile, "utf8"));
      assertValidEvidenceIdFormat(mapping.evidence_id, "mapping.evidence_id");
    } catch (err) {
      missingCommits.push(`${oid.slice(0, 12)} (${err.message})`);
      continue;
    }
    const digestHex = mapping.evidence_id.replace(/^sha256:/, "");
    const bundlesRoot = path.resolve(commonDir, "proof-commit", "bundles");
    const bundleDir = path.resolve(bundlesRoot, digestHex);
    if (path.dirname(bundleDir) !== bundlesRoot) {
      missingCommits.push(`${oid.slice(0, 12)} (bundle path containment failed)`);
      continue;
    }
    const manifestPath = path.join(bundleDir, "manifest.json");
    if (!fs.existsSync(manifestPath)) {
      missingCommits.push(`${oid.slice(0, 12)} (bundle manifest missing for ${mapping.evidence_id})`);
      continue;
    }
    let manifest;
    try {
      manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
      reverifyStoredBundle(repoRoot, oid, bundleDir, manifest, mapping.evidence_id);
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

  const qualifiedRepoTarget = `${effectiveHost}/${repoSlug}`;
  const repoArgs = ["--repo", qualifiedRepoTarget];
  const prJsonFields =
    "number,url,body,headRefOid,baseRefName,baseRefOid,headRefName,state,isCrossRepository,headRepositoryOwner,headRepository";

  const isSameRepoPr = (pr) => {
    if (!pr || pr.isCrossRepository !== false) return false;
    const ownerLogin = pr.headRepositoryOwner?.login;
    const repoName = pr.headRepository?.name;
    if (typeof ownerLogin !== "string" || typeof repoName !== "string") return false;
    if (`${ownerLogin}/${repoName}`.toLowerCase() !== repoSlug.toLowerCase()) return false;
    try {
      const u = new URL(String(pr.url || ""));
      if (u.protocol !== "https:" || u.hostname.toLowerCase() !== effectiveHost) return false;
    } catch {
      return false;
    }
    return true;
  };

  const isValidPrBaseRange = (prBaseOid) => {
    if (!/^[0-9a-f]{40,64}$/i.test(String(prBaseOid || ""))) return false;
    const hasLocalObj =
      git(repoRoot, ["cat-file", "-e", `${prBaseOid}^{commit}`], { allowFail: true }).status === 0;
    const matchesVerifiedRange = () => {
      const prRangeOut = git(repoRoot, ["rev-list", "--reverse", `${prBaseOid}..${headOid}`], {
        allowFail: true,
      });
      if (prRangeOut.status !== 0) return false;
      const prRangeOids = prRangeOut.stdout.trim().split(/\r?\n/).filter(Boolean);
      return (
        prRangeOids.length === commitOids.length &&
        prRangeOids.every((oid, idx) => oid === commitOids[idx])
      );
    };
    if (flags["skip-push-check"] || !remoteBaseOid) {
      return hasLocalObj ? matchesVerifiedRange() : true;
    }
    if (prBaseOid === remoteBaseOid) return true;
    if (!hasLocalObj) return false;
    const isAncestor =
      git(repoRoot, ["merge-base", "--is-ancestor", prBaseOid, remoteBaseOid], {
        allowFail: true,
      }).status === 0;
    if (!isAncestor) return false;
    return matchesVerifiedRange();
  };

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
        prJsonFields,
      ],
      ghOverride,
      effectiveHost,
    );
    if (r.status !== 0) {
      throw new Error(
        `gh pr list failed (exit ${r.status}): ${(r.stderr || r.stdout || "").trim()}`,
      );
    }
    let arr;
    try {
      arr = JSON.parse(r.stdout);
    } catch {
      throw new Error("gh pr list returned invalid JSON.");
    }
    if (!Array.isArray(arr)) {
      throw new Error("gh pr list returned non-array JSON response.");
    }
    return (
      arr.find((p) => isSameRepoPr(p) && p.baseRefName === baseBranch && p.headRefName === headBranch) ||
      null
    );
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
        prJsonFields,
      ],
      ghOverride,
      effectiveHost,
    );
    if (r.status !== 0) {
      throw new Error(
        `gh pr view #${num} failed (exit ${r.status}): ${(r.stderr || r.stdout || "").trim()}`,
      );
    }
    let parsed;
    try {
      parsed = JSON.parse(r.stdout);
    } catch {
      throw new Error(`gh pr view #${num} returned invalid JSON.`);
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error(`gh pr view #${num} returned unexpected JSON payload.`);
    }
    return parsed;
  };

  const assertPrMatchesTarget = (pr, label, { requireOpen = true } = {}) => {
    if (requireOpen && String(pr.state || "").toUpperCase() !== "OPEN") {
      throw new Error(
        `${label} PR #${pr.number} state is "${pr.state || "<missing>"}", expected OPEN.`,
      );
    }
    if (!isSameRepoPr(pr)) {
      throw new Error(
        `${label} PR #${pr.number} does not originate from same repository "${repoSlug}" (cross-repository or missing headRepository metadata).`,
      );
    }
    if (pr.baseRefName !== baseBranch || pr.headRefName !== headBranch) {
      throw new Error(
        `${label} PR #${pr.number} branch pair "${pr.headRefName || "<missing>"} -> ${pr.baseRefName || "<missing>"}" != expected "${headBranch} -> ${baseBranch}".`,
      );
    }
    if (pr.headRefOid !== headOid) {
      throw new Error(
        `${label} PR #${pr.number} remote headRefOid (${String(pr.headRefOid || "<missing>").slice(0, 12)}) != local HEAD (${headOid.slice(0, 12)}). Push branch before updating PR evidence.`,
      );
    }
    if (!/^[0-9a-f]{40,64}$/i.test(String(pr.baseRefOid || ""))) {
      throw new Error(`${label} PR #${pr.number} is missing a valid baseRefOid.`);
    }
    if (!isValidPrBaseRange(pr.baseRefOid)) {
      throw new Error(
        `${label} PR #${pr.number} baseRefOid (${String(pr.baseRefOid).slice(0, 12)}) diverges from verified origin/${baseBranch} (${remoteBaseOid?.slice(0, 12)}) commit range; fetch origin/${baseBranch}, rebase/push, and re-run \`publish-pr\`.`,
      );
    }
  };

  let existingPr = findOpenPrByPair();
  if (existingPr) {
    assertPrMatchesTarget(existingPr, "Open");
  }

  const trustedReceipts = loadTrustedUploadReceipts(commonDir, effectiveHost);
  const existingBodyUrls = parseExistingHostedUiUrls(
    existingPr ? existingPr.body : "",
    effectiveHost,
  );
  const existingHosted = new Map();
  for (const [altTag, bodyUrl] of existingBodyUrls.entries()) {
    if (trustedReceipts.get(receiptSlotKey(effectiveHost, repoSlug, altTag)) === bodyUrl) {
      existingHosted.set(altTag, bodyUrl);
    }
  }
  const qualifiedPrKeySlug = `${effectiveHost}/${repoSlug}`;
  const priorLocalPrReviewers = flags["clear-reviewers"]
    ? []
    : loadLocalPrReviewers(commonDir, qualifiedPrKeySlug, baseBranch, headOid);
  const branchReviewers = normalizeReviewers([...priorLocalPrReviewers, ...prExtraReviewers]);
  saveLocalPrReviewers(commonDir, qualifiedPrKeySlug, baseBranch, headOid, branchReviewers);

  const stageDir = fs.mkdtempSync(path.join(os.tmpdir(), "evcommit-pr-"));

  try {
    const pendingAttachments = [];
    const expectedUiAltTags = [];
    const expectedUiDigests = new Map();
    const sectionLines = [
      "## Verification Evidence (`evidence-commit`)",
      "",
      `- **Base branch:** \`${baseBranch}\` | **Head OID:** \`${headOid}\``,
      `- **Verified commits:** ${verifiedBundles.length} / ${commitOids.length}`,
    ];
    if (flags["skip-push-check"]) {
      sectionLines.push("- **Push/base check:** `SKIPPED (--skip-push-check)`");
    }
    if (flags["allow-private-unverified-assets"]) {
      sectionLines.push(
        "- **Asset byte check:** `SKIPPED (--allow-private-unverified-assets)`",
      );
    } else if (process.env.PROOF_COMMIT_MOCK_ASSET_MAP) {
      sectionLines.push("- **Asset byte check:** `MOCKED (PROOF_COMMIT_MOCK_ASSET_MAP)`");
    }
    if (branchReviewers.length > 0) {
      sectionLines.push(
        `- **Branch AI-Reviewed-By:** ${branchReviewers.map(formatReviewerMarkdown).join(", ")} _(self-attested)_`,
      );
    }
    if (missingCommits.length > 0) {
      sectionLines.push(
        `- **Unverified gaps:** ${missingCommits.map((g) => safeInlineCode(collapseInlineWhitespace(g))).join("; ")}`,
      );
    }

    for (const item of verifiedBundles) {
      const { bundleDir, manifest, oid, subject } = item;
      const shortSha = oid.slice(0, 8);
      const commitReviewers = normalizeReviewers(manifest.reviewers || []);
      const oneLineSubject = collapseInlineWhitespace(subject);
      const oneLineWhy = collapseInlineWhitespace(manifest.why || "");
      const oneLineCase = collapseInlineWhitespace(manifest.case_name || "");
      sectionLines.push(
        "",
        `### \`${shortSha}\` — ${safeInlineCode(oneLineSubject)}`,
        `- **Tree:** \`${manifest.tree_oid.slice(0, 12)}\` | **Mode:** \`${manifest.verification_mode}\` | **Evidence-ID:** \`${manifest.evidence_id}\``,
        `- **Case:** ${safeInlineCode(oneLineCase)}`,
        `- **Why:** ${safeInlineCode(oneLineWhy)}`,
      );
      if (commitReviewers.length > 0) {
        sectionLines.push(
          `- **AI-Reviewed-By:** ${commitReviewers.map(formatReviewerMarkdown).join(", ")}`,
        );
      }

      if (manifest.before) {
        const bText = manifest.before.quotes.map((q) => q.text).join("\n");
        const fence = safeFenceForText(bText);
        sectionLines.push(
          "",
          `**Before** (${safeInlineCode(collapseInlineWhitespace(manifest.before.argv_display))}, exit \`${manifest.before.exit_code}\`):`,
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
          `**After** (${safeInlineCode(collapseInlineWhitespace(manifest.after.argv_display))}, exit \`${manifest.after.exit_code}\`):`,
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
          expectedUiDigests.set(altTag, metaObj.sha256);
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
          `**Visual Verification** (route ${safeInlineCode(collapseInlineWhitespace(ui.route))}, viewport ${safeInlineCode(collapseInlineWhitespace(ui.viewport))}, theme ${safeInlineCode(collapseInlineWhitespace(ui.theme))}):`,
          "",
          "| Before | After |",
          "| :---: | :---: |",
          `| ${beforeCell} | ${afterCell} |`,
        );
        if (manifest.ui?.notes) {
          const singleLineNote = collapseInlineWhitespace(manifest.ui.notes);
          sectionLines.push("", `- **Inspection notes:** ${safeInlineCode(singleLineNote)}`);
        }
      }
    }

    const expectedReportInner = sectionLines.join("\n");
    const prTitle =
      validatedExplicitTitle ||
      collapseInlineWhitespace(verifiedBundles[verifiedBundles.length - 1]?.subject || headBranch);
    scanPublicTextPrivacy(prTitle, "pr_title");

    const defaultGeneratedSummary = verifiedBundles
      .map(
        (b) =>
          `- ${safeInlineCode(collapseInlineWhitespace(b.subject))}: ${safeInlineCode(collapseInlineWhitespace(b.manifest.why || ""))}`,
      )
      .join("\n");
    const createSummaryText =
      validatedSummary !== null
        ? `${safeFenceForText(validatedSummary)}text\n${validatedSummary}\n${safeFenceForText(validatedSummary)}`
        : defaultGeneratedSummary;

    const applyTrustedUrlsToInner = (bodyUrlsMap) => {
      let inner = expectedReportInner;
      for (const [altTag, url] of bodyUrlsMap.entries()) {
        if (trustedReceipts.get(receiptSlotKey(effectiveHost, repoSlug, altTag)) === url) {
          inner = inner.replaceAll(`![${altTag}](./${altTag}.png)`, `![${altTag}](${url})`);
          inner = inner.replaceAll(`![${altTag}](./${altTag}.jpg)`, `![${altTag}](${url})`);
          inner = inner.replaceAll(`![${altTag}](./${altTag}.webp)`, `![${altTag}](${url})`);
        }
      }
      return inner;
    };

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
      const bodyFile = path.join(stageDir, "pr_body.md");
      const attachArgs = batch.flatMap((item) => ["--attach", `./${item.fileName}`]);
      const wasEdit = Boolean(targetPrNumber);
      let preInvokeUrls;
      let canRecordReceipts = false;

      if (!wasEdit) {
        preInvokeUrls = parseExistingHostedUiUrls(latestBody || "", effectiveHost);
        const batchInner = applyTrustedUrlsToInner(preInvokeUrls);
        const bodyText = mergeReportBlockIntoBody(
          latestBody,
          createSummaryText,
          flags.closes,
          batchInner,
        );
        scanPublicTextPrivacy(bodyText, "rendered_pr_body");
        fs.writeFileSync(bodyFile, bodyText, "utf8");

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
          effectiveHost,
        );
        const discovered = findOpenPrByPair();
        if (discovered) {
          assertPrMatchesTarget(discovered, "Created");
          targetPrNumber = discovered.number;
          latestBody = discovered.body;
          const discBlock = extractSingleReportBlock(latestBody || "");
          const reportMatchesOurs =
            Boolean(discBlock) &&
            normalizeHostedUrlsForComparison(discBlock.inner, expectedUiAltTags) ===
              normalizeHostedUrlsForComparison(expectedReportInner, expectedUiAltTags);
          const stdoutMentionsCreatedUrl =
            typeof discovered.url === "string" &&
            discovered.url.length > 0 &&
            String(lastGhRes.stdout || "").includes(discovered.url);
          canRecordReceipts =
            reportMatchesOurs && (lastGhRes.status === 0 || stdoutMentionsCreatedUrl);
        }
      } else {
        const freshBeforeEdit = viewPrByNumber(targetPrNumber);
        assertPrMatchesTarget(freshBeforeEdit, "Pre-edit");
        latestBody = freshBeforeEdit.body;
        preInvokeUrls = parseExistingHostedUiUrls(latestBody || "", effectiveHost);
        const batchInner = applyTrustedUrlsToInner(preInvokeUrls);
        const refreshedBody = mergeReportBlockIntoBody(
          latestBody,
          createSummaryText,
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
          effectiveHost,
        );
        if (lastGhRes.status !== 0) {
          throw new Error(
            `gh pr edit #${targetPrNumber} failed (exit ${lastGhRes.status}): ${(lastGhRes.stderr || lastGhRes.stdout || "").trim()}`,
          );
        }
        const afterBatchView = viewPrByNumber(targetPrNumber);
        assertPrMatchesTarget(afterBatchView, "Post-edit");
        latestBody = afterBatchView.body;
        canRecordReceipts = true;
      }

      if (canRecordReceipts) {
        const uploadedUrls = parseExistingHostedUiUrls(latestBody || "", effectiveHost);
        let recordedAny = false;
        for (const item of batch) {
          const afterUrl = uploadedUrls.get(item.altTag);
          const beforeUrl = preInvokeUrls.get(item.altTag);
          if (afterUrl && afterUrl !== beforeUrl) {
            await verifyHostedAssetBytes(afterUrl, expectedUiDigests.get(item.altTag), {
              allowPrivateUnverifiedAssets: Boolean(flags["allow-private-unverified-assets"]),
              effectiveHost,
            });
            trustedReceipts.set(receiptSlotKey(effectiveHost, repoSlug, item.altTag), afterUrl);
            recordedAny = true;
          }
        }
        if (recordedAny) {
          saveTrustedUploadReceipts(commonDir, trustedReceipts);
        }
      }
    }

    if (!targetPrNumber) {
      throw new Error(
        `gh PR creation failed and no open PR was found for ${headBranch} -> ${baseBranch}: ${(lastGhRes?.stderr || lastGhRes?.stdout || "").trim()}`,
      );
    }

    const remotePr = viewPrByNumber(targetPrNumber);
    assertPrMatchesTarget(remotePr, "Remote", { requireOpen: true });

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

    const remoteHosted = parseExistingHostedUiUrls(remotePr.body || "", effectiveHost);
    for (const altTag of expectedUiAltTags) {
      const remoteUrl = remoteHosted.get(altTag);
      if (!remoteUrl) {
        throw new Error(
          `PARTIAL_PUBLISH_INCOMPLETE: PR ${remotePr.url} is missing hosted asset URL for ${altTag}.`,
        );
      }
      if (trustedReceipts.get(receiptSlotKey(effectiveHost, repoSlug, altTag)) !== remoteUrl) {
        throw new Error(
          `Remote PR ${remotePr.url} hosted asset URL for ${altTag} does not match local upload receipt.`,
        );
      }
      await verifyHostedAssetBytes(remoteUrl, expectedUiDigests.get(altTag), {
        allowPrivateUnverifiedAssets: Boolean(flags["allow-private-unverified-assets"]),
        effectiveHost,
      });
    }

    if (
      normalizeHostedUrlsForComparison(remoteBlock.inner, expectedUiAltTags) !==
      normalizeHostedUrlsForComparison(expectedReportInner, expectedUiAltTags)
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
      process.exitCode = 4;
      return;
    }

    process.stdout.write(
      `PUBLISH_PR_VERIFIED number=${remotePr.number} url=${remotePr.url} head=${remotePr.headRefOid} ui_attachments=${expectedUiAltTags.length}\n`,
    );
  } finally {
    fs.rmSync(stageDir, { recursive: true, force: true });
  }
}

async function cmdStage(argv) {
  const { flags, multi } = parseFlags(argv, "stage");
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
    if (parentOid) {
      const parentDirEntry = git(repoRoot, ["ls-tree", "-d", parentOid, "--", rel]).stdout.trim();
      if (parentDirEntry) {
        throw new Error(
          `Directory staging ("${rel}") is forbidden because "${rel}" was a directory in HEAD and staging it can sweep child deletions; list explicit file paths.`,
        );
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

  git(repoRoot, ["--literal-pathspecs", "add", "--", ...requestedNorm]);
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
  const { flags } = parseFlags(argv, "init");
  const mode = flags.mode || "snapshot";
  if (!ALLOWED_MODES.has(mode)) throw new Error(`Invalid --mode "${mode}".`);
  const validatedCase = flags.case ? assertSingleLineStructuralField(flags.case, "case", 240) : "";

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
    case_name: validatedCase,
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
  const { flags, multi, cmdAfterDashDash } = parseFlags(argv, "record");
  const phase = flags.phase;
  if (phase !== "before" && phase !== "after") {
    throw new Error("`record` requires `--phase before|after`.");
  }
  if (!cmdAfterDashDash || cmdAfterDashDash.length === 0) {
    throw new Error("`record` requires `-- <executable> [args...]`.");
  }
  const timeoutMs = flags["timeout-ms"]
    ? assertPositiveIntFlag(flags["timeout-ms"], "timeout-ms")
    : 300000;

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

    const result = await runCommandCapture(cmdAfterDashDash, execDir, timeoutMs);
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
  const { flags } = parseFlags(argv, "attach-ui");
  if (!flags.after || !flags.route || !flags.viewport) {
    throw new Error("`attach-ui` requires `--after <imgPath> --route <route> --viewport <WxH>`.");
  }
  if (!/^\d+x\d+$/i.test(flags.viewport)) {
    throw new Error(`Invalid --viewport "${flags.viewport}" (expected WxH, e.g., 1440x900).`);
  }
  const cleanRoute = assertSingleLineStructuralField(flags.route, "route", 240);
  const cleanTheme = assertSingleLineStructuralField(flags.theme || "default", "theme", 64);
  const cleanNewReason = flags["new-surface-reason"]
    ? assertSingleLineStructuralField(flags["new-surface-reason"], "new-surface-reason", 160)
    : null;
  const cleanNotes = flags.notes
    ? assertSingleLineStructuralField(flags.notes, "notes", 240)
    : "";
  if (cleanNotes) {
    scanPublicTextPrivacy(cleanNotes, "ui_notes");
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
    new_surface_reason: cleanNewReason,
    notes: cleanNotes,
    route: cleanRoute,
    theme: cleanTheme,
    viewport: flags.viewport.toLowerCase(),
  };
  saveRunState(statePath, state);
  process.stdout.write(
    `ATTACH_UI_OK route=${state.ui.route} viewport=${state.ui.viewport} after_sha256=${afterHash.slice(0, 12)}\n`,
  );
}

function buildValidatedCommitPlan(repoCtx, runBundle, flags, extraReviewers = []) {
  const { repoRoot, parentOid } = repoCtx;
  const { runDir, state } = runBundle;

  const type = flags.type;
  if (!ALLOWED_TYPES.has(type)) {
    throw new Error(`Invalid or missing --type "${type}". Allowed: ${[...ALLOWED_TYPES].join(", ")}`);
  }
  const title = assertSingleLineStructuralField(flags.title || "", "title", 72);
  if (!title) throw new Error("`--title` is required.");
  const rawWhy = flags["why-file"]
    ? fs.readFileSync(path.resolve(flags["why-file"]), "utf8").replace(/^\uFEFF/, "")
    : flags.why || "";
  const why = assertMultilineAuthorField(rawWhy, "why", 4000);
  if (why.length < 20) {
    throw new Error("`--why` must provide a substantive causal explanation (>= 20 chars).");
  }
  const cleanGranularity = flags.granularity
    ? assertMultilineAuthorField(flags.granularity, "granularity", 1200)
    : null;

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
  let noUiImpactReason = null;
  if (flags["no-ui-impact"] !== undefined) {
    if (state.ui || type === "ui") {
      throw new Error(
        '`--no-ui-impact` cannot be combined with `attach-ui` screenshots or `--type ui`.',
      );
    }
    noUiImpactReason = assertSingleLineStructuralField(flags["no-ui-impact"], "no-ui-impact", 200);
    if (noUiImpactReason.length < 8) {
      throw new Error("`--no-ui-impact` must state a concrete single-line reason (>= 8 chars).");
    }
  }
  if ((type === "ui" || (touchesUiPath && !noUiImpactReason)) && !state.ui) {
    throw new Error(
      `Staged UI changes require \`attach-ui\` visual proof (or explicit \`--no-ui-impact "<reason>"\` if non-visual).`,
    );
  }

  const maxLines = flags["max-lines"]
    ? assertPositiveIntFlag(flags["max-lines"], "max-lines", 50)
    : 3;
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

  const caseName = assertSingleLineStructuralField(
    flags.case || state.case_name || title,
    "case",
    240,
  );
  const scope = flags.scope ? assertSingleLineStructuralField(flags.scope, "scope", 64) : null;
  let cleanUiNotes = "";
  if (state.ui) {
    assertSingleLineStructuralField(state.ui.route, "ui.route", 240);
    assertSingleLineStructuralField(state.ui.theme, "ui.theme", 64);
    if (state.ui.new_surface_reason) {
      assertSingleLineStructuralField(state.ui.new_surface_reason, "ui.new_surface_reason", 160);
    }
    if (state.ui.notes) {
      cleanUiNotes = assertSingleLineStructuralField(state.ui.notes, "ui.notes", 240);
    }
  }
  const reviewers = normalizeReviewers(extraReviewers);
  const schemaVersion =
    reviewers.length > 0 || Boolean(noUiImpactReason) || Boolean(cleanUiNotes) ? 2 : 1;

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
    ...(noUiImpactReason ? { no_ui_impact_reason: noUiImpactReason } : {}),
    overlay: state.overlay || [],
    parent_oid: parentOid,
    ...(reviewers.length > 0 ? { reviewers } : {}),
    schema_version: schemaVersion,
    scope,
    tree_oid: liveTree,
    type,
    ui: state.ui
      ? {
          after_sha256: state.ui.after.sha256,
          before_sha256: state.ui.before ? state.ui.before.sha256 : null,
          new_surface_reason: state.ui.new_surface_reason,
          ...(cleanUiNotes ? { notes: cleanUiNotes } : {}),
          route: state.ui.route,
          theme: state.ui.theme,
          viewport: state.ui.viewport,
        }
      : null,
    verification_mode: effectiveMode,
  };

  const evidenceId = computeEvidenceId(canonicalPayload);

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
  if (cleanGranularity) {
    msgLines.push("", "Granularity:", cleanGranularity);
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
  for (const r of reviewers) {
    msgLines.push(formatReviewerTrailer(r));
  }
  if (noUiImpactReason && !state.ui) {
    msgLines.push(`UI-Impact: none (${noUiImpactReason})`);
  }
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

  return {
    canonicalPayload,
    cleanGranularity,
    cleanUiNotes,
    commitMessage,
    evidenceId,
    liveStagedFiles,
    liveTree,
    noUiImpactReason,
    parentOid,
    reviewers,
    title,
    why,
  };
}

async function cmdVerify(argv) {
  const { flags, multi } = parseFlags(argv, "verify");
  const repoCtx = resolveRepoContext();
  const runBundle = loadRunState(repoCtx.gitDir, flags["run-id"]);
  const plan = buildValidatedCommitPlan(repoCtx, runBundle, flags, multi["reviewed-by"]);
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
  const { flags, multi } = parseFlags(argv, "commit");
  const repoCtx = resolveRepoContext();
  const runBundle = loadRunState(repoCtx.gitDir, flags["run-id"]);
  const plan = buildValidatedCommitPlan(repoCtx, runBundle, flags, multi["reviewed-by"]);

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
      `Post-commit drift detected: commit ${commitOid.slice(0, 12)} recorded tree ${actualTree} instead of verified tree ${plan.liveTree} (likely modified by a pre-commit hook). Run \`git reset --soft HEAD~1\` before retrying.`,
    );
  }
  if (actualParent !== plan.parentOid) {
    throw new Error(`Post-commit parent mismatch (${actualParent} != ${plan.parentOid}).`);
  }
  if (bodyBlock !== plan.commitMessage) {
    scanPublicTextPrivacy(bodyBlock, "post_hook_commit_body");
    throw new Error(
      `Post-commit message drift detected on ${commitOid.slice(0, 12)}: a commit-msg hook altered the verified commit message. Run \`git reset --soft HEAD~1\` and disable message-mutating hooks.`,
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
    granularity: plan.cleanGranularity,
    ...(plan.reviewers.length > 0 ? { reviewers: plan.reviewers } : {}),
    staged_files: plan.liveStagedFiles,
    title: plan.title,
    ui_details: runBundle.state.ui
      ? { ...runBundle.state.ui, notes: plan.cleanUiNotes }
      : null,
    why: plan.why,
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
  if (argv.some((a) => a === "-h" || a === "--help" || a === "--help=true")) {
    printHelp();
    return;
  }
  if (argv.length > 1 || (argv[0] && argv[0].startsWith("-"))) {
    throw new Error("Usage: node proof_commit.mjs inspect [<commit-oid>]");
  }
  const targetRef = argv[0] || "HEAD";
  const { repoRoot, commonDir } = resolveRepoContext();
  const oid = git(repoRoot, ["rev-parse", "--verify", "--end-of-options", `${targetRef}^{commit}`]).stdout.trim();
  const mapPath = path.join(commonDir, "proof-commit", "commits", `${oid}.json`);
  if (!fs.existsSync(mapPath)) {
    throw new Error(`No local proof-commit record mapped for commit ${oid}.`);
  }
  const mapping = JSON.parse(fs.readFileSync(mapPath, "utf8"));
  assertValidEvidenceIdFormat(mapping.evidence_id, "mapping.evidence_id");
  const digestHex = mapping.evidence_id.replace(/^sha256:/, "");
  const bundlesRoot = path.resolve(commonDir, "proof-commit", "bundles");
  const bundleDir = path.resolve(bundlesRoot, digestHex);
  if (path.dirname(bundleDir) !== bundlesRoot) {
    throw new Error("Bundle directory containment check failed.");
  }
  const manifestPath = path.join(bundleDir, "manifest.json");
  process.stdout.write(fs.readFileSync(manifestPath, "utf8"));
}

async function main() {
  const [sub, ...rest] = process.argv.slice(2);
  if (!sub || sub === "--help" || sub === "-h" || sub === "--help=true") {
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
