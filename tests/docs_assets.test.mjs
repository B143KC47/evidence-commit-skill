import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const EXPECTED_SVGS = [
  'assets/hero-light.svg',
  'assets/hero-dark.svg',
  'assets/granularity-light.svg',
  'assets/granularity-dark.svg',
  'assets/pipeline-light.svg',
  'assets/pipeline-dark.svg',
];

function stripCommentsAndFences(md) {
  const noComments = md.replace(/<!--[\s\S]*?-->/g, '');
  const lines = noComments.split(/\r?\n/);
  const out = [];
  let fence = null;
  for (const line of lines) {
    const m = line.match(/^\s*(`{3,}|~{3,})/);
    if (m) {
      const marker = m[1];
      if (!fence) {
        fence = marker;
        out.push('');
        continue;
      }
      if (marker[0] === fence[0] && marker.length >= fence.length) {
        fence = null;
        out.push('');
        continue;
      }
    }
    out.push(fence ? '' : line);
  }
  return out.join('\n');
}

function githubSlugifyHeadings(md) {
  const stripped = stripCommentsAndFences(md);
  const slugs = new Set();
  const counts = new Map();
  for (const line of stripped.split('\n')) {
    const m = line.match(/^#{1,6}\s+(.+?)\s*$/);
    if (!m) continue;
    let text = m[1]
      .replace(/`([^`]*)`/g, '$1')
      .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
      .replace(/<[^>]+>/g, '')
      .trim()
      .toLowerCase();
    // GitHub / Comrak heading slugification: keep Unicode letters/marks/numbers, spaces & hyphens
    text = text.replace(/[^\p{L}\p{M}\p{N}\s_-]/gu, '').replace(/\s+/g, '-');
    const seen = counts.get(text) ?? 0;
    counts.set(text, seen + 1);
    slugs.add(seen === 0 ? text : `${text}-${seen}`);
  }
  return slugs;
}

test('all adaptive light/dark SVG diagrams exist, are well-formed, and pass GitHub sanitizer checks', () => {
  for (const rel of EXPECTED_SVGS) {
    const full = path.join(REPO_ROOT, rel);
    assert.ok(fs.existsSync(full), `Missing expected SVG asset: ${rel}`);
    const content = fs.readFileSync(full, 'utf8').trim();
    assert.match(content, /^<svg\b[^>]*xmlns="http:\/\/www\.w3\.org\/2000\/svg"/);
    assert.match(content, /\bviewBox="0 0 1200 \d+"/);
    assert.match(content, /<\/svg>$/);

    // Balanced basic XML element count sanity check
    const openTags = [...content.matchAll(/<([a-zA-Z][a-zA-Z0-9]*)\b(?![^>]*\/>)[^>]*>/g)].map((m) => m[1]);
    const closeTags = [...content.matchAll(/<\/([a-zA-Z][a-zA-Z0-9]*)\s*>/g)].map((m) => m[1]);
    assert.equal(openTags.length, closeTags.length, `${rel} has unbalanced XML open/close tags`);

    // GitHub Camo/sanitizer safety
    assert.doesNotMatch(content, /<script\b/i, `${rel} must not contain <script>`);
    assert.doesNotMatch(content, /<foreignObject\b/i, `${rel} must not contain <foreignObject>`);
    assert.doesNotMatch(content, /\bon[a-z]+\s*=/i, `${rel} must not contain inline event handlers`);
    assert.doesNotMatch(content, /javascript:/i, `${rel} must not contain javascript: URIs`);
    assert.doesNotMatch(content, /@import\s+url\(/i, `${rel} must not fetch external CSS`);
    assert.doesNotMatch(content, /<(?:image|use)\b[^>]*https?:/i, `${rel} must not fetch external images`);
  }
});

test('README.md and docs/README.zh-CN.md validate <picture> pairs, live non-nil video UUID, relative paths, and #anchors', () => {
  const docsToCheck = ['README.md', 'docs/README.zh-CN.md'];
  const slugCache = new Map();
  for (const rel of docsToCheck) {
    slugCache.set(
      path.resolve(REPO_ROOT, rel),
      githubSlugifyHeadings(fs.readFileSync(path.join(REPO_ROOT, rel), 'utf8'))
    );
  }

  const videoUrls = [];

  for (const docRel of docsToCheck) {
    const docPath = path.resolve(REPO_ROOT, docRel);
    const rawMd = fs.readFileSync(docPath, 'utf8');
    const cleanMd = stripCommentsAndFences(rawMd);
    const docDir = path.dirname(docPath);

    // 1. Validate explicit <picture> blocks for hero, granularity, and pipeline
    const pictureBlocks = [...cleanMd.matchAll(/<picture>\s*([\s\S]*?)\s*<\/picture>/g)].map((m) => m[1]);
    assert.equal(pictureBlocks.length, 3, `${docRel} must contain exactly 3 adaptive <picture> blocks`);
    const expectedStems = ['hero', 'granularity', 'pipeline'];
    expectedStems.forEach((stem, idx) => {
      const block = pictureBlocks[idx];
      assert.match(
        block,
        new RegExp(`<source\\s+media="\\(prefers-color-scheme:\\s*dark\\)"\\s+srcset="[^"]*${stem}-dark\\.svg"\\s*>`),
        `${docRel} picture #${idx + 1} missing dark source for ${stem}`
      );
      assert.match(
        block,
        new RegExp(`<source\\s+media="\\(prefers-color-scheme:\\s*light\\)"\\s+srcset="[^"]*${stem}-light\\.svg"\\s*>`),
        `${docRel} picture #${idx + 1} missing light source for ${stem}`
      );
      assert.match(
        block,
        new RegExp(`<img\\b[^>]*src="[^"]*${stem}-light\\.svg"[^>]*>`),
        `${docRel} picture #${idx + 1} missing fallback <img> for ${stem}`
      );
    });

    // 2. Validate standalone blank-line-bounded GitHub video URL outside code fences, rejecting nil placeholder
    const standaloneVideoMatches = [
      ...cleanMd.matchAll(
        /(?:^|\n)\n(https:\/\/github\.com\/user-attachments\/assets\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}))\n(?:\n|$)/g
      ),
    ];
    assert.equal(
      standaloneVideoMatches.length,
      1,
      `${docRel} must contain exactly one standalone blank-line-bounded GitHub user-attachments video URL`
    );
    const [fullMatch, videoUrl, uuid] = standaloneVideoMatches[0];
    assert.ok(fullMatch);
    assert.notEqual(
      uuid,
      '00000000-0000-0000-0000-000000000000',
      `${docRel} still contains the all-zero staging placeholder video UUID`
    );
    videoUrls.push(videoUrl);

    // 3. Validate all local relative paths AND #fragment anchors
    const attrRefs = [...cleanMd.matchAll(/\b(?:src|srcset|href)=["']([^"']+)["']/g)].flatMap((m) => {
      const val = m[1].trim();
      return val.includes(',') ? val.split(',').map((part) => part.trim().split(/\s+/)[0]) : [val.split(/\s+/)[0]];
    });
    const mdRefs = [...cleanMd.matchAll(/\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)].map((m) => m[1].trim());

    for (const rawTarget of [...attrRefs, ...mdRefs]) {
      if (!rawTarget || /^(https?:|mailto:|data:)/i.test(rawTarget)) continue;
      const [filePart, fragPart] = rawTarget.split('#');
      const targetFile = filePart ? path.resolve(docDir, filePart) : docPath;
      assert.ok(fs.existsSync(targetFile), `Broken relative path "${rawTarget}" in ${docRel} -> ${targetFile}`);

      if (fragPart !== undefined && fragPart.length > 0 && targetFile.endsWith('.md')) {
        const decodedFrag = decodeURIComponent(fragPart).toLowerCase();
        const targetSlugs =
          slugCache.get(targetFile) ?? githubSlugifyHeadings(fs.readFileSync(targetFile, 'utf8'));
        assert.ok(
          targetSlugs.has(decodedFrag),
          `Broken #anchor "${rawTarget}" in ${docRel}; available slugs: ${[...targetSlugs].join(', ')}`
        );
      }
    }
  }

  assert.equal(videoUrls[0], videoUrls[1], 'README.md and docs/README.zh-CN.md must embed the identical launch film asset URL');
});

test('SKILL.md preserves valid YAML frontmatter and compact progressive-disclosure metadata', () => {
  const skillPath = path.join(REPO_ROOT, 'skills/evidence-commit/SKILL.md');
  const content = fs.readFileSync(skillPath, 'utf8');
  const fmMatch = content.match(/^---\n([\s\S]*?)\n---/);
  assert.ok(fmMatch, 'SKILL.md must retain valid YAML frontmatter');
  const fm = fmMatch[1];
  assert.match(fm, /^name:\s*evidence-commit\s*$/m, 'SKILL.md frontmatter must declare name: evidence-commit');
  assert.match(fm, /^description:\s*>-?\s*\n\s+\S+/m, 'SKILL.md frontmatter must declare non-empty description');
  assert.ok(
    fm.length < 450,
    `SKILL.md frontmatter grew too large (${fm.length} chars) — violates compact metadata budget`
  );
  assert.doesNotMatch(content, /user-attachments\/assets/i);
  assert.doesNotMatch(content, /hero-(?:light|dark)\.svg/i);
});
