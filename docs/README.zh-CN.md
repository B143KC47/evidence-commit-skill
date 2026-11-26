# Evidence Commit（原子化取证提交技能）

**语言：** [English](../README.md) | 简体中文

面向 Google Antigravity、Codex CLI 与 Claude Code 的工程级原子 Commit 技能与零依赖取证工具：让每一次 `git commit` 都满足**不碎不粗的软件工程粒度**，并携带**绑定到精确暂存树（`git write-tree`）的因果理由、原文终端日志（Before → After）与 UI 视觉证据元数据**。

## 解决的核心痛点

1. **杜绝“半成品碎提交”与“大杂烩乱提交”**：内置 *Tidy First* 结构/行为分离准则与单一验收条件判据，禁止 `git add .` 把临时脚本或无关改动一锅端。
2. **根治“工作区绿灯、暂存区坏代码”错位**：默认在仓库外部临时目录物化精确暂存树 `T = git write-tree` 运行验证；支持 `--overlay` 将新写的回归测试挂载回父提交 `P` 诚实补采 `Before` 失败日志。
3. **禁止模型手敲伪造或空跑跳过**：所有 `  | ` 引文均从子进程原始字节流按区间直切（零篡改），自动拦截 `SKIP` / `0 passed` 假阳性，并在提交前扫描拦截本地用户目录路径与高危密钥格式。

## 安装方式

```bash
npx skills add B143KC47/evidence-commit-skill
```

或复制到项目本地技能目录：
- **Antigravity / Codex**：`.agents/skills/evidence-commit/`
- **Claude Code**：`.claude/skills/evidence-commit/`

## 运行自测

```bash
node --test tests/*.test.mjs
```
