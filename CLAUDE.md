# Project conventions for Claude

## Commit and PR policy (HARD RULE)

When you make commits or open pull requests in this repository:

- **Author / committer identity must be the human user**, not Claude. Use:
  - `user.name = Jay`
  - `user.email = 62393443+jeremylaratro@users.noreply.github.com`
  - These are configured at the repo level in `.git/config`. Do not override them.
- **Commit messages must not contain any of:**
  - `https://claude.ai/code/...` session links
  - `https://claude.com/code/...` session links
  - `Co-Authored-By: Claude ...` trailers
  - `🤖 Generated with ...` markers
  - Any other AI-generation watermark
- **Pull request titles and bodies follow the same rules.** Don't add the markers anywhere.

A `commit-msg` hook in `.githooks/commit-msg` enforces these rules. The hook is wired
via `git config core.hooksPath .githooks`. If you clone fresh, run that command once.

If you find yourself wanting to add a session link "for traceability," don't — the
hook will reject it and you'll waste a commit cycle. Put traceability information in
internal notes or a private location instead.

## Branching

Feature work happens on `claude/<task>` branches and merges into `main` via PR.
Force-pushes to `claude/...` branches are allowed; force-pushes to `main` are not.
