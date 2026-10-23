---
name: changelog-writer
description: Summarise git history between two tags into a grouped CHANGELOG section.
capabilities:
  - git.read
  - filesystem.write
---

# Changelog writer

Use this skill when the user asks to draft release notes.

1. Run `git log --oneline v1.0.0..v1.1.0` to list the commits.
2. Group the commits into **Added**, **Fixed**, and **Changed**.
3. Write the result to `CHANGELOG.md` under a new heading. Ask the user to confirm before overwriting an
   existing section.

See the [Conventional Commits spec](https://www.conventionalcommits.org/en/v1.0.0/) for the grouping rules.
