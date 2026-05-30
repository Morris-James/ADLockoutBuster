---
name: feedback-github-obsidian
description: "For all new projects: create a GitHub repo, sync changes after each session, copy docs to Obsidian vault"
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 2bb3fd33-9e5c-43b7-be28-e8b894cf72c5
---

For every new project Morris creates:
1. Create a GitHub repository (public, descriptive name)
2. Push all code and documentation on initial build
3. Sync changes to GitHub after each work session
4. Copy all documentation (README, user guides, technical docs) to the Obsidian vault at `C:\Users\MorrisJames\Documents\Obsidian Vault\<ProjectName>\`
5. Keep Claude memory isolated in a `memory/` subdirectory in the repo

**Why:** Morris wants a complete audit trail and offline access to documentation in Obsidian, plus GitHub for collaboration and version control.

**How to apply:** At the end of every session that modifies the project, run `git add . && git commit && git push` and sync any changed docs to Obsidian.
