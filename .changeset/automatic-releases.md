---
"mcp-remote": patch
---

Add automatic release infrastructure using changesets

- Install and configure @changesets/cli with GitHub changelog generator
- Add release.yml workflow for automated publishing with npm Trusted Publishing
- Add check-changeset.yml workflow to validate PRs include changesets (works on forks)
- Update README with contribution guidelines
