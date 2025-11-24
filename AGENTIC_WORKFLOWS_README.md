# Agentic Workflows Setup

This repository has been configured with automated agent workflows for handling issues from the upstream repository.

## Workflows Installed

### 1. Sync Upstream Issues (`sync-upstream-issues.yml`)
- **Runs:** Every 6 hours (scheduled) or manually
- **Purpose:** Fetches open issues from upstream and creates them in this fork
- **Labels added:** `upstream`, `needs-triage`

**Manual trigger:**
```bash
gh workflow run sync-upstream-issues.yml
```

### 2. Triage Agent (`agent-triage.md` + `trigger-triage-agent.yml`)
- **Runs:** When issue is labeled with `needs-triage`
- **Purpose:** Analyzes issue complexity, type, and determines if auto-fixable
- **Outputs:** Adds labels like `bug`, `feature`, `complexity:easy`, `agent-fix`

### 3. Fix Agent (`agent-fix-issue.md` + `trigger-fix-agent.yml`)
- **Runs:** When issue is labeled with `agent-fix` or manually triggered
- **Purpose:** Attempts to automatically fix the issue
- **Outputs:** Creates branch and draft PR with fix

**Manual trigger:**
```bash
gh workflow run trigger-fix-agent.yml -f issue_number=42
```

### 4. Upstream PR Agent (`agent-create-upstream-pr.md` + `trigger-upstream-pr.yml`)
- **Runs:** When fork PR is approved and labeled `ready-for-upstream`
- **Purpose:** Prepares PR for submission to upstream repository
- **Outputs:** Creates branch rebased on upstream, provides commands for PR creation

## Usage

### Automatic Flow
1. Agent syncs issues from upstream (every 6 hours)
2. Triage agent analyzes each new issue
3. If suitable, adds `agent-fix` label
4. Fix agent creates PR with attempted fix
5. Human reviews and approves PR
6. Add `ready-for-upstream` label to trigger upstream PR preparation

### Manual Flow

#### Manually triage an issue:
```bash
gh issue edit ISSUE_NUMBER --add-label needs-triage
```

#### Manually trigger fix agent:
```bash
gh workflow run trigger-fix-agent.yml -f issue_number=ISSUE_NUMBER
```

#### Prepare upstream PR:
```bash
gh issue edit PR_NUMBER --add-label ready-for-upstream
# Or manually trigger:
gh workflow run trigger-upstream-pr.yml -f pr_number=PR_NUMBER
```

## Configuration

### Upstream Repository
Configured upstream: C2SP/x509-limbo

To change:
1. Edit `.github/workflows/sync-upstream-issues.yml`
2. Edit `.github/workflows/trigger-upstream-pr.yml`
3. Replace `C2SP/x509-limbo` with new upstream

### AI Provider
Currently using GitHub's Claude integration via `ANTHROPIC_API_KEY` secret.

To use your own key:
```bash
gh secret set ANTHROPIC_API_KEY
# Paste your key when prompted
```

### Sync Schedule
Edit `.github/workflows/sync-upstream-issues.yml`:
```yaml
schedule:
  - cron: '0 */6 * * *'  # Every 6 hours
  # Change to:
  - cron: '0 0 * * *'    # Daily at midnight
```

## Labels Used

### Issue Labels
- `upstream` - Synced from upstream repository
- `upstream-issue-<N>` - Tracks the original upstream issue number
- `needs-triage` - Needs automated analysis
- `agent-fix` - Suitable for automated fixing
- `needs-human-review` - Requires human intervention
- `needs-clarification` - Issue description is unclear
- `bug`, `feature`, `docs`, etc. - Issue type
- `complexity:trivial/easy/medium/hard` - Complexity level
- `area:frontend/backend/etc` - Code area affected
- `priority:critical/high/medium/low` - Priority level

### PR Labels
- `automated-fix` - Created by fix agent
- `needs-review` - Awaiting human review
- `ready-for-upstream` - Ready to submit to upstream
- `upstream-pr-created` - Upstream PR has been created

## Monitoring

### View workflow runs:
```bash
gh run list
```

### View specific run logs:
```bash
gh run view RUN_ID --log
```

### Check synced issues:
```bash
gh issue list --label upstream
```

### Check issues needing triage:
```bash
gh issue list --label needs-triage
```

### Check automated fix PRs:
```bash
gh pr list --label automated-fix
```

## Troubleshooting

### No issues being synced
- Check workflow runs: `gh run list --workflow=sync-upstream-issues.yml`
- Verify upstream repository is accessible
- Check rate limits: `gh api rate_limit`

### Triage agent not running
- Verify issue has `needs-triage` label
- Check workflow permissions in Settings > Actions > General
- View run logs for errors

### Fix agent fails
- Review the workflow logs
- Check if repository has required project files (package.json, etc.)
- Verify tests can run in GitHub Actions environment

### Cannot create upstream PR
- Ensure branch is pushed to fork
- Verify you have permission to create PRs in upstream
- Check that upstream issue is still open

## Advanced Configuration

### Enable Full AI-Powered Workflows

To use the full capabilities with gh-aw:

1. **Install gh-aw extension:**
   ```bash
   gh extension install githubnext/gh-aw
   ```

2. **Build agentic workflows:**
   ```bash
   gh aw build .github/workflows/agent-triage.md
   gh aw build .github/workflows/agent-fix-issue.md
   gh aw build .github/workflows/agent-create-upstream-pr.md
   ```

3. **Update trigger workflows** to use the built `.lock.yml` files

### Customize Agent Behavior

Edit the `.md` files in `.github/workflows/`:
- `agent-triage.md` - Modify triage logic
- `agent-fix-issue.md` - Change fix approach
- `agent-create-upstream-pr.md` - Adjust PR creation

Then rebuild with gh-aw if using the extension.

### Add Custom Instructions

Create files in `.github/instructions/`:
```markdown
# .github/instructions/coding-style.instructions.md

Follow these style guidelines:
- Use 2 spaces for indentation
- Add JSDoc comments for public functions
- Write unit tests for all new code
```

## Best Practices

1. **Review all automated PRs** before merging
2. **Test locally** before submitting to upstream
3. **Monitor workflow usage** to stay within limits
4. **Keep agents updated** with project-specific instructions
5. **Human approval required** for all upstream submissions

## Support

For issues with:
- **This setup:** Create an issue in this repository
- **gh-aw extension:** https://github.com/githubnext/gh-aw/issues
- **Upstream project:** Follow their contribution guidelines

## License

These workflows are provided as-is. Follow the upstream repository's license for contributions.
