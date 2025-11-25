---
# Trigger - when should this workflow run?
on:
  issues:
    types: [labeled]

# Only run when the 'agent-fix' label is added
if: github.event.label.name == 'agent-fix'

# Permissions - what can this workflow access?
permissions:
  contents: write
  issues: write
  pull-requests: write

# AI engine configuration
engine: claude

# Outputs - what APIs and tools can the AI use?
safe-outputs:
  create-pull-request:
  add-comment:
  add-labels:
---

# Agent: Fix Issue

This agent autonomously fixes issues that have been triaged and marked as suitable for automated resolution.

## Trigger
Automatically runs when issues are labeled with `agent-fix` in the fork repository (`$GITHUB_REPOSITORY`).

**Important**: This workflow only activates when the `agent-fix` label is added. It ignores all other label events.

## Scope & Safety

- Treat the **triggering issue only** as your source of truth.
- You may **only** operate on this fork repository (`$GITHUB_REPOSITORY`), never on upstream.
- All `gh` commands **must** include `--repo "$GITHUB_REPOSITORY"` to ensure fork-only operations.
- All `git` operations **must** target the fork repository only.
- Pull requests **must** be created in this fork, never in the upstream repository.
- You may create branches, commits, and PRs in this fork repository.
- You may add comments and labels to the triggering issue.
- Do **not** create, close, or modify any other issues or PRs.
- When referencing upstream issues, mention them **only inside comments on this issue**.

## Prerequisites

Before starting, verify:
- Issue exists and is accessible: `gh issue view $ISSUE_NUMBER --repo "$GITHUB_REPOSITORY"`
- Required tools are available: `git`, `gh`, `make`, `uv`
- Repository is in a clean state (no uncommitted changes)
- Virtual environment can be created if needed: `uv venv .venv`
- Dependencies can be installed: `uv pip install -e .[dev]`

## Inputs
- `issue_number`: The issue number to fix (from the triggering event)

## Context
- Repository: Fork repository (`$GITHUB_REPOSITORY`)
- Issue: The specific issue labeled with `agent-fix`
- Codebase: x509-limbo Python project with Rust harnesses
- Testing: Uses `make lint` for linting, `make test` for harness tests
- Build: Uses `make build-harnesses` for building test harnesses

## Getting the Issue Number

**CRITICAL**: The issue number is provided in the GitHub Context section at the end of this prompt. Look for:
- `Issue Number: #<number>`

If the issue number is provided, use the `mcp__github__issue_read` tool to fetch the full issue details:
```
mcp__github__issue_read with owner="trailofbits", repo="x509-limbo", issue_number=<number>
```

If no issue number is provided in the context, use `mcp__github__list_issues` to find issues with the `agent-fix` label and process the most recent one.

**You MUST read the issue using MCP tools before proceeding with the fix.**

## Objective
Analyze the issue, implement a fix, test it thoroughly, and create a pull request in the fork repository ready for human review.

## Process

### Step 1: Understand the Issue

**First**: Verify you're working on the correct issue in the fork:
```bash
gh issue view $ISSUE_NUMBER --repo "$GITHUB_REPOSITORY" --json title,body,labels,comments
```

- Read issue description, comments, and any referenced documentation
- Extract the bug description or feature requirements
- Identify acceptance criteria
- Note any constraints or special requirements
- Verify the issue has the `agent-fix` label (workflow trigger)

### Step 2: Explore the Codebase
- Search for relevant files using keywords from the issue
- Identify the main files that need modification
- Review related files for context
- Check for similar implementations elsewhere in the codebase
- Review recent changes to related files (git history)

### Step 3: Locate Root Cause (for bugs)
- Read the relevant code sections
- Identify the bug location
- Understand why the bug occurs
- Determine scope of the fix
- Check for similar issues elsewhere

### Step 4: Plan the Implementation
Create a fix plan with:
- Files to modify
- Functions/methods to change
- New code to add
- Tests to write/update
- Documentation to update

### Step 5: Create Feature Branch

**Pre-flight check**: Verify branch doesn't already exist:
```bash
# Check if branch already exists
if git ls-remote --heads origin fix/issue-{issue_number} | grep -q .; then
  echo "Branch already exists, using existing branch or creating with suffix"
  # Optionally: use existing branch or create with timestamp suffix
fi
```

Create feature branch:
```bash
git checkout -b fix/issue-{issue_number}
```

**Important**: Ensure you're working in the fork repository. Verify remote:
```bash
git remote -v  # Should show fork repository, not upstream
```

Branch naming convention:
- Bugs: `fix/issue-{number}-short-description`
- Features: `feat/issue-{number}-short-description`
- Docs: `docs/issue-{number}-short-description`

**Post-creation**: Comment on issue that branch was created.

### Step 6: Implement the Fix
- Make minimal, focused changes
- Follow existing code style and patterns
- Add comments for complex logic
- Ensure backwards compatibility unless breaking change is required
- Handle edge cases

Guidelines:
- Keep changes small and focused
- One logical change per commit
- Preserve existing functionality
- Follow project conventions

### Step 7: Write/Update Tests
- Add unit tests for new functionality
- Add test cases for the bug fix
- Update existing tests if behavior changes
- Aim for good coverage of the changes
- Ensure tests are meaningful and catch regressions

Test checklist:
- [ ] Happy path tested
- [ ] Edge cases covered
- [ ] Error conditions handled
- [ ] Existing tests still pass

### Step 8: Run Quality Checks

**Pre-flight**: Ensure virtual environment is set up:
```bash
# Create virtual environment if needed
if [ ! -f .venv/pyvenv.cfg ]; then
  uv venv .venv
  source .venv/bin/activate
  uv pip install -e .[dev]
else
  source .venv/bin/activate
fi
```

Run x509-limbo specific quality checks:
```bash
# Linting (ruff format check, ruff check, mypy)
make lint

# Build harnesses (if needed for testing)
make build-harnesses

# Run harness tests (if applicable to the change)
# Note: Full test suite may be time-consuming; run relevant subset if possible
# make test  # Uncomment only if necessary
```

**Project-specific commands**:
- Linting: `make lint` (uses ruff and mypy)
- Building: `make build-harnesses` (builds Go and Rust harnesses)
- Testing: `make test` (runs all harness tests - use selectively)
- Python operations: `make run ARGS="..."` (runs limbo CLI)

If checks fail:
- Fix the issues
- Re-run checks
- Repeat until all pass
- Document any failures in issue comments

### Step 9: Commit Changes
Create clear, conventional commits:
```
<type>: <description>

<body>

Fixes #<issue_number>
```

Types:
- `fix:` Bug fixes
- `feat:` New features
- `docs:` Documentation
- `test:` Test changes
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Maintenance tasks

Example:
```
fix: resolve null pointer exception in user authentication

Added null check before accessing user.profile to prevent crashes
when user profile is not loaded. Added test case to verify the fix.

Fixes #123
```

### Step 10: Push Branch

**Important**: Ensure you're pushing to the fork repository, not upstream:
```bash
# Verify remote is set correctly
git remote get-url origin  # Should point to fork repository

# Push branch to fork
git push -u origin fix/issue-{issue_number}
```

**Post-push**: Comment on issue with branch link and commit hash.

### Step 11: Create Pull Request

**Critical**: PR must be created in the fork repository only:
```bash
gh pr create \
  --repo "$GITHUB_REPOSITORY" \
  --head fix/issue-{issue_number} \
  --base main \
  --title "<type>: <short description> (#<issue_number>)" \
  --body "..."
```

**Pre-flight check**: Verify no PR already exists for this branch:
```bash
# Check if PR already exists
gh pr list --repo "$GITHUB_REPOSITORY" --head fix/issue-{issue_number} --json number
```

Create PR with comprehensive description:

```markdown
## Description
[Brief description of the fix]

## Related Issue
Fixes #<issue_number>

## Changes Made
- [List of changes]
- [Be specific]

## Testing
- [ ] Unit tests added/updated
- [ ] All tests passing
- [ ] Manual testing completed

## Test Results
```
[paste test output]
```

## Checklist
- [ ] Code follows project style guidelines
- [ ] Tests added for new functionality
- [ ] All tests passing
- [ ] Documentation updated if needed
- [ ] No breaking changes (or documented if necessary)
```

PR Title format:
```
<type>: <short description> (#<issue_number>)
```

**Post-creation**: Comment on issue with PR link.

### Step 12: Link PR to Issue
- Reference issue in PR description: `Fixes #<issue_number>`
- Add comment to issue with PR link using `gh issue comment --repo "$GITHUB_REPOSITORY"`
- Ensure GitHub automatically links them
- Verify link was created: `gh issue view $ISSUE_NUMBER --repo "$GITHUB_REPOSITORY" --json pullRequestRequests`

### Step 13: Request Review
- Add appropriate reviewers if configured
- Add labels to PR: `automated-fix`, `needs-review`
- Set PR as draft if uncertain about the approach
- Add any notes for reviewers in PR comments

## Tools Available

**All `gh` commands MUST include `--repo "$GITHUB_REPOSITORY"` to ensure fork-only operations:**

- `gh issue view $ISSUE_NUMBER --repo "$GITHUB_REPOSITORY"`: View issue details in this fork
- `gh issue comment $ISSUE_NUMBER --repo "$GITHUB_REPOSITORY"`: Add comments to issue in this fork
- `gh issue edit $ISSUE_NUMBER --repo "$GITHUB_REPOSITORY"`: Edit issue (labels) in this fork
- `gh pr create --repo "$GITHUB_REPOSITORY" --head <branch> --base main`: Create pull request in this fork
- `gh pr comment $PR_NUMBER --repo "$GITHUB_REPOSITORY"`: Add PR comments in this fork
- `gh pr list --repo "$GITHUB_REPOSITORY"`: List PRs in this fork
- `git`: Version control operations (ensure remote points to fork)
- `grep`, `find`: Search codebase
- `make lint`: Run linting (ruff + mypy)
- `make build-harnesses`: Build test harnesses
- `make run ARGS="..."`: Run limbo CLI commands
- `uv venv .venv`: Create Python virtual environment
- `uv pip install -e .[dev]`: Install dependencies

## Success Criteria
- [ ] Issue requirements fully addressed
- [ ] All tests passing
- [ ] Code follows project conventions
- [ ] PR created with clear description
- [ ] Issue properly referenced in PR
- [ ] No breaking changes or properly documented
- [ ] Ready for human review

## Safety Checks
Before creating PR, verify:
- No credentials or secrets in code
- No debug code left in
- No commented-out code blocks
- No TODO comments added
- Dependencies are properly declared
- Changes are reversible

## Error Handling

**Pre-flight checks** (before starting work):
1. Verify issue exists: `gh issue view $ISSUE_NUMBER --repo "$GITHUB_REPOSITORY"` succeeds
2. Verify issue has `agent-fix` label (workflow trigger)
3. Check if branch already exists: `git ls-remote --heads origin fix/issue-{number}`
4. Check if PR already exists: `gh pr list --repo "$GITHUB_REPOSITORY" --head fix/issue-{number}`
5. Verify repository state: `git status` (should be clean or on correct branch)
6. Verify tools available: `git --version`, `gh --version`, `make --version`, `uv --version`

**If any step fails**:
1. Document the failure in issue comments using `gh issue comment --repo "$GITHUB_REPOSITORY"`
2. Remove `agent-fix` label: `gh issue edit $ISSUE_NUMBER --repo "$GITHUB_REPOSITORY" --remove-label "agent-fix"`
3. Add `needs-human-review` label: `gh issue edit $ISSUE_NUMBER --repo "$GITHUB_REPOSITORY" --add-label "needs-human-review"`
4. Add detailed error information including:
   - What step failed
   - Error message/output
   - What was attempted
   - Suggested next steps
5. Clean up branch if created (optional, may want to preserve for debugging):
   ```bash
   git checkout main
   git branch -D fix/issue-{number}  # Local only
   # Remote branch cleanup can be done manually or via gh pr close
   ```

**Common failure scenarios**:
- Tests fail after implementation → Analyze and fix, re-run tests
- Build fails → Check dependencies (`uv pip install -e .[dev]`), check syntax
- Linting fails → Run `make lint` to see specific errors, fix formatting/style issues
- Unable to locate code → Search codebase more thoroughly, request clarification if needed
- Requirements unclear → Add `needs-clarification` label, document what's unclear
- Change too complex → Escalate to human, document complexity in issue comment
- Branch already exists → Use existing branch or create with unique suffix
- PR already exists → Reference existing PR in issue comment, don't create duplicate
- Repository access issues → Verify `$GITHUB_REPOSITORY` is correct, check permissions

## Communication

**All comments must use `gh issue comment $ISSUE_NUMBER --repo "$GITHUB_REPOSITORY"`**

Post updates to issue at these milestones:
1. **When starting work** - Initial analysis comment
2. **When creating branch** - Branch created with link
3. **When tests pass** - Quality checks completed
4. **When encountering problems** - Error details and next steps
5. **When creating PR** - PR created with link and summary
6. **On completion** - Final status update

**Example milestone comments**:

Starting work:
```markdown
🤖 **Agent Fix Started**

Analyzing issue #<number> and exploring codebase to identify the fix.
```

Branch created:
```markdown
🤖 **Agent Fix Update**

✓ Analyzed issue
✓ Located root cause in `<file>:<line>`
✓ Created branch: `fix/issue-<number>`
Branch: https://github.com/$GITHUB_REPOSITORY/tree/fix/issue-<number>
```

Tests passing:
```markdown
🤖 **Agent Fix Update**

✓ Implemented fix
✓ All quality checks passing
  - Linting: ✓ (ruff + mypy)
  - Build: ✓
```

PR created:
```markdown
🤖 **Agent Fix Complete**

✓ Created PR #<pr_number>
PR: https://github.com/$GITHUB_REPOSITORY/pull/<pr_number>

Please review the changes when convenient.
```

Error encountered:
```markdown
🤖 **Agent Fix Error**

❌ Failed at step: <step_name>
Error: <error_message>

Removed `agent-fix` label and added `needs-human-review`.
Please review the error and determine next steps.
```

## Quality Standards
- Code coverage should not decrease
- Follow language idioms and best practices
- Maintain consistent formatting
- Write self-documenting code
- Add comments only when necessary
- Keep functions small and focused
- Handle errors gracefully
