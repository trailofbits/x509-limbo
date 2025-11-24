# Agent: Fix Issue

This agent autonomously fixes issues that have been triaged and marked as suitable for automated resolution.

## Inputs
- `issue_number`: The issue number to fix (required)

## Context
- Repository with existing codebase
- Issue with clear requirements
- Access to run tests and linters

## Objective
Analyze the issue, implement a fix, test it thoroughly, and create a pull request ready for human review.

## Process

### Step 1: Understand the Issue
- Read issue description, comments, and any referenced documentation
- Extract the bug description or feature requirements
- Identify acceptance criteria
- Note any constraints or special requirements

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
```bash
git checkout -b fix/issue-{issue_number}
```

Branch naming convention:
- Bugs: `fix/issue-{number}-short-description`
- Features: `feat/issue-{number}-short-description`
- Docs: `docs/issue-{number}-short-description`

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
Run all available checks:
```bash
# Tests
npm test || pytest || go test || cargo test

# Linting
npm run lint || flake8 || golangci-lint run || cargo clippy

# Type checking
npm run type-check || mypy . || go vet

# Build
npm run build || make build || cargo build
```

If checks fail:
- Fix the issues
- Re-run checks
- Repeat until all pass

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
```bash
git push -u origin fix/issue-{issue_number}
```

### Step 11: Create Pull Request
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

### Step 12: Link PR to Issue
- Reference issue in PR description: `Fixes #<issue_number>`
- Add comment to issue with PR link
- Ensure GitHub automatically links them

### Step 13: Request Review
- Add appropriate reviewers if configured
- Add labels to PR: `automated-fix`, `needs-review`
- Set PR as draft if uncertain about the approach
- Add any notes for reviewers in PR comments

## Tools Available
- `gh issue view`: View issue details
- `gh pr create`: Create pull request
- `gh pr comment`: Add PR comments
- `git`: Version control operations
- `grep`, `find`: Search codebase
- Project-specific tools (npm, pytest, etc.)

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
If any step fails:
1. Document the failure in issue comments
2. Remove `agent-fix` label
3. Add `needs-human-review` label
4. Add detailed error information
5. Clean up branch if created

Common failure scenarios:
- Tests fail after implementation → Analyze and fix
- Build fails → Check dependencies and syntax
- Unable to locate code → Request clarification
- Requirements unclear → Add `needs-clarification` label
- Change too complex → Escalate to human

## Communication
Post updates to issue:
- When starting work
- When creating branch
- When encountering problems
- When creating PR
- Include links to commits/PR

Example comment:
```markdown
🤖 **Agent Fix Update**

✓ Analyzed issue
✓ Located root cause in `src/auth.js:45`
✓ Implemented fix
✓ Tests passing (12/12)
✓ Created PR #123

Please review the changes when convenient.
```

## Quality Standards
- Code coverage should not decrease
- Follow language idioms and best practices
- Maintain consistent formatting
- Write self-documenting code
- Add comments only when necessary
- Keep functions small and focused
- Handle errors gracefully
