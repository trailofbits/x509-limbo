# Agent: Triage Issues

This agent analyzes new issues synced from upstream and decides how to handle them.

## Trigger
Automatically runs when issues are labeled with "needs-triage"

## Context
- Repository: GitHub repository being analyzed
- Issue: The specific issue to triage
- Upstream: Original issue from upstream repository

## Objective
Analyze the issue and determine:
1. Type of issue (bug, feature, enhancement, documentation, etc.)
2. Complexity level (trivial, easy, medium, hard, complex)
3. Required skill areas (frontend, backend, database, devops, etc.)
4. Whether it's suitable for automated fixing
5. Priority level based on impact and effort

## Process

### Step 1: Read and Understand
- Read the full issue description
- Extract the upstream issue reference
- Identify key requirements and acceptance criteria
- Note any specific constraints or dependencies

### Step 2: Analyze Complexity
Assess complexity based on:
- Number of files likely to change
- Need for new dependencies
- API changes or breaking changes
- Test coverage requirements
- Documentation needs

Rate as:
- **trivial**: Single file, < 10 lines, obvious fix
- **easy**: 1-3 files, clear implementation path, < 50 lines
- **medium**: 3-7 files, moderate complexity, may need design decisions
- **hard**: 7+ files, complex logic, requires architectural understanding
- **complex**: Major refactoring, multiple systems, needs extensive testing

### Step 3: Categorize Issue Type
Add appropriate type label:
- `bug`: Something isn't working correctly
- `feature`: New functionality request
- `enhancement`: Improvement to existing functionality
- `documentation`: Docs need updates
- `performance`: Performance optimization
- `security`: Security-related issue
- `refactoring`: Code quality improvement
- `tests`: Test-related changes

### Step 4: Identify Skill Areas
Add area labels:
- `area:frontend`: UI/UX changes
- `area:backend`: Server-side logic
- `area:database`: Database changes
- `area:api`: API modifications
- `area:testing`: Test infrastructure
- `area:docs`: Documentation
- `area:devops`: CI/CD, infrastructure
- `area:security`: Security concerns

### Step 5: Determine Auto-fix Eligibility
An issue is eligible for automated fixing if ALL criteria are met:
- Complexity is trivial or easy
- Requirements are clear and unambiguous
- No breaking changes involved
- Existing tests can validate the fix
- No external dependencies needed
- Change is localized (< 5 files)

If eligible, add label: `agent-fix`

### Step 6: Assess Priority
Consider:
- Security implications (critical priority)
- Impact on users (high/medium/low)
- Effort required (low effort + high impact = high priority)

Add priority label:
- `priority:critical`: Security issues, major bugs affecting all users
- `priority:high`: Significant bugs or important features
- `priority:medium`: Regular bugs or enhancements
- `priority:low`: Nice-to-have improvements

### Step 7: Add Analysis Comment
Post a comment with:
```markdown
## 🤖 Automated Triage Analysis

**Issue Type:** [type]
**Complexity:** [level]
**Areas:** [areas]
**Priority:** [priority]

### Analysis
[Brief explanation of the issue and what needs to be done]

### Recommended Approach
[High-level approach to fixing/implementing]

### Estimated Scope
- Files to modify: [estimate]
- New dependencies: [yes/no]
- Breaking changes: [yes/no]
- Tests required: [type of tests]

### Auto-fix Eligible: [Yes/No]
[If yes: Issue will be automatically assigned to fix agent]
[If no: Reason why manual intervention is needed]
```

### Step 8: Final Actions
- Remove `needs-triage` label
- Add all determined labels
- If eligible for auto-fix, add `agent-fix` label
- If not eligible, add `needs-human-review` label

## Tools Available
- `gh issue view NUMBER`: View issue details
- `gh issue edit NUMBER`: Modify issue labels
- `gh issue comment NUMBER`: Add comments
- `gh api`: Make GitHub API calls
- `gh repo view`: Get repository information

## Success Criteria
- Issue is properly categorized with type label
- Complexity and area labels are accurate
- Priority is appropriately assigned
- Auto-fix decision is correct (no false positives)
- Analysis comment is helpful and actionable
- `needs-triage` label is removed

## Error Handling
- If issue description is unclear, add `needs-clarification` label
- If upstream issue is closed, add `upstream-closed` label and close
- If issue is duplicate, add `duplicate` label and link to original
- If analysis fails, add `triage-failed` label for human review
