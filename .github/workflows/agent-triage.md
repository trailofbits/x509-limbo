---
# Trigger - when should this workflow run?
on:
  issues:
    types: [labeled]

# Permissions - what can this workflow access?
permissions:
  contents: read
  issues: write
  pull-requests: write

# AI engine configuration
engine: claude

# Outputs - what APIs and tools can the AI use?
safe-outputs:
  add-comment:
  add-labels:
---

# Agent: Triage Issues

This agent analyzes new issues synced from upstream and decides how to handle them.

## Trigger
Automatically runs when issues are labeled with "needs-triage"

## Context
- Repository: GitHub repository being analyzed
- Issue: The specific issue to triage
- Upstream: Original issue from upstream repository

## Objective
Analyze the **currently triggered issue** and determine:
1. Type of issue (bug, feature, enhancement, documentation, etc.)
2. Complexity level (trivial, easy, medium, hard, complex)
3. Required skill areas (frontend, backend, database, devops, etc.)
4. Whether it's suitable for automated fixing
5. Priority level based on impact and effort

## Scope & Safety

- Treat the **triggering issue only** as your source of truth.
- You may **only** add comments and labels to this issue.
- Do **not** create, close, or relabel any other issues or PRs.
- When you need to reference related or upstream issues, mention them **only inside the comment on this issue**.
- Keep your analysis and summary clearly scoped to this one issue, even if upstream context mentions multiple tasks.

## Process

### Step 1: Read and Understand
- Read the full issue description
- Extract the upstream issue reference
- Identify key requirements and acceptance criteria
- Note any specific constraints or dependencies

### Step 1a: Handle Upstream-Synced \"Mega\" Issues
- Detect if the issue was synced from upstream:
  - It has the `upstream` label, and/or
  - It has a label of the form `upstream-issue-<N>`.
- Check if the body clearly contains **multiple distinct tasks**, for example:
  - Markdown checklists (`- [ ] item`, `- [x] item`)
  - Numbered lists (`1. ...`, `2. ...`)
  - Bullet lists where each bullet describes a separate change or feature.
- If there are multiple independent tasks, **split them into separate local issues**:
  - For each task item:
    - Create a new issue in this fork with:
      - A short, specific title for that task.
      - A body that:
        - Quotes only the relevant bullet/checklist item and minimal context.
        - Mentions the original upstream issue in **non-linking form**, e.g. ``upstream ref: `C2SP/x509-limbo#<N>` `` so we don’t ping upstream.
      - Labels:
        - `upstream`
        - The original `upstream-issue-<N>` label
        - Any additional type/area labels you deem appropriate.
  - On the original synced issue:
    - Optionally repurpose it as a meta/tracking issue (linking the new local issues) or close it as \"split\".
    - Clearly state which local issues correspond to which original task items.

#### Implementation note for the agent

- You **must not** create or modify other issues automatically.
- Instead, in your triage comment on this issue:
  - Summarize the checklist items and proposed splits.
  - Make it clear these are **suggestions for human maintainers** to create or update other issues.
  - Keep all concrete actions (comments and labels) scoped to this single issue.

### Step 1b: Localize Cross-References
- When an upstream-synced issue body or comments reference other issues:
  - Avoid using `C2SP/x509-limbo#<N>` or `owner/repo#<N>` in a way that pings upstream.
  - Prefer:
    - Local issue references (e.g. `#<local-number>`) when a corresponding local issue exists.
    - Plain-text or backticked upstream references, e.g. ``upstream `C2SP/x509-limbo#<N>` ``.
- To map upstream → local issues:
  - Use `gh issue list --label upstream-issue-<N> --json number` to find all local issues cloned from upstream issue `<N>`.
  - When rewriting text, replace:
    - `C2SP/x509-limbo#<N>` with one or more local references (e.g. `#123, #124`) plus a non-linking upstream note if needed.
    - Bare `#<N>` that clearly refers to upstream with the appropriate local issue number.

#### Implementation note for the agent

- Do **not** call `gh issue list` or edit other issues.
- You may reason about likely local mappings in your comment, but restrict concrete changes (labels, comments) to this issue only.

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
Default to **optimistic auto-fix**.

An issue should receive the `agent-fix` label **unless** one or more of these are true:
- The description or requirements are unclear even after careful reading.
- The change appears to be large-scale or architectural (e.g., affects many subsystems, major refactor).
- It is primarily a **process**, coordination, or product decision issue (not a code change).

Guidelines:
- Medium or even hard issues can still be marked `agent-fix` if the goals are clear and the blast radius is understood.
- When in doubt, **prefer to add `agent-fix`** and clearly call out any risks or unknowns in your triage comment.

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
- Auto-fix decision is **optimistic but well-documented** (rare false negatives; risks called out in the comment)
- Analysis comment is helpful and actionable
- `needs-triage` label is removed

## Error Handling
- If issue description is unclear, add `needs-clarification` label
- If upstream issue is closed, add `upstream-closed` label and close
- If issue is duplicate, add `duplicate` label and link to original
- If analysis fails, add `triage-failed` label for human review
