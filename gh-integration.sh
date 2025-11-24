#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# Global dry-run flag (set DRY_RUN=true in the environment to enable)
DRY_RUN=${DRY_RUN:-false}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKFLOWS_DIR=".github/workflows"
INSTRUCTIONS_DIR=".github/instructions"

# Print colored output
print_info() {
    echo -e "${BLUE}ℹ ${1}${NC}"
}

print_success() {
    echo -e "${GREEN}✓ ${1}${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ ${1}${NC}"
}

print_error() {
    echo -e "${RED}✗ ${1}${NC}"
}

print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  ${1}${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"

    # Check if gh CLI is installed
    if ! command -v gh &> /dev/null; then
        print_error "GitHub CLI (gh) is not installed"
        print_info "Install from: https://cli.github.com/"
        exit 1
    fi
    print_success "GitHub CLI found"

    # Check if authenticated
    if ! gh auth status &> /dev/null; then
        print_error "Not authenticated with GitHub CLI"
        print_info "Run: gh auth login"
        exit 1
    fi
    print_success "GitHub CLI authenticated"

    # Check if in a git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        print_error "Not in a git repository"
        print_info "Navigate to your forked repository or run: gh repo fork UPSTREAM_OWNER/REPO_NAME --clone=true"
        exit 1
    fi
    print_success "Git repository detected"

    # Check if gh-aw extension is installed
    if ! gh extension list | grep -q "gh-aw"; then
        print_warning "GitHub Agentic Workflows extension (gh-aw) not installed"
        read -p "Install it now? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_info "Installing gh-aw extension..."
            gh extension install githubnext/gh-aw
            print_success "gh-aw extension installed"
        else
            print_warning "Skipping gh-aw installation. Some features will be limited."
            print_info "You can install it later with: gh extension install githubnext/gh-aw"
        fi
    else
        print_success "gh-aw extension found"
    fi
}

# Select run mode (dry-run on test branch vs real install on current branch)
select_mode() {
    print_header "Run Mode Selection"

    CURRENT_BRANCH=$(git branch --show-current)
    print_info "Current branch: ${CURRENT_BRANCH}"

    echo "Choose how to run this setup:"
    echo "  1) Dry-run on a dedicated test branch (recommended for first run)"
    echo "  2) Real installation on the current branch"
    read -p "Select 1 or 2 [1]: " MODE_CHOICE
    echo

    if [[ -z "$MODE_CHOICE" || "$MODE_CHOICE" == "1" ]]; then
        TEST_BRANCH="agentic-workflows-dryrun"

        if git rev-parse --verify "$TEST_BRANCH" >/dev/null 2>&1; then
            print_info "Switching to existing dry-run branch: ${TEST_BRANCH}"
            git checkout "$TEST_BRANCH"
        else
            print_info "Creating dry-run branch: ${TEST_BRANCH} (from ${CURRENT_BRANCH})"
            git checkout -b "$TEST_BRANCH"
        fi

        DRY_RUN="true"
        export DRY_RUN
        print_success "Configured DRY-RUN mode on branch ${TEST_BRANCH}"
        print_info "All generated workflows will log what they would do, without changing issues/PRs."
    else
        DRY_RUN="false"
        export DRY_RUN
        print_warning "Running in REAL mode on branch ${CURRENT_BRANCH}"
        print_info "Workflows will be created with DRY-RUN disabled and can modify issues/PRs."
    fi
}

# Get repository information
get_repo_info() {
    print_header "Repository Information"

    CURRENT_REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner)
    print_info "Current repository: ${CURRENT_REPO}"

    # Prefer a local git remote named 'upstream' if it exists.
    # This matches the common pattern: origin = fork, upstream = canonical repo.
    UPSTREAM_REPO=""
    if git remote get-url upstream >/dev/null 2>&1; then
        UPSTREAM_URL=$(git remote get-url upstream)

        # Support both HTTPS and SSH GitHub URLs:
        #   https://github.com/owner/repo.git
        #   git@github.com:owner/repo.git
        if [[ "$UPSTREAM_URL" =~ github.com[:/]+([^/]+)/([^/.]+)(\.git)?$ ]]; then
            UPSTREAM_OWNER="${BASH_REMATCH[1]}"
            UPSTREAM_NAME="${BASH_REMATCH[2]}"
            UPSTREAM_REPO="${UPSTREAM_OWNER}/${UPSTREAM_NAME}"
            print_info "Detected upstream from git remote: ${UPSTREAM_REPO}"
        else
            print_warning "Could not parse upstream remote URL: ${UPSTREAM_URL}"
        fi
    fi

    # Fallback: try GitHub's notion of a fork parent.
    if [ -z "$UPSTREAM_REPO" ]; then
        UPSTREAM_REPO=$(gh repo view --json parent -q .parent.nameWithOwner 2>/dev/null || echo "")
        if [ -n "$UPSTREAM_REPO" ]; then
            print_info "Detected upstream from GitHub parent: ${UPSTREAM_REPO}"
        fi
    fi

    # Last resort: ask the user.
    if [ -z "$UPSTREAM_REPO" ]; then
        print_warning "Unable to automatically determine upstream repository."
        read -p "Enter upstream repository (e.g., owner/repo): " UPSTREAM_REPO

        if [ -z "$UPSTREAM_REPO" ]; then
            print_error "Upstream repository is required"
            exit 1
        fi
    fi

    print_success "Using upstream repository: ${UPSTREAM_REPO}"

    # Extract owner and repo name
    UPSTREAM_OWNER=$(echo "$UPSTREAM_REPO" | cut -d'/' -f1)
    UPSTREAM_NAME=$(echo "$UPSTREAM_REPO" | cut -d'/' -f2)

    # Safety check: never operate directly on the upstream repository.
    if [ "$CURRENT_REPO" = "$UPSTREAM_REPO" ]; then
        print_error "Refusing to run against upstream repository: ${UPSTREAM_REPO}"
        print_info "This script must be run in your fork, not in the upstream clone."
        print_info "Current repository: ${CURRENT_REPO}"
        exit 1
    fi

    export CURRENT_REPO UPSTREAM_REPO UPSTREAM_OWNER UPSTREAM_NAME
}

# Configure AI provider
configure_ai_provider() {
    print_header "AI Provider Configuration"

    print_info "This script will use Claude via GitHub's provisioned API key"
    print_info "Checking for ANTHROPIC_API_KEY in repository secrets..."

    # Check if secret exists (this will fail silently if not)
    if gh secret list | grep -q "ANTHROPIC_API_KEY"; then
        print_success "ANTHROPIC_API_KEY secret found"
        USE_EXISTING_KEY="true"
    else
        print_warning "ANTHROPIC_API_KEY not found in repository secrets"
        print_info "We'll configure the workflow to use GitHub's Claude integration"
        USE_EXISTING_KEY="false"

        read -p "Do you want to add your own Anthropic API key as a backup? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            read -sp "Enter your Anthropic API key (will be hidden): " API_KEY
            echo
            if [ -n "$API_KEY" ]; then
                echo "$API_KEY" | gh secret set ANTHROPIC_API_KEY
                print_success "ANTHROPIC_API_KEY secret set"
                USE_EXISTING_KEY="true"
            fi
        fi
    fi

    export USE_EXISTING_KEY
}

# Create directory structure
create_directories() {
    print_header "Creating Directory Structure"

    mkdir -p "$WORKFLOWS_DIR"
    print_success "Created $WORKFLOWS_DIR"

    mkdir -p "$INSTRUCTIONS_DIR"
    print_success "Created $INSTRUCTIONS_DIR"
}

# Create issue sync workflow
create_issue_sync_workflow() {
    print_header "Creating Issue Sync Workflow"

    cat > "$WORKFLOWS_DIR/sync-upstream-issues.yml" << 'EOF'
name: Sync Upstream Issues

on:
  schedule:
    - cron: '0 */6 * * *'  # Run every 6 hours
  workflow_dispatch:  # Allow manual trigger

permissions:
  issues: write
  contents: read

jobs:
  sync-issues:
    runs-on: ubuntu-latest
    env:
      DRY_RUN: __DRY_RUN__
    steps:
      - uses: actions/checkout@v4

      - name: Fetch upstream issues
        id: fetch
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          UPSTREAM_REPO: __UPSTREAM_REPO__
        run: |
          echo "Fetching open issues from upstream..."

          # Create temp file for issues
          TEMP_FILE=$(mktemp)

          # Fetch open issues from upstream (max 100)
          gh api "repos/$UPSTREAM_REPO/issues" \
            --paginate \
            -X GET \
            -f state=open \
            -f per_page=100 \
            --jq '.[] | select(.pull_request == null) | {number, title, body, labels: [.labels[].name], created_at}' \
            > "$TEMP_FILE"

          echo "issues_file=$TEMP_FILE" >> $GITHUB_OUTPUT

          ISSUE_COUNT=$(wc -l < "$TEMP_FILE")
          echo "Found $ISSUE_COUNT open issues"
          echo "issue_count=$ISSUE_COUNT" >> $GITHUB_OUTPUT

      - name: Create or update issues in fork
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          UPSTREAM_REPO: __UPSTREAM_REPO__
        run: |
          ISSUES_FILE="${{ steps.fetch.outputs.issues_file }}"
          CREATED_COUNT=0
          SKIPPED_COUNT=0

          if [ ! -s "$ISSUES_FILE" ]; then
            echo "No issues to process"
            exit 0
          fi

          while IFS= read -r issue; do
            TITLE=$(echo "$issue" | jq -r '.title')
            BODY=$(echo "$issue" | jq -r '.body // "No description provided"')
            UPSTREAM_NUM=$(echo "$issue" | jq -r '.number')
            LABELS=$(echo "$issue" | jq -r '.labels | join(",")')
            CREATED_AT=$(echo "$issue" | jq -r '.created_at')
            TRACKING_LABEL="upstream-issue-$UPSTREAM_NUM"

            # Check if issue already exists in fork using tracking label
            EXISTING=$(gh issue list \
              --label "$TRACKING_LABEL" \
              --json number \
              --jq '.[0].number // empty')

            if [ -z "$EXISTING" ]; then
              echo "Creating issue for upstream #$UPSTREAM_NUM..."

              # Prepare issue body with upstream reference
              ISSUE_BODY="**Upstream Issue:** $UPSTREAM_REPO#$UPSTREAM_NUM
**Created:** $CREATED_AT
**Original Labels:** $LABELS

---

$BODY

---

*This issue was automatically synced from the upstream repository.*"

              if [ "$DRY_RUN" = "true" ]; then
                echo "[DRY-RUN] Would create issue for upstream #$UPSTREAM_NUM with labels: upstream,needs-triage,$TRACKING_LABEL"
              else
                # Create new issue
                gh issue create \
                  --title "Upstream #$UPSTREAM_NUM: $TITLE" \
                  --body "$ISSUE_BODY" \
                  --label upstream \
                  --label needs-triage \
                  --label "$TRACKING_LABEL" 2>/dev/null && {
                    CREATED_COUNT=$((CREATED_COUNT + 1))
                    echo "✓ Created issue for upstream #$UPSTREAM_NUM"
                  } || {
                    echo "⚠ Failed to create issue for upstream #$UPSTREAM_NUM"
                  }
              fi

              # Rate limiting - be nice to GitHub API
              sleep 2
            else
              SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
              echo "⊘ Issue already exists for upstream #$UPSTREAM_NUM (Fork #$EXISTING)"
            fi
          done < <(jq -c '.' "$ISSUES_FILE")

          echo ""
          echo "Summary:"
          echo "- Created: $CREATED_COUNT new issues"
          echo "- Skipped: $SKIPPED_COUNT existing issues"
          echo "- Total processed: ${{ steps.fetch.outputs.issue_count }}"
EOF

    # Replace placeholders
    sed -i.bak "s|__UPSTREAM_REPO__|$UPSTREAM_REPO|g" "$WORKFLOWS_DIR/sync-upstream-issues.yml"
    sed -i.bak "s|__DRY_RUN__|$DRY_RUN|g" "$WORKFLOWS_DIR/sync-upstream-issues.yml"
    rm -f "$WORKFLOWS_DIR/sync-upstream-issues.yml.bak"

    print_success "Created sync-upstream-issues.yml"
}

# Create triage agent workflow
create_triage_agent() {
    print_header "Creating Triage Agent Workflow"

    cat > "$WORKFLOWS_DIR/agent-triage.md" << 'EOF'
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
EOF

    print_success "Created agent-triage.md"

    # Create the trigger workflow
    cat > "$WORKFLOWS_DIR/trigger-triage-agent.yml" << 'EOF'
name: Trigger Triage Agent

on:
  issues:
    types: [labeled]

jobs:
  triage:
    if: github.event.label.name == 'needs-triage'
    runs-on: ubuntu-latest
    permissions:
      issues: write
      contents: read
    env:
      DRY_RUN: __DRY_RUN__

    steps:
      - uses: actions/checkout@v4

      - name: Run Triage Agent
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          ISSUE_NUMBER: ${{ github.event.issue.number }}
          ISSUE_TITLE: ${{ github.event.issue.title }}
          ISSUE_BODY: ${{ github.event.issue.body }}
        run: |
          echo "🤖 Triaging issue #$ISSUE_NUMBER..."

          # For now, this is a placeholder for the actual agent logic
          # When gh-aw is properly configured, this will run the agent

          # Basic triage logic as fallback
          COMPLEXITY="easy"
          TYPE="bug"

          # Detect type from title/body
          if echo "$ISSUE_TITLE" | grep -iq "feat\|feature"; then
            TYPE="feature"
          elif echo "$ISSUE_TITLE" | grep -iq "doc\|documentation"; then
            TYPE="documentation"
          elif echo "$ISSUE_TITLE" | grep -iq "perf\|performance"; then
            TYPE="performance"
          fi

          if [ "$DRY_RUN" = "true" ]; then
            echo "[DRY-RUN] Would label issue #$ISSUE_NUMBER with: $TYPE, complexity:$COMPLEXITY and remove needs-triage"
            echo "[DRY-RUN] Would add automated triage comment to issue #$ISSUE_NUMBER"
          else
            # Add labels
            gh issue edit "$ISSUE_NUMBER" \
              --add-label "$TYPE" \
              --add-label "complexity:$COMPLEXITY" \
              --remove-label "needs-triage"

            # Add analysis comment
            gh issue comment "$ISSUE_NUMBER" --body "## 🤖 Automated Triage

**Type:** $TYPE
**Complexity:** $COMPLEXITY

This issue has been automatically triaged. A human reviewer will assess if it's suitable for automated fixing.

*To enable full AI-powered triage, configure the agentic workflow with gh-aw.*"
          fi

          echo "✓ Triage complete (dry-run=$DRY_RUN)"
EOF

    # Replace placeholders
    sed -i.bak "s|__DRY_RUN__|$DRY_RUN|g" "$WORKFLOWS_DIR/trigger-triage-agent.yml"
    rm -f "$WORKFLOWS_DIR/trigger-triage-agent.yml.bak"

    print_success "Created trigger-triage-agent.yml"
}

# Create fix agent workflow
create_fix_agent() {
    print_header "Creating Fix Agent Workflow"

    cat > "$WORKFLOWS_DIR/agent-fix-issue.md" << 'EOF'
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
EOF

    print_success "Created agent-fix-issue.md"

    # Create trigger workflow
    cat > "$WORKFLOWS_DIR/trigger-fix-agent.yml" << 'EOF'
name: Trigger Fix Agent

on:
  issues:
    types: [labeled]
  workflow_dispatch:
    inputs:
      issue_number:
        description: 'Issue number to fix'
        required: true
        type: number

jobs:
  fix:
    if: github.event.label.name == 'agent-fix' || github.event_name == 'workflow_dispatch'
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write
      pull-requests: write
    env:
      DRY_RUN: __DRY_RUN__

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set Issue Number
        id: issue
        run: |
          if [ "${{ github.event_name }}" == "workflow_dispatch" ]; then
            echo "number=${{ github.event.inputs.issue_number }}" >> $GITHUB_OUTPUT
          else
            echo "number=${{ github.event.issue.number }}" >> $GITHUB_OUTPUT
          fi

      - name: Get Issue Details
        id: issue_details
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          ISSUE_DATA=$(gh issue view ${{ steps.issue.outputs.number }} --json title,body,labels)
          echo "title=$(echo "$ISSUE_DATA" | jq -r '.title')" >> $GITHUB_OUTPUT
          echo "body=$(echo "$ISSUE_DATA" | jq -r '.body')" >> $GITHUB_OUTPUT

      - name: Add Starting Comment
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          if [ "$DRY_RUN" = "true" ]; then
            echo "[DRY-RUN] Would add 'Agent Fix Started' comment to issue #${{ steps.issue.outputs.number }}"
            exit 0
          fi

          gh issue comment ${{ steps.issue.outputs.number }} --body "🤖 **Agent Fix Started**

I'm working on this issue. Will update with progress.

- [ ] Analyze issue
- [ ] Locate relevant code
- [ ] Implement fix
- [ ] Run tests
- [ ] Create pull request

*This is an automated fix attempt. Human review will be required before merging.*"

      - name: Run Fix Agent
        id: fix
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          ISSUE_NUMBER: ${{ steps.issue.outputs.number }}
          ISSUE_TITLE: ${{ steps.issue_details.outputs.title }}
          ISSUE_BODY: ${{ steps.issue_details.outputs.body }}
        run: |
          echo "🤖 Running fix agent for issue #$ISSUE_NUMBER..."

          # This is a placeholder for actual agent logic
          # When gh-aw is configured, it will execute the markdown workflow

          echo "⚠️  Full AI-powered fixing requires gh-aw configuration"
          echo "For now, creating a template branch and PR..."

          # Create branch (use different prefix in dry-run to be explicit)
          if [ "$DRY_RUN" = "true" ]; then
            BRANCH_NAME="dryrun/fix/issue-$ISSUE_NUMBER"
          else
            BRANCH_NAME="fix/issue-$ISSUE_NUMBER"
          fi
          git checkout -b "$BRANCH_NAME"

          # Create a placeholder commit
          mkdir -p .github/agent-work
          cat > .github/agent-work/fix-$ISSUE_NUMBER.md << FIXEOF
# Fix for Issue #$ISSUE_NUMBER

## Issue Title
$ISSUE_TITLE

## Analysis
This is a placeholder. The actual fix should be implemented here.

## TODO
- [ ] Analyze the issue thoroughly
- [ ] Locate the relevant code
- [ ] Implement the fix
- [ ] Write tests
- [ ] Verify all tests pass

## Next Steps
A human developer should review this issue and implement the fix.
FIXEOF

          git add .github/agent-work/fix-$ISSUE_NUMBER.md
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git commit -m "chore: agent fix template for issue #$ISSUE_NUMBER"

          if [ "$DRY_RUN" = "true" ]; then
            echo "[DRY-RUN] Would push branch '$BRANCH_NAME' to origin"
          else
            git push -u origin "$BRANCH_NAME"
          fi

          echo "branch=$BRANCH_NAME" >> $GITHUB_OUTPUT

      - name: Create Pull Request
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          BRANCH_NAME: ${{ steps.fix.outputs.branch }}
        run: |
          if [ "$DRY_RUN" = "true" ]; then
            echo "[DRY-RUN] Would create draft PR from branch '$BRANCH_NAME' with title:"
            echo "  fix: ${{ steps.issue_details.outputs.title }} (#${{ steps.issue.outputs.number }})"
            exit 0
          fi

          gh pr create \
            --repo "$GITHUB_REPOSITORY" \
            --head "$BRANCH_NAME" \
            --title "fix: ${{ steps.issue_details.outputs.title }} (#${{ steps.issue.outputs.number }})" \
            --body "## Description
This PR was automatically created by the fix agent.

## Related Issue
Fixes #${{ steps.issue.outputs.number }}

## Status
⚠️ **This is a template PR**

To enable full automated fixing:
1. Install and configure gh-aw extension
2. Configure Claude API integration
3. Re-run the fix agent workflow

## What to do now
A human developer should:
1. Review the issue
2. Implement the actual fix in this branch
3. Update this PR description
4. Request review when ready

## Checklist
- [ ] Actual fix implemented
- [ ] Tests added/updated
- [ ] All tests passing
- [ ] Documentation updated if needed
- [ ] Ready for review" \
            --label automated-fix \
            --label needs-human-review \
            --draft

      - name: Update Issue
        if: always()
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          if [ "$DRY_RUN" = "true" ]; then
            echo "[DRY-RUN] Would update issue #${{ steps.issue.outputs.number }} with success/failure comment and labels"
            exit 0
          fi

          if [ "${{ job.status }}" == "success" ]; then
            gh issue comment ${{ steps.issue.outputs.number }} --body "✅ **Agent Fix Complete**

Created draft PR with branch \`${{ steps.fix.outputs.branch }}\`

⚠️ This is a template. A human developer needs to implement the actual fix.

To enable full AI-powered fixing, configure the gh-aw extension with Claude integration."
          else
            gh issue comment ${{ steps.issue.outputs.number }} --body "❌ **Agent Fix Failed**

The automated fix attempt encountered an error. A human developer should investigate.

Please review the [workflow run](${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}) for details."

            gh issue edit ${{ steps.issue.outputs.number }} \
              --remove-label "agent-fix" \
              --add-label "needs-human-review"
          fi
EOF

    # Replace placeholders
    sed -i.bak "s|__DRY_RUN__|$DRY_RUN|g" "$WORKFLOWS_DIR/trigger-fix-agent.yml"
    rm -f "$WORKFLOWS_DIR/trigger-fix-agent.yml.bak"

    print_success "Created trigger-fix-agent.yml"
}

# Create PR agent workflow
create_pr_agent() {
    print_header "Creating PR Creation Agent Workflow"

    cat > "$WORKFLOWS_DIR/agent-create-upstream-pr.md" << 'EOF'
# Agent: Create Upstream PR

This agent creates a pull request to the upstream repository after a fix has been reviewed and approved in the fork.

## Inputs
- `pr_number`: The PR number in our fork that contains the fix (required)

## Context
- Fork repository with approved PR
- Upstream repository to contribute to
- Branch with tested and reviewed changes

## Objective
Create a well-formatted pull request to the upstream repository, ensuring all changes are properly documented and tested.

## Process

### Step 1: Verify Fork PR Status
- Check that the PR exists and is approved
- Verify all checks have passed
- Confirm no pending change requests
- Ensure branch is up to date with fork's main branch

Requirements:
- At least one approval
- All CI checks passing
- No merge conflicts
- No draft status

### Step 2: Get PR Details
Extract from fork PR:
- Title
- Description
- Linked issue numbers
- Changes made
- Test results
- List of commits

### Step 3: Identify Upstream Issue
- Find the original upstream issue reference
- Verify the issue still exists and is open
- Check if issue has been closed or already fixed
- Ensure issue still describes the same problem

### Step 4: Sync Fork with Upstream
```bash
# Add upstream remote if not exists
git remote add upstream https://github.com/UPSTREAM_OWNER/REPO_NAME.git

# Fetch latest changes
git fetch upstream

# Check if our changes conflict with upstream
git merge-base --is-ancestor upstream/main HEAD
```

If conflicts exist:
- Rebase the branch on upstream/main
- Resolve conflicts
- Re-run tests
- Update fork PR

### Step 5: Prepare Upstream Branch
```bash
# Create a clean branch from upstream/main
git checkout -b upstream-pr-{upstream_issue_number} upstream/main

# Cherry-pick commits from fork PR
git cherry-pick {commit_range}

# Or merge squashed
git merge --squash {fork_branch}
git commit
```

### Step 6: Push to Fork
```bash
# Push to our fork with upstream-targeted branch
git push origin upstream-pr-{upstream_issue_number}
```

### Step 7: Create Upstream PR Description
Format the PR description for upstream:

```markdown
## Description
[Clear description of what this PR does]

## Related Issue
Fixes #{upstream_issue_number}

## Motivation and Context
[Why this change is needed and what problem it solves]

## Changes Made
- [Detailed list of changes]
- [Be specific about what was modified]

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
### Test Environment
- [Describe test environment]

### Test Cases
- [ ] [Test case 1]
- [ ] [Test case 2]

### Test Results
```
[Paste relevant test output]
```

## Screenshots (if applicable)
[Add screenshots if the change affects UI]

## Checklist
- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] Any dependent changes have been merged and published

## Additional Notes
[Any additional information reviewers should know]

---
*This PR was created from a fork. Original work done in [FORK_OWNER/REPO#PR_NUMBER].*
```

### Step 8: Create Upstream PR
```bash
gh pr create \
  --repo UPSTREAM_OWNER/REPO_NAME \
  --base main \
  --head FORK_OWNER:upstream-pr-{issue_number} \
  --title "{type}: {description} (#{issue_number})" \
  --body "{formatted_description}"
```

Title format:
- `fix: description (#123)` for bug fixes
- `feat: description (#123)` for features
- `docs: description (#123)` for documentation

### Step 9: Link PRs
- Add comment to fork PR with upstream PR link
- Add comment to upstream PR referencing fork PR
- Update fork PR labels: add `upstream-pr-created`
- Link to upstream issue in both PRs

### Step 10: Monitor Upstream PR
- Add comment to fork PR about what to watch for
- Notify about any CI failures in upstream
- Be ready to make requested changes

## Tools Available
- `gh pr view`: View PR details
- `gh pr create`: Create pull request
- `gh pr comment`: Add comments
- `gh issue view`: View issue details
- `git`: Version control operations

## Success Criteria
- [ ] Fork PR is approved and passing all checks
- [ ] Upstream branch created and pushed
- [ ] Upstream PR created successfully
- [ ] All links between PRs/issues are established
- [ ] Description is clear and comprehensive
- [ ] All commits are clean and well-formatted
- [ ] Tests passing in upstream PR

## Communication
Update fork PR with:
```markdown
🚀 **Upstream PR Created**

This fix has been submitted to the upstream repository:
- **Upstream PR:** UPSTREAM_OWNER/REPO#123
- **Upstream Issue:** UPSTREAM_OWNER/REPO#456

## Next Steps
1. Monitor the upstream PR for reviewer feedback
2. Be ready to make requested changes
3. Update this fork PR if upstream requires modifications

## For Maintainers
If upstream requests changes:
1. Make changes in this branch
2. Push to update this PR
3. Cherry-pick/rebase to upstream branch
4. Force push to update upstream PR

Thank you for contributing to the upstream project! 🎉
```

## Error Handling

### Fork PR Not Ready
- Add comment explaining requirements
- Add `upstream-blocked` label
- List what needs to be fixed

### Upstream Conflicts
- Create issue in fork documenting conflicts
- Add `needs-rebase` label
- Provide instructions for resolving

### Upstream PR Creation Fails
- Document error in fork PR
- Add `upstream-pr-failed` label
- Provide manual instructions

### Upstream Already Fixed
- Close fork PR with explanation
- Reference upstream fix
- Thank contributor for effort

## Quality Checks Before Submission
- [ ] Commits are clean and follow conventions
- [ ] No merge commits (use rebase if needed)
- [ ] No "fix typo" or "oops" commits
- [ ] Commit messages are descriptive
- [ ] No debug code or console.logs
- [ ] No commented-out code
- [ ] All tests passing
- [ ] Documentation updated
- [ ] CHANGELOG updated if required by project

## Squashing Commits (if needed)
Some projects prefer squashed commits:
```bash
git rebase -i upstream/main
# Mark commits as 'squash' or 'fixup'
# Edit combined commit message
git push --force-with-lease
```

## Best Practices
- Keep upstream PRs focused and small
- Follow upstream project's contribution guidelines
- Respect upstream maintainers' time
- Respond promptly to feedback
- Be professional and courteous
- Credit original issue reporters
- Thank reviewers
EOF

    print_success "Created agent-create-upstream-pr.md"

    # Create trigger workflow
    cat > "$WORKFLOWS_DIR/trigger-upstream-pr.yml" << 'EOF'
name: Create Upstream PR

on:
  workflow_dispatch:
    inputs:
      pr_number:
        description: 'Fork PR number to submit upstream'
        required: true
        type: number
  pull_request_review:
    types: [submitted]

jobs:
  create-upstream-pr:
    # Only run if PR is approved or manually triggered
    if: |
      github.event_name == 'workflow_dispatch' ||
      (github.event.review.state == 'approved' &&
       contains(github.event.pull_request.labels.*.name, 'ready-for-upstream'))

    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
      issues: write
    env:
      DRY_RUN: __DRY_RUN__

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set PR Number
        id: pr
        run: |
          if [ "${{ github.event_name }}" == "workflow_dispatch" ]; then
            echo "number=${{ github.event.inputs.pr_number }}" >> $GITHUB_OUTPUT
          else
            echo "number=${{ github.event.pull_request.number }}" >> $GITHUB_OUTPUT
          fi

      - name: Get Fork PR Details
        id: fork_pr
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          PR_DATA=$(gh pr view ${{ steps.pr.outputs.number }} --json title,body,headRefName,state,reviews,statusCheckRollup)

          echo "title=$(echo "$PR_DATA" | jq -r '.title')" >> $GITHUB_OUTPUT
          echo "body=$(echo "$PR_DATA" | jq -r '.body')" >> $GITHUB_OUTPUT
          echo "branch=$(echo "$PR_DATA" | jq -r '.headRefName')" >> $GITHUB_OUTPUT
          echo "state=$(echo "$PR_DATA" | jq -r '.state')" >> $GITHUB_OUTPUT

          # Check if approved
          APPROVED=$(echo "$PR_DATA" | jq '[.reviews // [] | .[] | select(.state == "APPROVED")] | length')
          echo "approved=$APPROVED" >> $GITHUB_OUTPUT

          # Check if checks passed
          CHECKS_PASSED=$(echo "$PR_DATA" | jq '[.statusCheckRollup // [] | .[] | select(.conclusion == "SUCCESS" or .conclusion == "NEUTRAL")] | length')
          echo "checks_passed=$CHECKS_PASSED" >> $GITHUB_OUTPUT

      - name: Verify PR is Ready
        env:
          APPROVED: ${{ steps.fork_pr.outputs.approved }}
          STATE: ${{ steps.fork_pr.outputs.state }}
        run: |
          if [ "$STATE" != "OPEN" ]; then
            echo "❌ PR is not open"
            exit 1
          fi

          if [ "$APPROVED" -lt 1 ] && [ "${{ github.event_name }}" != "workflow_dispatch" ]; then
            echo "❌ PR needs at least one approval"
            exit 1
          fi

          echo "✅ PR is ready for upstream submission"

      - name: Extract Upstream Issue
        id: upstream
        env:
          PR_BODY: ${{ steps.fork_pr.outputs.body }}
        run: |
          # Extract upstream issue reference (e.g., "Upstream Issue: owner/repo#123")
          UPSTREAM_REF=$(echo "$PR_BODY" | grep -oP 'Upstream Issue:\s*\K[^\s]+' || echo "")

          if [ -z "$UPSTREAM_REF" ]; then
            # Try to extract from title (e.g., "Upstream #123:")
            UPSTREAM_NUM=$(echo "${{ steps.fork_pr.outputs.title }}" | grep -oP 'Upstream #\K\d+' || echo "")
            if [ -n "$UPSTREAM_NUM" ]; then
              UPSTREAM_REF="__UPSTREAM_REPO__#$UPSTREAM_NUM"
            fi
          fi

          if [ -z "$UPSTREAM_REF" ]; then
            echo "❌ Could not find upstream issue reference"
            exit 1
          fi

          echo "reference=$UPSTREAM_REF" >> $GITHUB_OUTPUT
          echo "Found upstream reference: $UPSTREAM_REF"

      - name: Setup Git
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"

      - name: Add Upstream Remote
        run: |
          git remote add upstream https://github.com/__UPSTREAM_REPO__.git || true
          git fetch upstream

      - name: Create Upstream Branch
        id: upstream_branch
        env:
          FORK_BRANCH: ${{ steps.fork_pr.outputs.branch }}
        run: |
          UPSTREAM_BRANCH="upstream-pr-${{ steps.pr.outputs.number }}"

          if [ "$DRY_RUN" = "true" ]; then
            echo "[DRY-RUN] Would rebase '$FORK_BRANCH' on upstream/main and push '$UPSTREAM_BRANCH' to origin"
            echo "branch=$UPSTREAM_BRANCH" >> $GITHUB_OUTPUT
            exit 0
          fi

          # Checkout fork branch
          git checkout "$FORK_BRANCH"

          # Rebase on upstream main
          git rebase upstream/main || {
            echo "❌ Rebase failed - conflicts with upstream"
            git rebase --abort
            exit 1
          }

          # Create new branch for upstream
          git checkout -b "$UPSTREAM_BRANCH"
          git push origin "$UPSTREAM_BRANCH" --force

          echo "branch=$UPSTREAM_BRANCH" >> $GITHUB_OUTPUT

      - name: Prepare Upstream PR Body
        id: pr_body
        env:
          FORK_PR_BODY: ${{ steps.fork_pr.outputs.body }}
          UPSTREAM_REF: ${{ steps.upstream.outputs.reference }}
        run: |
          cat > upstream_pr_body.md << 'UPSTREAMEOF'
## Description
This PR addresses ${{ steps.upstream.outputs.reference }}

${{ steps.fork_pr.outputs.body }}

## Testing
All tests have been run and are passing in the fork.

## Checklist
- [x] Code follows project style guidelines
- [x] Self-review completed
- [x] Tests added/updated
- [x] All tests passing
- [x] Documentation updated if needed

---
*This contribution was developed and tested in a fork: ${{ github.repository }}#${{ steps.pr.outputs.number }}*
UPSTREAMEOF

          echo "body<<UPSTREAMEOF" >> $GITHUB_OUTPUT
          cat upstream_pr_body.md >> $GITHUB_OUTPUT
          echo "UPSTREAMEOF" >> $GITHUB_OUTPUT

      - name: Create Upstream PR (Dry Run)
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          UPSTREAM_BRANCH: ${{ steps.upstream_branch.outputs.branch }}
          PR_TITLE: ${{ steps.fork_pr.outputs.title }}
        run: |
          echo "🚀 Would create upstream PR with:"
          echo "Repository: __UPSTREAM_REPO__"
          echo "Base: main"
          echo "Head: ${{ github.repository_owner }}:$UPSTREAM_BRANCH"
          echo "Title: $PR_TITLE"
          echo ""
          echo "⚠️  Dry run mode - not actually creating PR"
          echo "To create real upstream PR, you need to:"
          echo "1. Ensure you have write access to push branches"
          echo "2. Run this command manually:"
          echo ""
          echo "gh pr create \\"
          echo "  --repo __UPSTREAM_REPO__ \\"
          echo "  --base main \\"
          echo "  --head ${{ github.repository_owner }}:$UPSTREAM_BRANCH \\"
          echo "  --title \"$PR_TITLE\" \\"
          echo "  --body-file upstream_pr_body.md"

      - name: Update Fork PR
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          if [ "$DRY_RUN" = "true" ]; then
            echo "[DRY-RUN] Would comment on fork PR #${{ steps.pr.outputs.number }} and add 'ready-for-upstream' label"
            exit 0
          fi

          gh pr comment ${{ steps.pr.outputs.number }} --body "🚀 **Ready for Upstream Submission**

Branch \`${{ steps.upstream_branch.outputs.branch }}\` has been prepared and rebased on upstream/main.

## Next Steps
To create the upstream PR, run:
\`\`\`bash
gh pr create \\
  --repo __UPSTREAM_REPO__ \\
  --base main \\
  --head ${{ github.repository_owner }}:${{ steps.upstream_branch.outputs.branch }} \\
  --title \"${{ steps.fork_pr.outputs.title }}\" \\
  --body-file upstream_pr_body.md
\`\`\`

Or use the GitHub web interface to create a PR from the branch.

⚠️ Automated PR creation requires additional permissions and configuration."

          gh pr edit ${{ steps.pr.outputs.number }} --add-label "ready-for-upstream"
EOF

    # Replace placeholders
    sed -i.bak "s|__UPSTREAM_REPO__|$UPSTREAM_REPO|g" "$WORKFLOWS_DIR/trigger-upstream-pr.yml"
    sed -i.bak "s|__DRY_RUN__|$DRY_RUN|g" "$WORKFLOWS_DIR/trigger-upstream-pr.yml"
    rm -f "$WORKFLOWS_DIR/trigger-upstream-pr.yml.bak"

    print_success "Created trigger-upstream-pr.yml"
}

# Create README with instructions
create_readme() {
    print_header "Creating Documentation"

    cat > "AGENTIC_WORKFLOWS_README.md" << 'EOF'
# Agentic Workflows Setup

This repository has been configured with automated agent workflows for handling issues from the upstream repository.

## Workflows Installed

### 1. Sync Upstream Issues (`sync-upstream-issues.yml`)
- **Runs:** Every 6 hours (scheduled) or manually
- **Purpose:** Fetches open issues from upstream and creates them in this fork
- **Labels added:** `upstream`, `needs-triage`

**Manual trigger (fork only):**
```bash
gh workflow run sync-upstream-issues.yml --repo <your-fork-owner>/<your-fork-repo>
```

### 2. Triage Agent (`agent-triage.md` + `trigger-triage-agent.yml`)
- **Runs:** When issue is labeled with `needs-triage`
- **Purpose:** Analyzes issue complexity, type, and determines if auto-fixable
- **Outputs:** Adds labels like `bug`, `feature`, `complexity:easy`, `agent-fix`

### 3. Fix Agent (`agent-fix-issue.md` + `trigger-fix-agent.yml`)
- **Runs:** When issue is labeled with `agent-fix` or manually triggered
- **Purpose:** Attempts to automatically fix the issue
- **Outputs:** Creates branch and draft PR with fix

**Manual trigger (fork only):**
```bash
gh workflow run trigger-fix-agent.yml -f issue_number=42 --repo <your-fork-owner>/<your-fork-repo>
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
Configured upstream: __UPSTREAM_REPO__

To change:
1. Edit `.github/workflows/sync-upstream-issues.yml`
2. Edit `.github/workflows/trigger-upstream-pr.yml`
3. Replace `__UPSTREAM_REPO__` with new upstream

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
EOF

    # Replace placeholder
    sed -i.bak "s|__UPSTREAM_REPO__|$UPSTREAM_REPO|g" "AGENTIC_WORKFLOWS_README.md"
    rm -f "AGENTIC_WORKFLOWS_README.md.bak"

    print_success "Created AGENTIC_WORKFLOWS_README.md"
}

# Commit and push changes
commit_and_push() {
    print_header "Committing Changes"

    read -p "Do you want to commit and push these changes? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_warning "Skipping commit. Changes are staged but not committed."
        return
    fi

    # Stage changes
    git add .github/ AGENTIC_WORKFLOWS_README.md

    # Commit
    git commit -m "feat: add agentic workflows for automated issue handling

- Add upstream issue sync workflow (runs every 6 hours)
- Add triage agent for automatic issue analysis
- Add fix agent for automated issue resolution
- Add upstream PR creation agent
- Add comprehensive documentation

These workflows enable automated handling of upstream issues with
human oversight and approval before submission."

    print_success "Changes committed"

    # Push
    read -p "Push to remote? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        CURRENT_BRANCH=$(git branch --show-current)
        git push -u origin "$CURRENT_BRANCH"
        print_success "Changes pushed to $CURRENT_BRANCH"
    fi
}

# Test workflows
test_workflows() {
    print_header "Testing Workflows"

    print_info "You can test the workflows manually:"
    echo ""
    echo "1. Test issue sync:"
    echo "   gh workflow run sync-upstream-issues.yml --repo $CURRENT_REPO"
    echo ""
    echo "2. Create a test issue and add 'needs-triage' label:"
    echo "   gh issue create --title 'Test issue' --label needs-triage"
    echo ""
    echo "3. Manually trigger fix agent:"
    echo "   gh workflow run trigger-fix-agent.yml -f issue_number=ISSUE_NUMBER --repo $CURRENT_REPO"
    echo ""

    read -p "Run sync workflow now to test? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "Triggering sync workflow..."
        gh workflow run sync-upstream-issues.yml --repo "$CURRENT_REPO"
        print_success "Workflow triggered. Check status with: gh run list --repo $CURRENT_REPO"
    fi
}

# Print summary
print_summary() {
    print_header "Setup Complete! 🎉"

    cat << EOF
${GREEN}Agentic workflows have been configured successfully!${NC}

${BLUE}What was installed:${NC}
✓ Issue sync workflow (scheduled every 6 hours)
✓ Triage agent workflow
✓ Fix agent workflow
✓ Upstream PR creation workflow
✓ Comprehensive documentation

${BLUE}Next steps:${NC}
1. Review the created files in .github/workflows/
2. Read AGENTIC_WORKFLOWS_README.md for usage instructions
3. Test the workflows (fork only):
   ${YELLOW}gh workflow run sync-upstream-issues.yml --repo ${CURRENT_REPO}${NC}
4. Monitor workflow runs:
   ${YELLOW}gh run list --repo ${CURRENT_REPO}${NC}

${BLUE}Quick commands (fork only):${NC}
• Sync issues now:     ${YELLOW}gh workflow run sync-upstream-issues.yml --repo ${CURRENT_REPO}${NC}
• View all issues:     ${YELLOW}gh issue list --label upstream --repo ${CURRENT_REPO}${NC}
• Trigger fix agent:   ${YELLOW}gh workflow run trigger-fix-agent.yml -f issue_number=N --repo ${CURRENT_REPO}${NC}
• View workflow runs:  ${YELLOW}gh run list --repo ${CURRENT_REPO}${NC}

${BLUE}Configuration:${NC}
• Upstream: ${GREEN}${UPSTREAM_REPO}${NC}
• AI Provider: ${GREEN}Claude (via GitHub)${NC}
• Sync Schedule: ${GREEN}Every 6 hours${NC}

${YELLOW}⚠️  Important:${NC}
- Review all automated PRs before merging
- Human approval required for upstream submissions
- Monitor Actions usage to stay within limits

${BLUE}Documentation:${NC}
Read AGENTIC_WORKFLOWS_README.md for detailed information.

Happy automating! 🤖
EOF
}

# Main execution
main() {
    print_header "Agentic Workflows Setup Script"

    check_prerequisites
    select_mode
    get_repo_info
    configure_ai_provider
    create_directories
    create_issue_sync_workflow
    create_triage_agent
    create_fix_agent
    create_pr_agent
    create_readme
    commit_and_push
    test_workflows
    print_summary
}

# Run main function
main "$@"
