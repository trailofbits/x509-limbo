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
