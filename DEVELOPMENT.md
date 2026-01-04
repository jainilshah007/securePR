# Development Log

Detailed step-by-step build process for SecurePR.

---

## Step 1: Basic Workflow Setup
Created `.github/workflows/security-scan.yml` with:
- Trigger on push to main
- Ubuntu runner
- Basic job structure

## Step 2: Display Commit Info
Added workflow steps to show:
- Repository and branch using `${{ github.repository }}`
- Commit author via `git log -1 --format='%an'`
- Changed files via `git diff-tree`

## Step 3: Python Environment
```yaml
- uses: actions/setup-python@v4
  with:
    python-version: '3.11'
- run: pip install openai
```

## Step 4: Security Analyzer Script
Created `scripts/analyze_security.py`:
- Accepts git diff from stdin
- Calls OpenAI GPT-4 API
- Parses JSON response
- Formats as markdown

## Step 5: Security Prompt Engineering
Designed prompt with:
- 8 vulnerability categories (SQL injection, XSS, etc.)
- CWE/OWASP references
- Guidelines to avoid false positives
- Structured JSON output format
- Example of good analysis

## Step 6: Output Formatting
Added markdown formatting:
- Summary table with severity counts
- Emoji indicators (🔴🟠🟡🟢)
- Collapsible `<details>` sections
- Attack scenarios and fixes

## Step 7: Caching System
Implemented to reduce API costs:
- SHA-256 hash of diff content
- Store results in `/tmp/.securePR_cache/`
- Skip API calls for duplicate diffs

## Step 8: Confidence Filtering
Added to reduce false positives:
- Request numeric confidence (0-100) from GPT-4
- Default threshold: 70%
- Filter out low-confidence findings

## Step 9: Pull Request Triggers
Changed workflow to run on PRs:
```yaml
on:
  pull_request:
    types: [opened, synchronize, reopened]
```

Key changes:
- `fetch-depth: 0` for full git history
- Compare base branch with PR head: `git diff base...head`
- Display PR number, title, author
- Handle PRs from forks (secrets limitation noted)

## Step 10: PR Comment Integration
Created `scripts/post_pr_comment.py`:
- Uses PyGithub to interact with GitHub API
- Posts security results as PR comments
- Updates existing comments (avoids duplicates)
- Uses `<!-- securePR-bot-comment -->` marker to identify our comments
- Handles errors (no permission, rate limits)

Workflow changes:
- Added `pull-requests: write` permission
- Added `PyGithub` dependency
- Captures analysis output to `/tmp/security_results.md`
- Calls `post_pr_comment.py` after analysis

---

## Git Commands Reference

| Command | Purpose |
|---------|---------|
| `git diff-tree --name-only HEAD` | Files in last commit |
| `git diff base...head` | Changes in PR only |
| `git log -1 --format='%an'` | Commit author name |
| `fetch-depth: 0` | Clone full history |
| `fetch-depth: 2` | Clone last 2 commits |
