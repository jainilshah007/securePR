#!/usr/bin/env python3
"""
Post security analysis results as a professional PR comment.
Uses GitHub API to create or update comments.
"""

import os
import sys
import re
import argparse
from datetime import datetime
from github import Github, GithubException

# Unique marker to identify our bot's comments
BOT_MARKER = "<!-- securePR-bot-comment -->"

# Repository URLs
REPO_URL = "https://github.com/jainilshah007/securePR"
DOCS_URL = f"{REPO_URL}#readme"
ISSUES_URL = f"{REPO_URL}/issues/new?labels=false-positive&title=False+Positive+Report"


def get_github_client():
    """Initialize GitHub client with token."""
    token = os.environ.get('GITHUB_TOKEN')
    if not token:
        print("::error::GITHUB_TOKEN environment variable not set.")
        sys.exit(1)
    return Github(token)


def find_existing_comment(pr, marker=BOT_MARKER):
    """Find existing bot comment on the PR."""
    try:
        for comment in pr.get_issue_comments():
            if marker in comment.body:
                return comment
    except GithubException as e:
        print(f"::warning::Could not fetch comments: {e}")
    return None


def parse_summary_from_content(content: str) -> dict:
    """Parse vulnerability counts from the markdown content."""
    summary = {
        'total': 0,
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'status': 'PASS'
    }
    
    # Try to parse counts from content
    patterns = {
        'critical': r'🔴 Critical[:\s|]+(\d+)',
        'high': r'🟠 High[:\s|]+(\d+)',
        'medium': r'🟡 Medium[:\s|]+(\d+)',
        'low': r'🟢 Low[:\s|]+(\d+)',
    }
    
    for key, pattern in patterns.items():
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            summary[key] = int(match.group(1))
    
    summary['total'] = summary['critical'] + summary['high'] + summary['medium'] + summary['low']
    
    # Determine status
    if summary['critical'] > 0 or summary['high'] > 0:
        summary['status'] = 'FAIL'
    elif summary['medium'] > 0 or summary['low'] > 0:
        summary['status'] = 'WARN'
    else:
        summary['status'] = 'PASS'
    
    return summary


def get_status_badge(status: str) -> str:
    """Generate shields.io style badge."""
    if status == 'FAIL':
        return "![Security](https://img.shields.io/badge/Security-FAILED-red?style=flat-square&logo=shield)"
    elif status == 'WARN':
        return "![Security](https://img.shields.io/badge/Security-WARNING-yellow?style=flat-square&logo=shield)"
    else:
        return "![Security](https://img.shields.io/badge/Security-PASSED-brightgreen?style=flat-square&logo=shield)"


def format_no_issues_comment(timestamp: str, commit_sha: str) -> str:
    """Format comment when no issues are found."""
    return f"""{BOT_MARKER}
<div align="center">

## 🔒 SecurePR Security Analysis

{get_status_badge('PASS')}

</div>

---

### ✅ All Clear!

**No security vulnerabilities detected in this PR.**

| | |
|---|---|
| 📅 **Scan Date** | `{timestamp}` |
| 🔗 **Commit** | `{commit_sha[:7]}` |
| 🎯 **Issues Found** | **0** |

---

<details>
<summary>💡 <b>Tips for maintaining security</b></summary>

<br>

- ✔️ Always validate and sanitize user input
- ✔️ Use parameterized queries to prevent SQL injection
- ✔️ Keep dependencies updated with `npm audit` or `pip-audit`
- ✔️ Never commit secrets or API keys to the repository
- ✔️ Review the [OWASP Top 10](https://owasp.org/Top10/) regularly

</details>

---

<sub>🤖 Powered by **[SecurePR]({REPO_URL})** — AI-powered security scanning for your PRs</sub>
"""


def format_issues_found_comment(content: str, summary: dict, timestamp: str, commit_sha: str) -> str:
    """Format comment when issues are found."""
    status = summary['status']
    total = summary['total']
    
    if status == 'FAIL':
        status_emoji = "❌"
        status_text = "Critical Issues Found"
        alert_box = """
> [!CAUTION]
> **This PR has critical security issues that must be fixed before merging.**
"""
    else:
        status_emoji = "⚠️"
        status_text = "Review Recommended"
        alert_box = """
> [!WARNING]
> **This PR has security issues that should be reviewed.**
"""

    # Build severity badges row
    severity_display = f"""
| 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low |
|:-----------:|:-------:|:---------:|:------:|
| **{summary['critical']}** | **{summary['high']}** | **{summary['medium']}** | **{summary['low']}** |
"""

    # Prioritization advice for many issues
    advice = ""
    if total > 5:
        advice = """
<details>
<summary>🎯 <b>Prioritization Guide</b></summary>

<br>

**Fix in this order:**
1. 🔴 **Critical** — Fix immediately, these are exploitable
2. 🟠 **High** — Fix before merging, significant risk
3. 🟡 **Medium** — Schedule for next sprint
4. 🟢 **Low** — Consider fixing when convenient

</details>

"""

    return f"""{BOT_MARKER}
<div align="center">

## 🔒 SecurePR Security Analysis

{get_status_badge(status)}

</div>

---

### {status_emoji} {status_text}

{alert_box}

| | |
|---|---|
| 📅 **Scan Date** | `{timestamp}` |
| 🔗 **Commit** | `{commit_sha[:7]}` |
| 🎯 **Issues Found** | **{total}** |

---

### 📊 Summary

{severity_display}

{advice}

---

<details>
<summary>🔍 <b>View Detailed Findings</b> ({total} issues)</summary>

<br>

{content}

</details>

---

<table>
<tr>
<td>💡 <b>Need help?</b></td>
<td><a href="{DOCS_URL}">Security Guide</a></td>
<td>🐛 <b>False positive?</b></td>
<td><a href="{ISSUES_URL}">Report it</a></td>
</tr>
</table>

<sub>🤖 Powered by **[SecurePR]({REPO_URL})** — AI-powered security scanning for your PRs</sub>
"""


def format_error_comment(error_msg: str, timestamp: str) -> str:
    """Format comment when analysis fails."""
    return f"""{BOT_MARKER}
<div align="center">

## 🔒 SecurePR Security Analysis

![Security](https://img.shields.io/badge/Security-ERROR-lightgrey?style=flat-square&logo=shield)

</div>

---

### ⚠️ Analysis Could Not Complete

The security scan encountered an error and could not complete.

**Error:** `{error_msg[:200]}`

**Scan Date:** `{timestamp}`

---

<details>
<summary>🔧 <b>Debugging Tips</b></summary>

<br>

1. **Check the Actions log** for detailed error messages
2. **Verify OPENAI_API_KEY** is set correctly in repository secrets
3. **For fork PRs**, secrets may not be available (GitHub security policy)
4. **If persistent**, [open an issue]({ISSUES_URL})

</details>

---

<sub>🤖 Powered by **[SecurePR]({REPO_URL})**</sub>
"""


def format_comment(content: str, has_vulnerabilities: bool, commit_sha: str = "unknown") -> str:
    """Format the comment based on content and status."""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Check for error conditions
    if "::error::" in content or "Error:" in content:
        error_match = re.search(r'(?:::error::|Error:)\s*(.+)', content)
        error_msg = error_match.group(1) if error_match else "Unknown error"
        return format_error_comment(error_msg, timestamp)
    
    # Parse summary from content
    summary = parse_summary_from_content(content)
    
    # No issues
    if not has_vulnerabilities and summary['total'] == 0:
        return format_no_issues_comment(timestamp, commit_sha)
    
    # Issues found
    return format_issues_found_comment(content, summary, timestamp, commit_sha)


def post_comment(repo_name: str, pr_number: int, content: str, has_vulnerabilities: bool):
    """Post or update a comment on the PR."""
    try:
        gh = get_github_client()
        repo = gh.get_repo(repo_name)
        pr = repo.get_pull(pr_number)
        
        # Get commit SHA
        commit_sha = pr.head.sha
        
        formatted_comment = format_comment(content, has_vulnerabilities, commit_sha)
        
        # Check for existing comment
        existing = find_existing_comment(pr)
        
        if existing:
            print(f"📝 Updating existing comment (ID: {existing.id})")
            existing.edit(formatted_comment)
            print("✅ Comment updated successfully")
        else:
            print("💬 Creating new comment")
            pr.create_issue_comment(formatted_comment)
            print("✅ Comment created successfully")
            
    except GithubException as e:
        if e.status == 403:
            print("::warning::No permission to post comment.")
            print("This may happen for PRs from forks.")
            print("Results are available in the Actions log.")
        elif e.status == 404:
            print(f"::error::PR #{pr_number} not found in {repo_name}")
            sys.exit(1)
        elif "rate limit" in str(e).lower():
            print("::error::GitHub API rate limit exceeded.")
            sys.exit(1)
        else:
            print(f"::error::GitHub API error: {e}")
            sys.exit(1)
    except Exception as e:
        print(f"::error::Failed to post comment: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Post security results as PR comment')
    parser.add_argument('--repo', required=True, help='Repository name (owner/repo)')
    parser.add_argument('--pr', type=int, required=True, help='PR number')
    parser.add_argument('--content-file', help='File containing markdown content')
    parser.add_argument('--content', help='Markdown content directly')
    parser.add_argument('--has-vulnerabilities', action='store_true', 
                        help='Flag if vulnerabilities were found')
    
    args = parser.parse_args()
    
    # Get content from file or argument
    if args.content_file:
        if not os.path.exists(args.content_file):
            print(f"::error::Content file not found: {args.content_file}")
            sys.exit(1)
        with open(args.content_file, 'r') as f:
            content = f.read()
    elif args.content:
        content = args.content
    else:
        # Read from stdin if no content provided
        if not sys.stdin.isatty():
            content = sys.stdin.read()
        else:
            print("::error::No content provided. Use --content, --content-file, or pipe stdin.")
            sys.exit(1)
    
    print(f"📤 Posting to {args.repo} PR #{args.pr}")
    post_comment(args.repo, args.pr, content, args.has_vulnerabilities)


if __name__ == "__main__":
    main()
