
import os
import sys
import argparse
from datetime import datetime
from github import Github, GithubException

# Unique marker to identify our bot's comments
BOT_MARKER = "<!-- securePR-bot-comment -->"


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


def format_comment(content: str, has_vulnerabilities: bool) -> str:
    """Format the comment with header and footer."""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    status_icon = "🚨" if has_vulnerabilities else "✅"
    status_text = "Vulnerabilities Detected" if has_vulnerabilities else "No Issues Found"
    
    comment = f"""{BOT_MARKER}
## {status_icon} SecurePR Security Analysis

**Status:** {status_text}  
**Analyzed:** {timestamp}

---

<details>
<summary>📋 Click to expand full report</summary>

{content}

</details>

---

<sub>🔒 Powered by [SecurePR](https://github.com/jainilshah007/securePR) | AI-powered security scanning</sub>
"""
    return comment


def post_comment(repo_name: str, pr_number: int, content: str, has_vulnerabilities: bool):
    """Post or update a comment on the PR."""
    try:
        gh = get_github_client()
        repo = gh.get_repo(repo_name)
        pr = repo.get_pull(pr_number)
        
        formatted_comment = format_comment(content, has_vulnerabilities)
        
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
