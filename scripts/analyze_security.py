#!/usr/bin/env python3

import sys
import os
import json
import hashlib
from pathlib import Path
from openai import OpenAI

# Configuration
CONFIDENCE_THRESHOLD = 70  # Only report findings with confidence >= 70%
CACHE_DIR = Path(os.environ.get('RUNNER_TEMP', '/tmp')) / '.securePR_cache'

SECURITY_PROMPT = """You are an expert security code reviewer with deep knowledge of OWASP Top 10, CWE, and secure coding practices.

## Task
Analyze the provided git diff for security vulnerabilities. Be thorough but avoid false positives.

## Vulnerability Categories to Check

1. **Injection Flaws**
   - SQL Injection (CWE-89)
   - Command Injection (CWE-78)
   - LDAP Injection (CWE-90)
   - XPath Injection (CWE-643)

2. **Cross-Site Scripting (XSS)** (CWE-79)
   - Reflected XSS
   - Stored XSS
   - DOM-based XSS

3. **Authentication & Session Issues**
   - Hardcoded credentials (CWE-798)
   - Weak password requirements
   - Session fixation (CWE-384)
   - Missing authentication (CWE-306)

4. **Sensitive Data Exposure**
   - API keys, tokens, secrets in code
   - Unencrypted sensitive data
   - Logging sensitive information

5. **Security Misconfigurations**
   - Debug mode enabled
   - CORS misconfiguration
   - Insecure defaults

6. **Insecure Direct Object References**
   - Path traversal (CWE-22)
   - Unauthorized access patterns

7. **Dangerous Functions**
   - eval(), exec() usage
   - Insecure deserialization (CWE-502)
   - Unsafe regex (ReDoS)

8. **Server-Side Request Forgery (SSRF)** (CWE-918)

## Analysis Guidelines

- **Context matters**: Consider if user input reaches the vulnerable code
- **New code focus**: Prioritize vulnerabilities in added lines (+ prefix)
- **Avoid false positives**: Don't flag safe patterns (parameterized queries, properly escaped output)
- **Be specific**: Include exact file, line, and code snippet
- **Confidence score**: Provide a numeric confidence score (0-100) for each finding

## Response Format (JSON only)

{
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": 85,
      "confidence_level": "HIGH|MEDIUM|LOW",
      "type": "vulnerability type",
      "category": "DEFINITE|POTENTIAL",
      "cwe": "CWE-XXX",
      "owasp": "A01:2021 - Category Name",
      "file": "path/to/file.py",
      "line": "line number or range",
      "vulnerable_code": "the exact vulnerable code",
      "explanation": "detailed explanation of why this is vulnerable",
      "attack_scenario": "how an attacker could exploit this",
      "fix": "recommended fix with code example",
      "references": ["https://owasp.org/..."]
    }
  ],
  "summary": {
    "total": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "risk_score": "CRITICAL|HIGH|MEDIUM|LOW|NONE",
    "assessment": "brief overall security assessment"
  }
}

## Confidence Score Guidelines
- 90-100: Definite vulnerability, clear evidence
- 70-89: Highly likely vulnerability
- 50-69: Potential issue, needs manual review
- 0-49: Uncertain, might be false positive

## Example Good Analysis

For code like: `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`

```json
{
  "id": "VULN-001",
  "severity": "CRITICAL",
  "confidence": 95,
  "confidence_level": "HIGH",
  "type": "SQL Injection",
  "category": "DEFINITE",
  "cwe": "CWE-89",
  "owasp": "A03:2021 - Injection",
  "file": "app/database.py",
  "line": "45",
  "vulnerable_code": "cursor.execute(f\\"SELECT * FROM users WHERE id = {user_id}\\")",
  "explanation": "User input is directly interpolated into SQL query using f-string, allowing SQL injection attacks.",
  "attack_scenario": "Attacker provides: 1; DROP TABLE users;-- as user_id to delete all user data.",
  "fix": "Use parameterized queries: cursor.execute(\\"SELECT * FROM users WHERE id = ?\\", (user_id,))",
  "references": ["https://owasp.org/Top10/A03_2021-Injection/"]
}
```

IMPORTANT: Respond with ONLY valid JSON. No markdown, no code fences, no explanations outside JSON.

## Git Diff to Analyze

"""


def get_diff_hash(diff: str) -> str:
    """Generate a hash of the diff for caching."""
    return hashlib.sha256(diff.encode()).hexdigest()[:16]


def get_cache_path(diff_hash: str) -> Path:
    """Get the cache file path for a given hash."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"{diff_hash}.json"


def load_from_cache(diff_hash: str) -> dict | None:
    """Load cached results if available."""
    cache_path = get_cache_path(diff_hash)
    if cache_path.exists():
        try:
            with open(cache_path, 'r') as f:
                print(f"📦 Cache hit! Using cached results for hash: {diff_hash}")
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None
    return None


def save_to_cache(diff_hash: str, results: dict) -> None:
    """Save results to cache."""
    cache_path = get_cache_path(diff_hash)
    try:
        with open(cache_path, 'w') as f:
            json.dump(results, f)
        print(f"💾 Results cached with hash: {diff_hash}")
    except IOError as e:
        print(f"⚠️ Failed to cache results: {e}")


def get_diff_input():
    """Get diff from stdin or command line argument."""
    if len(sys.argv) > 1:
        diff_path = sys.argv[1]
        if os.path.exists(diff_path):
            with open(diff_path, 'r') as f:
                return f.read()
        return sys.argv[1]
    elif not sys.stdin.isatty():
        return sys.stdin.read()
    else:
        print("Error: No diff provided.")
        print("Usage: git diff | python analyze_security.py")
        sys.exit(1)


def analyze_with_openai(diff: str) -> dict:
    """Send diff to OpenAI for security analysis."""
    api_key = os.environ.get('OPENAI_API_KEY')
    if not api_key:
        print("::error::OPENAI_API_KEY environment variable not set.")
        sys.exit(1)
    
    client = OpenAI(api_key=api_key)
    
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {
                    "role": "system",
                    "content": "You are a security expert. Respond only with valid JSON, no markdown."
                },
                {
                    "role": "user",
                    "content": SECURITY_PROMPT + diff
                }
            ],
            temperature=0.1,
            max_tokens=4096
        )
        
        content = response.choices[0].message.content.strip()
        
        # Clean up potential markdown formatting
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
        
        return json.loads(content)
        
    except json.JSONDecodeError as e:
        print(f"::error::Failed to parse response: {e}")
        sys.exit(1)
    except Exception as e:
        error_msg = str(e).lower()
        if "rate_limit" in error_msg:
            print("::error::OpenAI rate limit exceeded. Try again later.")
        elif "invalid_api_key" in error_msg:
            print("::error::Invalid OpenAI API key.")
        else:
            print(f"::error::API error: {e}")
        sys.exit(1)


def filter_by_confidence(results: dict, threshold: int = CONFIDENCE_THRESHOLD) -> dict:
    """Filter vulnerabilities by confidence threshold."""
    vulns = results.get('vulnerabilities', [])
    
    filtered = []
    skipped = []
    
    for vuln in vulns:
        # Handle both numeric and string confidence
        conf = vuln.get('confidence', 0)
        if isinstance(conf, str):
            conf = {'HIGH': 90, 'MEDIUM': 70, 'LOW': 40}.get(conf.upper(), 50)
        
        if conf >= threshold:
            filtered.append(vuln)
        else:
            skipped.append(vuln)
    
    if skipped:
        print(f"🔇 Filtered out {len(skipped)} low-confidence finding(s) (< {threshold}%)")
    
    # Recalculate summary
    summary = results.get('summary', {})
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    for vuln in filtered:
        sev = vuln.get('severity', 'LOW').lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    summary['total'] = len(filtered)
    summary['critical'] = severity_counts['critical']
    summary['high'] = severity_counts['high']
    summary['medium'] = severity_counts['medium']
    summary['low'] = severity_counts['low']
    
    # Update risk score
    if severity_counts['critical'] > 0:
        summary['risk_score'] = 'CRITICAL'
    elif severity_counts['high'] > 0:
        summary['risk_score'] = 'HIGH'
    elif severity_counts['medium'] > 0:
        summary['risk_score'] = 'MEDIUM'
    elif severity_counts['low'] > 0:
        summary['risk_score'] = 'LOW'
    else:
        summary['risk_score'] = 'NONE'
    
    return {'vulnerabilities': filtered, 'summary': summary}


def severity_emoji(severity: str) -> str:
    """Get emoji for severity level."""
    return {
        'CRITICAL': '🔴',
        'HIGH': '🟠',
        'MEDIUM': '🟡',
        'LOW': '🟢'
    }.get(severity.upper(), '⚪')


def confidence_badge(confidence) -> str:
    """Get badge for confidence level."""
    if isinstance(confidence, int):
        if confidence >= 90:
            return f'🎯 {confidence}% Confidence'
        elif confidence >= 70:
            return f'🔍 {confidence}% Confidence'
        else:
            return f'❓ {confidence}% Confidence'
    
    return {
        'HIGH': '🎯 High Confidence',
        'MEDIUM': '🔍 Medium Confidence',
        'LOW': '❓ Low Confidence'
    }.get(str(confidence).upper(), '')


def format_markdown_output(results: dict) -> str:
    """Format results as markdown."""
    output = []
    vulns = results.get('vulnerabilities', [])
    summary = results.get('summary', {})
    
    # Header
    output.append("# 🔒 SecurePR Security Analysis Report\n")
    
    # Summary section
    output.append("## 📊 Summary\n")
    
    if not vulns:
        output.append("✅ **No security vulnerabilities detected!**\n")
        output.append("Your code changes passed the security scan.\n")
        return "\n".join(output)
    
    total = summary.get('total', len(vulns))
    risk = summary.get('risk_score', 'UNKNOWN')
    
    output.append(f"| Metric | Value |")
    output.append(f"|--------|-------|")
    output.append(f"| Total Issues | **{total}** |")
    output.append(f"| 🔴 Critical | {summary.get('critical', 0)} |")
    output.append(f"| 🟠 High | {summary.get('high', 0)} |")
    output.append(f"| 🟡 Medium | {summary.get('medium', 0)} |")
    output.append(f"| 🟢 Low | {summary.get('low', 0)} |")
    output.append(f"| **Risk Level** | **{severity_emoji(risk)} {risk}** |")
    output.append(f"| Confidence Threshold | ≥ {CONFIDENCE_THRESHOLD}% |")
    output.append("")
    
    if summary.get('assessment'):
        output.append(f"> {summary['assessment']}\n")
    
    # Vulnerabilities
    output.append("---\n")
    output.append("## 🚨 Vulnerabilities Found\n")
    
    for vuln in vulns:
        vid = vuln.get('id', 'VULN')
        sev = vuln.get('severity', 'UNKNOWN')
        vtype = vuln.get('type', 'Unknown')
        category = vuln.get('category', '')
        conf = vuln.get('confidence', 'N/A')
        
        # Header with severity
        output.append(f"### {severity_emoji(sev)} [{sev}] {vtype}")
        output.append(f"**ID:** `{vid}` | **{confidence_badge(conf)}**")
        
        if category == 'POTENTIAL':
            output.append("> ⚠️ *Potential issue - requires manual verification*\n")
        
        # Location
        if vuln.get('file'):
            loc = f"📍 **Location:** `{vuln['file']}`"
            if vuln.get('line'):
                loc += f" (Line {vuln['line']})"
            output.append(loc + "\n")
        
        # CWE/OWASP
        refs = []
        if vuln.get('cwe'):
            refs.append(f"**{vuln['cwe']}**")
        if vuln.get('owasp'):
            refs.append(f"**{vuln['owasp']}**")
        if refs:
            output.append(f"📚 {' | '.join(refs)}\n")
        
        # Vulnerable code
        if vuln.get('vulnerable_code'):
            output.append("<details>")
            output.append("<summary>🔍 Vulnerable Code</summary>\n")
            output.append("```")
            output.append(vuln['vulnerable_code'])
            output.append("```")
            output.append("</details>\n")
        
        # Explanation
        output.append(f"**Explanation:** {vuln.get('explanation', 'N/A')}\n")
        
        # Attack scenario
        if vuln.get('attack_scenario'):
            output.append(f"**🎯 Attack Scenario:** {vuln['attack_scenario']}\n")
        
        # Fix
        if vuln.get('fix'):
            output.append("<details>")
            output.append("<summary>✅ Recommended Fix</summary>\n")
            output.append("```")
            output.append(vuln['fix'])
            output.append("```")
            output.append("</details>\n")
        
        output.append("---\n")
    
    return "\n".join(output)


def print_console_output(results: dict):
    """Print formatted output to console."""
    vulns = results.get('vulnerabilities', [])
    summary = results.get('summary', {})
    
    print("\n" + "=" * 50)
    print("🔒 SECURITY ANALYSIS RESULTS")
    print("=" * 50)
    
    if not vulns:
        print("\n✅ No security vulnerabilities detected!\n")
        return False
    
    # Summary
    print(f"\n⚠️  Found {len(vulns)} issue(s) (confidence ≥ {CONFIDENCE_THRESHOLD}%):\n")
    print(f"   🔴 Critical: {summary.get('critical', 0)}")
    print(f"   🟠 High:     {summary.get('high', 0)}")
    print(f"   🟡 Medium:   {summary.get('medium', 0)}")
    print(f"   🟢 Low:      {summary.get('low', 0)}")
    print(f"\n   Risk Level: {summary.get('risk_score', 'UNKNOWN')}")
    
    # Each vulnerability
    for vuln in vulns:
        sev = vuln.get('severity', 'UNKNOWN')
        conf = vuln.get('confidence', 'N/A')
        print(f"\n{'='*50}")
        print(f"{severity_emoji(sev)} [{sev}] {vuln.get('type', 'Unknown')} ({conf}% confidence)")
        print(f"{'='*50}")
        
        if vuln.get('file'):
            print(f"File: {vuln['file']}", end="")
            if vuln.get('line'):
                print(f" (Line {vuln['line']})")
            else:
                print()
        
        if vuln.get('cwe'):
            print(f"Reference: {vuln['cwe']}")
        
        print(f"\nExplanation: {vuln.get('explanation', 'N/A')}")
        
        if vuln.get('fix'):
            print(f"\nFix: {vuln['fix']}")
    
    print("\n" + "=" * 50 + "\n")
    
    # Return True if critical/high issues found
    return summary.get('critical', 0) > 0 or summary.get('high', 0) > 0


def main():
    """Main entry point."""
    print("🔍 SecurePR Security Analyzer")
    print("-" * 30)
    
    diff = get_diff_input()
    
    if not diff.strip():
        print("No changes to analyze.")
        sys.exit(0)
    
    print(f"Analyzing {len(diff.splitlines())} lines...")
    print(f"Confidence threshold: {CONFIDENCE_THRESHOLD}%\n")
    
    # Check cache first
    diff_hash = get_diff_hash(diff)
    results = load_from_cache(diff_hash)
    
    if results is None:
        # No cache hit, call OpenAI
        print("🌐 Calling OpenAI API...")
        results = analyze_with_openai(diff)
        save_to_cache(diff_hash, results)
    
    # Filter by confidence threshold
    results = filter_by_confidence(results)
    
    # Print markdown (for GitHub Actions)
    markdown = format_markdown_output(results)
    print(markdown)
    
    # Check for critical issues
    has_critical = print_console_output(results)
    
    if has_critical:
        print("❌ Critical/High vulnerabilities found!")
        sys.exit(1)
    else:
        print("✅ No critical vulnerabilities.")
        sys.exit(0)


if __name__ == "__main__":
    main()
