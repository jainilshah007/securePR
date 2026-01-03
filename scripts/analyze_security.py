#!/usr/bin/env python3
"""
Security vulnerability analyzer using OpenAI GPT-4.
Analyzes git diffs for common security vulnerabilities.
"""

import sys
import os
import json
from openai import OpenAI

# Security prompt template
SECURITY_PROMPT = """You are a senior security engineer performing a code review.
Analyze the following git diff for security vulnerabilities.

Look specifically for these vulnerability types:
1. SQL Injection
2. XSS (Cross-Site Scripting)
3. Authentication bypasses
4. Hardcoded secrets/credentials (API keys, passwords, tokens)
5. Insecure deserialization
6. Path traversal
7. Command injection
8. SSRF (Server-Side Request Forgery)

For each vulnerability found, respond in this exact JSON format:
{
  "vulnerabilities": [
    {
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "type": "vulnerability type",
      "file": "filename if identifiable",
      "line": "line number or range if identifiable",
      "code": "the vulnerable code snippet",
      "explanation": "detailed explanation of the vulnerability",
      "fix": "suggested fix for the vulnerability"
    }
  ],
  "summary": "brief overall assessment",
  "has_critical": true/false
}

If no vulnerabilities are found, return:
{
  "vulnerabilities": [],
  "summary": "No security vulnerabilities detected in this diff.",
  "has_critical": false
}

IMPORTANT: Respond ONLY with valid JSON, no markdown formatting.

Here is the git diff to analyze:

"""


def get_diff_input():
    """Get diff from stdin or command line argument."""
    if len(sys.argv) > 1:
        # Read from file if path provided
        diff_path = sys.argv[1]
        if os.path.exists(diff_path):
            with open(diff_path, 'r') as f:
                return f.read()
        else:
            # Treat argument as the diff itself
            return sys.argv[1]
    elif not sys.stdin.isatty():
        # Read from stdin (piped input)
        return sys.stdin.read()
    else:
        print("Error: No diff provided. Pipe a diff or provide as argument.")
        print("Usage: git diff | python analyze_security.py")
        print("   or: python analyze_security.py <diff_file>")
        sys.exit(1)


def analyze_with_openai(diff: str) -> dict:
    """Send diff to OpenAI for security analysis."""
    api_key = os.environ.get('OPENAI_API_KEY')
    if not api_key:
        print("Error: OPENAI_API_KEY environment variable not set.")
        sys.exit(1)
    
    client = OpenAI(api_key=api_key)
    
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {
                    "role": "system",
                    "content": "You are a security expert. Respond only in valid JSON format."
                },
                {
                    "role": "user",
                    "content": SECURITY_PROMPT + diff
                }
            ],
            temperature=0.1,  # Low temperature for consistent analysis
            max_tokens=4096
        )
        
        content = response.choices[0].message.content.strip()
        
        # Try to parse JSON response
        # Handle potential markdown code blocks
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        
        return json.loads(content)
        
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse OpenAI response as JSON: {e}")
        print(f"Raw response: {content}")
        sys.exit(1)
    except Exception as e:
        error_msg = str(e).lower()
        if "rate_limit" in error_msg:
            print("Error: OpenAI API rate limit exceeded. Please try again later.")
        elif "invalid_api_key" in error_msg or "authentication" in error_msg:
            print("Error: Invalid OpenAI API key.")
        elif "insufficient_quota" in error_msg:
            print("Error: OpenAI API quota exceeded.")
        else:
            print(f"Error: OpenAI API call failed: {e}")
        sys.exit(1)


def format_vulnerability(vuln: dict, index: int) -> str:
    """Format a single vulnerability for display."""
    severity = vuln.get('severity', 'UNKNOWN')
    
    # Color codes for terminal
    severity_colors = {
        'CRITICAL': '\033[91m',  # Red
        'HIGH': '\033[93m',      # Yellow
        'MEDIUM': '\033[94m',    # Blue
        'LOW': '\033[92m',       # Green
    }
    reset = '\033[0m'
    color = severity_colors.get(severity, '')
    
    output = []
    output.append(f"\n{'='*60}")
    output.append(f"{color}[{severity}]{reset} Vulnerability #{index + 1}: {vuln.get('type', 'Unknown')}")
    output.append(f"{'='*60}")
    
    if vuln.get('file'):
        location = f"File: {vuln['file']}"
        if vuln.get('line'):
            location += f" (Line {vuln['line']})"
        output.append(location)
    
    if vuln.get('code'):
        output.append(f"\nVulnerable Code:")
        output.append(f"  {vuln['code']}")
    
    output.append(f"\nExplanation:")
    output.append(f"  {vuln.get('explanation', 'No explanation provided.')}")
    
    output.append(f"\nSuggested Fix:")
    output.append(f"  {vuln.get('fix', 'No fix suggested.')}")
    
    return '\n'.join(output)


def print_results(results: dict) -> bool:
    """Print formatted results. Returns True if critical vulnerabilities found."""
    vulnerabilities = results.get('vulnerabilities', [])
    summary = results.get('summary', '')
    has_critical = results.get('has_critical', False)
    
    print("\n" + "="*60)
    print("🔒 SECURITY ANALYSIS RESULTS")
    print("="*60)
    
    if not vulnerabilities:
        print("\n✅ No security vulnerabilities detected!")
        print(f"\nSummary: {summary}")
        return False
    
    # Count by severity
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for vuln in vulnerabilities:
        sev = vuln.get('severity', 'LOW')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    print(f"\n⚠️  Found {len(vulnerabilities)} potential vulnerability(ies):")
    print(f"   CRITICAL: {severity_counts['CRITICAL']}")
    print(f"   HIGH:     {severity_counts['HIGH']}")
    print(f"   MEDIUM:   {severity_counts['MEDIUM']}")
    print(f"   LOW:      {severity_counts['LOW']}")
    
    # Print each vulnerability
    for i, vuln in enumerate(vulnerabilities):
        print(format_vulnerability(vuln, i))
    
    print(f"\n{'='*60}")
    print(f"Summary: {summary}")
    print(f"{'='*60}\n")
    
    return has_critical or severity_counts['CRITICAL'] > 0


def main():
    """Main entry point."""
    print("🔍 SecurePR Security Analyzer")
    print("-" * 30)
    
    # Get the diff
    diff = get_diff_input()
    
    if not diff.strip():
        print("No changes to analyze.")
        sys.exit(0)
    
    print(f"Analyzing {len(diff.splitlines())} lines of diff...")
    
    # Analyze with OpenAI
    results = analyze_with_openai(diff)
    
    # Print results
    has_critical = print_results(results)
    
    # Exit with appropriate code
    if has_critical:
        print("❌ Critical vulnerabilities found. Please review before merging.")
        sys.exit(1)
    else:
        print("✅ No critical vulnerabilities detected.")
        sys.exit(0)


if __name__ == "__main__":
    main()
