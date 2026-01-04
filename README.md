# 🔒 SecurePR

AI-powered security scanner for GitHub Pull Requests using OpenAI GPT-4.

[![Security Scan](https://github.com/jainilshah007/securePR/actions/workflows/security-scan.yml/badge.svg)](https://github.com/jainilshah007/securePR/actions/workflows/security-scan.yml)

## What It Does

SecurePR automatically scans your code changes for security vulnerabilities on every push. It uses GPT-4 to analyze git diffs and identify issues like:

- 🔴 **SQL Injection** (CWE-89)
- 🔴 **Command Injection** (CWE-78)
- 🟠 **Hardcoded Secrets** (CWE-798)
- 🟠 **XSS Vulnerabilities** (CWE-79)
- 🟠 **Path Traversal** (CWE-22)
- 🟡 **Insecure Randomness** (CWE-330)

## Quick Start

### 1. Add Your OpenAI API Key

Go to **Settings → Secrets → Actions** and add:
- Name: `OPENAI_API_KEY`
- Value: Your OpenAI API key

### 2. Create a Pull Request

The security scan runs automatically on every PR to `main`.

### 3. Check Results

View the scan results in the **Actions** tab. The workflow will fail if critical vulnerabilities are found.

---

## How I Built This

See [DEVELOPMENT.md](DEVELOPMENT.md) for detailed step-by-step build process.

**Summary:**
1. Basic GitHub Actions workflow setup
2. Commit info display with git commands
3. Python environment with OpenAI SDK
4. Security analyzer script with GPT-4
5. Prompt engineering for vulnerability detection
6. Markdown output formatting
7. Caching to reduce API costs
8. Confidence filtering to reduce false positives
9. PR trigger with base/head diff comparison

---

## Project Structure

```
securePR/
├── .github/workflows/security-scan.yml   # GitHub Actions workflow
├── scripts/analyze_security.py           # Security analyzer script
├── test_vulnerable_code.py               # Test file with vulnerabilities
├── DEVELOPMENT.md                        # Build process documentation
└── README.md
```

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `CONFIDENCE_THRESHOLD` | 70 | Minimum confidence % to report |
| Model | `gpt-4o` | OpenAI model used |

## Example Output

```
🔒 SECURITY ANALYSIS RESULTS
==================================================
⚠️  Found 5 issue(s) (confidence ≥ 70%):

   🔴 Critical: 2
   🟠 High:     3

   Risk Level: CRITICAL
==================================================
🔴 [CRITICAL] SQL Injection (95% confidence)
File: app/database.py (Line 45)
Fix: Use parameterized queries.
```

