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

### 2. Push Code

The security scan runs automatically on every push to `main`.

### 3. Check Results

View the scan results in the **Actions** tab. The workflow will fail if critical vulnerabilities are found.

---

## How I Built This (Step-by-Step)

### Step 1: Basic Workflow Setup
Created the GitHub Actions foundation with trigger on push to main, ubuntu-latest runner, and a scan job.

### Step 2: Display Commit Info
Added steps to show repository/branch name, commit author/message, and list of changed files using GitHub context variables.

### Step 3: Set Up Python Environment
Added `actions/setup-python@v4` with Python 3.11 and installed the `openai` package.

### Step 4: Create the Security Analyzer Script
Built `scripts/analyze_security.py` that accepts git diff as input, sends it to GPT-4 with a security-focused prompt, and formats the output.

### Step 5: Craft the Security Prompt
Designed a detailed prompt with 8 vulnerability categories, CWE references, analysis guidelines to avoid false positives, and structured JSON output format.

### Step 6: Add Output Formatting
Created markdown output with summary tables, emoji indicators (🔴🟠🟡🟢), collapsible sections, OWASP/CWE references, and attack scenarios.

### Step 7: Add Caching
Implemented SHA-256 hash-based caching to skip API calls for already-analyzed diffs.

### Step 8: Add Confidence Filtering
Added threshold system (≥70% confidence) to reduce false positives.

---

## Project Structure

```
securePR/
├── .github/workflows/security-scan.yml   # GitHub Actions workflow
├── scripts/analyze_security.py           # Security analyzer script
├── test_vulnerable_code.py               # Test file with vulnerabilities
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

