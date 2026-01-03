#!/usr/bin/env python3
"""
Test file with INTENTIONAL security vulnerabilities.
DO NOT use this code in production!
This file is for testing the SecurePR security scanner.
"""

import os
import subprocess
import sqlite3
import random  # VULN: Using random instead of secrets for security

# ============================================
# VULNERABILITY 1: Hardcoded API Key
# ============================================
# CWE-798: Use of Hard-coded Credentials
API_KEY = "sk-proj-abc123xyz789secretkey"  # VULNERABLE: Hardcoded secret!
DATABASE_PASSWORD = "admin123"  # VULNERABLE: Hardcoded password!


def get_user_by_id(user_id):
    """
    VULNERABILITY 2: SQL Injection
    CWE-89: SQL Injection
    
    User input is directly concatenated into the SQL query,
    allowing attackers to inject malicious SQL.
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABLE: String concatenation in SQL query!
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    
    # Attacker could input: ' OR '1'='1' --
    # This would return all users!
    
    return cursor.fetchone()


def search_users(search_term):
    """
    Another SQL injection example with f-string.
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABLE: f-string SQL injection!
    query = f"SELECT * FROM users WHERE name LIKE '%{search_term}%'"
    cursor.execute(query)
    
    return cursor.fetchall()


def run_system_command(filename):
    """
    VULNERABILITY 3: Command Injection
    CWE-78: OS Command Injection
    
    User input is passed directly to shell command,
    allowing arbitrary command execution.
    """
    # VULNERABLE: Direct shell injection!
    os.system(f"cat {filename}")  # Attacker: "; rm -rf /"
    
    # Also vulnerable:
    subprocess.call(f"grep error {filename}", shell=True)  # VULNERABLE!
    
    # Attacker could input: "file.txt; whoami; cat /etc/passwd"


def process_file(user_input):
    """
    Another command injection variant.
    """
    # VULNERABLE: User input in shell command
    result = subprocess.Popen(
        f"wc -l {user_input}",
        shell=True,  # VULNERABLE: shell=True with user input!
        stdout=subprocess.PIPE
    )
    return result.communicate()[0]


def generate_session_token():
    """
    VULNERABILITY 4: Insecure Random Number Generation
    CWE-330: Use of Insufficiently Random Values
    
    Using random module instead of secrets for security tokens.
    random is predictable and not cryptographically secure.
    """
    # VULNERABLE: random is not cryptographically secure!
    token = ''.join([str(random.randint(0, 9)) for _ in range(32)])
    return token


def generate_password_reset_token(user_id):
    """
    Insecure token generation for password reset.
    """
    # VULNERABLE: Predictable token!
    random.seed(user_id)  # VERY VULNERABLE: Seeding with user_id!
    return random.randint(100000, 999999)


# ============================================
# BONUS VULNERABILITIES
# ============================================

def read_user_file(filename):
    """
    Path Traversal vulnerability.
    CWE-22: Path Traversal
    """
    # VULNERABLE: No path validation!
    # Attacker could input: "../../../etc/passwd"
    with open(f"/uploads/{filename}", 'r') as f:
        return f.read()


def render_user_content(user_html):
    """
    Cross-Site Scripting (XSS) vulnerability.
    CWE-79: XSS
    """
    # VULNERABLE: Unsanitized HTML output!
    return f"<div class='user-content'>{user_html}</div>"


# Main execution
if __name__ == "__main__":
    print("This file contains intentional vulnerabilities for testing.")
    print(f"API Key (exposed!): {API_KEY}")
    
    # These would be vulnerable if called with user input:
    # get_user_by_id(request.args.get('id'))
    # run_system_command(request.args.get('file'))
