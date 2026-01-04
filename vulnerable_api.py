"""
Vulnerable Flask API - FOR TESTING PURPOSES ONLY
This file contains INTENTIONAL security vulnerabilities for testing SecurePR.
DO NOT use this code in production!
"""

from flask import Flask, request, jsonify, render_template_string
import sqlite3
import jwt
import os

app = Flask(__name__)

# ============================================
# VULNERABILITY 1: Hardcoded JWT Secret
# CWE-798: Use of Hard-coded Credentials
# ============================================
# VULNERABLE: Never hardcode secrets!
JWT_SECRET = "super_secret_key_12345"  # This should be in environment variables
DATABASE_URL = "sqlite:///users.db"


def get_db_connection():
    """Get database connection."""
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn


# ============================================
# VULNERABILITY 2: SQL Injection in Login
# CWE-89: SQL Injection
# ============================================
@app.route('/api/login', methods=['POST'])
def login():
    """
    VULNERABLE: SQL Injection
    User input is directly concatenated into SQL query.
    Attacker can bypass authentication with: ' OR '1'='1
    """
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # VULNERABLE: String concatenation in SQL!
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    
    user = cursor.fetchone()
    conn.close()
    
    if user:
        # Generate JWT token
        token = jwt.encode({'user_id': user['id']}, JWT_SECRET, algorithm='HS256')
        return jsonify({'token': token})
    
    return jsonify({'error': 'Invalid credentials'}), 401


# ============================================
# VULNERABILITY 3: Missing Authentication
# CWE-306: Missing Authentication for Critical Function
# ============================================
@app.route('/api/admin/users', methods=['GET'])
def get_all_users():
    """
    VULNERABLE: No authentication check!
    Anyone can access this admin endpoint.
    Should require admin token validation.
    """
    # VULNERABLE: No auth check, no role verification!
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role FROM users")
    users = cursor.fetchall()
    conn.close()
    
    return jsonify([dict(u) for u in users])


@app.route('/api/admin/delete-user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    """
    VULNERABLE: No authentication, no authorization!
    Anyone can delete any user.
    """
    # VULNERABLE: No permission check!
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE id = {user_id}")  # Also SQL injection!
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'User deleted'})


# ============================================
# VULNERABILITY 4: XSS in Error Messages
# CWE-79: Cross-Site Scripting
# ============================================
@app.route('/api/search', methods=['GET'])
def search():
    """
    VULNERABLE: XSS vulnerability
    User input is reflected directly in HTML response without sanitization.
    """
    query = request.args.get('q', '')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE name LIKE ?", (f'%{query}%',))
    results = cursor.fetchall()
    conn.close()
    
    if not results:
        # VULNERABLE: User input rendered as HTML without escaping!
        return render_template_string(f'''
            <html>
            <body>
                <h1>Search Results</h1>
                <p>No results found for: {query}</p>
            </body>
            </html>
        ''')
    
    return jsonify([dict(r) for r in results])


@app.route('/api/error', methods=['GET'])
def error_page():
    """Another XSS example in error handling."""
    error_msg = request.args.get('message', 'Unknown error')
    
    # VULNERABLE: Unsanitized input in HTML!
    return f'''
        <div class="error-box">
            <h2>Error</h2>
            <p>{error_msg}</p>
        </div>
    ''', 400


# ============================================
# VULNERABILITY 5: Insecure File Upload
# CWE-434: Unrestricted Upload of File with Dangerous Type
# ============================================
@app.route('/api/upload', methods=['POST'])
def upload_file():
    """
    VULNERABLE: Allows upload of any file type.
    No validation of file extension, content type, or size.
    Attacker can upload malicious scripts.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    # VULNERABLE: No file type validation!
    # Should check allowed extensions: .jpg, .png, .pdf
    # Should check MIME type
    # Should limit file size
    # Should sanitize filename
    
    filename = file.filename  # VULNERABLE: Using unsanitized filename!
    
    # VULNERABLE: Saving directly to uploads without validation!
    upload_path = os.path.join('/var/www/uploads', filename)
    file.save(upload_path)
    
    return jsonify({
        'message': 'File uploaded successfully',
        'path': upload_path  # VULNERABLE: Exposing server path!
    })


# ============================================
# BONUS VULNERABILITIES
# ============================================

@app.route('/api/user/<username>')
def get_user_profile(username):
    """Path traversal possibility in user lookup."""
    # VULNERABLE: No input validation on username
    profile_path = f"/data/profiles/{username}.json"
    
    try:
        with open(profile_path, 'r') as f:
            return jsonify(f.read())
    except FileNotFoundError:
        return jsonify({'error': 'User not found'}), 404


@app.route('/api/execute', methods=['POST'])
def execute_command():
    """
    VULNERABLE: Command Injection
    CWE-78: OS Command Injection
    """
    data = request.get_json()
    filename = data.get('filename', '')
    
    # VULNERABLE: Direct command execution with user input!
    import subprocess
    result = subprocess.run(f"cat /tmp/{filename}", shell=True, capture_output=True)
    
    return jsonify({'output': result.stdout.decode()})


# Configuration
if __name__ == '__main__':
    # VULNERABLE: Debug mode enabled in production!
    app.run(debug=True, host='0.0.0.0', port=5000)


