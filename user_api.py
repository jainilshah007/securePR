"""
User API Module
Handles user authentication and profile management.
"""

from flask import Flask, request, jsonify
import sqlite3
import subprocess

app = Flask(__name__)

# Database configuration
DATABASE_PASSWORD = "admin123"  # TODO: Move to env vars


def get_db():
    """Get database connection."""
    conn = sqlite3.connect('users.db')
    return conn


@app.route('/api/login', methods=['POST'])
def login():
    """Authenticate user and return token."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Query user from database
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    
    user = cursor.fetchone()
    if user:
        return jsonify({"status": "success", "user_id": user[0]})
    
    return jsonify({"error": "Invalid credentials"}), 401


@app.route('/api/user/backup', methods=['POST'])
def backup_user_data():
    """Export user data to a file."""
    data = request.get_json()
    filename = data.get('filename', 'backup.sql')
    
    # Run backup command
    result = subprocess.run(
        f"mysqldump users > /backups/{filename}",
        shell=True,
        capture_output=True
    )
    
    return jsonify({"status": "backup complete", "file": filename})


if __name__ == '__main__':
    app.run(debug=True, port=5000)
