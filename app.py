from flask import Flask, render_template, request, redirect, url_for, session, g, flash
import sqlite3
import uuid
import os
import datetime
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

app = Flask(__name__)
# Generate a strong random secret key
app.secret_key = os.urandom(24)

# Configure secure cookies based on environment
if os.environ.get('FLASK_ENV') == 'production':
    app.config.update(
        SESSION_COOKIE_SECURE=True,      # Only transmit cookies over HTTPS
        SESSION_COOKIE_HTTPONLY=True,     # Prevent JavaScript access to cookies
        SESSION_COOKIE_SAMESITE='Lax',    # Restrict cookie sending to same-site requests
        PERMANENT_SESSION_LIFETIME=datetime.timedelta(hours=1))
else:
    # Development settings (less strict for local testing)
    app.config.update(
        SESSION_COOKIE_SECURE=False,      # Allow HTTP in development
        SESSION_COOKIE_HTTPONLY=True,     # Still prevent JS access
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=datetime.timedelta(hours=1))

DATABASE = 'members.db'

# Session ID encryption serializer
serializer = URLSafeTimedSerializer(app.secret_key)

# Updated user store with password hash and 2-minute expiration
USERS = {
    "staff": {
        "password": generate_password_hash("staffpass"),
        "role": "staff",
        "password_expiry": datetime.datetime.now() + datetime.timedelta(minutes=2)
    },
    "member": {
        "password": generate_password_hash("memberpass"),
        "role": "member",
        "password_expiry": datetime.datetime.now() + datetime.timedelta(minutes=2)
    },
    "pakkarim": {
        "password": generate_password_hash("karim"),
        "role": "staff",
        "password_expiry": datetime.datetime.now() + datetime.timedelta(minutes=2)
    }
}

# Helper function to connect to the SQLite database
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Return rows as dictionaries
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

@app.before_request
def create_tables():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS members (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    membership_status TEXT NOT NULL
                 )''')
    db.execute('''CREATE TABLE IF NOT EXISTS classes (
                    id INTEGER PRIMARY KEY,
                    class_name TEXT NOT NULL,
                    class_time TEXT NOT NULL
                 )''')
    db.execute('''CREATE TABLE IF NOT EXISTS member_classes (
                    member_id INTEGER,
                    class_id INTEGER,
                    FOREIGN KEY (member_id) REFERENCES members (id),
                    FOREIGN KEY (class_id) REFERENCES classes (id)
                 )''')
    # New table for password information with 2-minute expiration
    db.execute('''CREATE TABLE IF NOT EXISTS user_passwords (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    password_expiry TEXT NOT NULL,
                    last_change TEXT NOT NULL
                 )''')
    db.commit()

@app.before_request
def check_session_validity():
    if 'user' in session:
        # Check if the encrypted session ID is valid
        try:
            # Verify the session ID with a 2 minutes max age
            session_data = serializer.loads(session.get('encrypted_session_id', ''), max_age=120)
            if session_data.get('user') != session.get('user'):
                session.clear()
                return redirect(url_for('login'))
            
            # Check if password has expired
            if 'password_expiry' in session:
                expiry_date = datetime.datetime.fromisoformat(session['password_expiry'])
                if datetime.datetime.now() > expiry_date:
                    session.clear()
                    flash("Your password has expired. Please contact an administrator to reset it.")
                    return redirect(url_for('login'))
                
        except (SignatureExpired, BadSignature):
            session.clear()
            return redirect(url_for('login'))

# Home Route (Login)
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in USERS:
            # Check password using secure verification
            if check_password_hash(USERS[username]['password'], password):
                # Check if password has expired
                if datetime.datetime.now() > USERS[username]['password_expiry']:
                    return "Password expired! Please contact an administrator."
                
                # Create and encrypt session ID
                session_id = str(uuid.uuid4())
                session_data = {'user': username, 'session_id': session_id}
                encrypted_session_id = serializer.dumps(session_data)
                
                # Store in session
                session['encrypted_session_id'] = encrypted_session_id
                session['user'] = username
                session['role'] = USERS[username]['role']
                session['password_expiry'] = USERS[username]['password_expiry'].isoformat()
                session.permanent = True  # Use the configured lifetime
                
                # Store user's IP and User-Agent for session validation
                session['ip_address'] = request.remote_addr
                session['user_agent'] = request.user_agent.string
                
                return redirect(url_for('dashboard'))
            else:
                return "Login Failed! Invalid credentials."
        else:
            return "Login Failed! User not found."
    return render_template('login.html')

# Dashboard (for both staff and members)
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Basic session validation
    if session.get('ip_address') != request.remote_addr or session.get('user_agent') != request.user_agent.string:
        session.clear()
        return redirect(url_for('login'))
    
    # Calculate seconds until password expiration for the 2-minute policy
    expiry_date = datetime.datetime.fromisoformat(session['password_expiry'])
    seconds_left = int((expiry_date - datetime.datetime.now()).total_seconds())
    
    return render_template('dashboard.html', username=session['user'], seconds_left=seconds_left)

# Password management
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Check if current password is correct
        if not check_password_hash(USERS[session['user']]['password'], current_password):
            flash("Current password is incorrect")
            return redirect(url_for('change_password'))
        
        # Check if new password matches confirmation
        if new_password != confirm_password:
            flash("New passwords do not match")
            return redirect(url_for('change_password'))
        
        # Update password with new 2-minute expiration
        USERS[session['user']]['password'] = generate_password_hash(new_password)
        USERS[session['user']]['password_expiry'] = datetime.datetime.now() + datetime.timedelta(minutes=2)
        session['password_expiry'] = USERS[session['user']]['password_expiry'].isoformat()
        
        flash("Password changed successfully. New password will expire in 2 minutes.")
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

# Member Management Routes
@app.route('/add_member', methods=['GET', 'POST'])
def add_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))
    
    return render_template('add_member.html')

# View specific member classes
@app.route('/member/<int:member_id>/classes')
def member_classes(member_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    member = query_db("SELECT * FROM members WHERE id = ?", [member_id], one=True)
    classes = query_db("SELECT c.class_name, c.class_time FROM classes c "
                       "JOIN member_classes mc ON c.id = mc.class_id "
                       "WHERE mc.member_id = ?", [member_id])
    
    return render_template('member_classes.html', member=member, classes=classes)

# Register class
@app.route('/register_class/<int:member_id>', methods=['GET', 'POST'])
def register_class(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    classes = query_db("SELECT * FROM classes")
    
    if request.method == 'POST':
        class_id = request.form['class_id']
        db = get_db()
        db.execute("INSERT INTO member_classes (member_id, class_id) VALUES (?, ?)", (member_id, class_id))
        db.commit()
        return redirect(url_for('member_classes', member_id=member_id))
    
    return render_template('register_class.html', member_id=member_id, classes=classes)

# View members
@app.route('/view_members')
def view_members():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    members = query_db("SELECT * FROM members")
    return render_template('view_members.html', members=members)

# Register a new member
@app.route('/register_member', methods=['GET', 'POST'])
def register_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))
    
    return render_template('register_member.html')

# Class Scheduling Routes
@app.route('/add_class', methods=['GET', 'POST'])
def add_class():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        class_name = request.form['class_name']
        class_time = request.form['class_time']
        db = get_db()
        db.execute("INSERT INTO classes (class_name, class_time) VALUES (?, ?)", (class_name, class_time))
        db.commit()
        return redirect(url_for('view_classes'))
    
    return render_template('add_class.html')

@app.route('/view_classes')
def view_classes():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    classes = query_db("SELECT * FROM classes")
    return render_template('view_classes.html', classes=classes)

# Deleting member
@app.route('/delete_member/<int:member_id>', methods=['POST'])
def delete_member(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    db = get_db()
    
    db.execute("DELETE FROM members WHERE id = ?", [member_id])
    db.execute("DELETE FROM member_classes WHERE member_id = ?", [member_id])
    
    db.commit()
    
    return redirect(url_for('view_members'))

# New route to demonstrate password expiry
@app.route('/check_password_expiry')
def check_password_expiry():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    expiry_date = datetime.datetime.fromisoformat(session['password_expiry'])
    seconds_left = int((expiry_date - datetime.datetime.now()).total_seconds())
    
    if seconds_left <= 0:
        return "Your password has expired! Please change it now."
    else:
        return f"Your password will expire in {seconds_left} seconds. <a href='{url_for('change_password')}'>Change password</a>"

# Logout Route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Set FLASK_ENV environment variable
    os.environ['FLASK_ENV'] = 'development'  # Change to 'production' when deploying
    
    if os.environ.get('FLASK_ENV') == 'production':
        # In production, use proper SSL certificates
        app.run(host='0.0.0.0', port=443, ssl_context=(
            '/path/to/cert.pem', 
            '/path/to/key.pem'
        ))
    else:
        # In development, use adhoc SSL or HTTP based on cookie settings
        if app.config['SESSION_COOKIE_SECURE']:
            app.run(debug=True, ssl_context='adhoc')
        else:
            app.run(debug=True)
