from flask import Flask, render_template, request, flash, session, redirect, url_for
import sqlite3
import bcrypt
import pyotp
import qrcode
import io
import base64

app = Flask(__name__)
# Secret key used to cryptographically sign session cookies
app.secret_key = 'devkey123'

# --- DATABASE SETUP ---
def get_db():
    conn = sqlite3.connect('secure_login.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    # Initialize users table with a column for the 2FA TOTP secret
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            totp_secret TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Run this once when the app starts
init_db()

# --- ROUTES ---
@app.route('/')
def home():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Security: Hash the password with bcrypt before storing
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        conn = get_db()
        # Security: Parameterized query (?) prevents SQL Injection
        existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if existing_user:
            flash('Username already taken. Please choose another one.', 'error')
            conn.close()
            return render_template('register.html')
            
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()
        
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user:
            stored_password = user['password']
            if isinstance(stored_password, str):
                stored_password = stored_password.encode('utf-8')
                
            # Security: Verify the entered password against the stored bcrypt hash
            if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                # Temporarily store user info in session to verify 2FA next
                session['pending_user_id'] = user['id']
                session['pending_username'] = user['username']
                
                if user['totp_secret']:
                    # User has 2FA enabled, enforce it
                    return redirect(url_for('verify_2fa'))
                else:
                    # No 2FA, grant full access
                    session['user_id'] = session['pending_user_id']
                    session['username'] = session['pending_username']
                    session.modified = True
                    flash('Login successful! Consider setting up 2FA.', 'success')
                    return redirect(url_for('dashboard'))
                    
        flash('Invalid username or password.', 'error')
        return render_template('login.html')
        
    return render_template('login.html')

@app.route('/setup_2fa', methods=['GET', 'POST'])
def setup_2fa():
    # Security: Ensure user is logged in before setting up 2FA
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if user['totp_secret']:
        flash('2FA is already set up!', 'success')
        conn.close()
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        secret = session.get('temp_totp_secret')
        token = request.form.get('token')
        totp = pyotp.TOTP(secret)
        
        # Verify the 6-digit code entered by the user
        if totp.verify(token):
            conn.execute('UPDATE users SET totp_secret = ? WHERE id = ?', (secret, session['user_id']))
            conn.commit()
            flash('2FA enabled successfully!', 'success')
            conn.close()
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid code. Try again.', 'error')
            conn.close()
            return render_template('setup_2fa.html', secret=secret, qr_b64=session.get('qr_b64'))
            
    # Generate a new TOTP secret and QR code for the setup page
    secret = pyotp.random_base32()
    session['temp_totp_secret'] = secret
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=session['username'], issuer_name='SecureLoginApp')
    
    qr = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    session['qr_b64'] = qr_b64
    
    conn.close()
    return render_template('setup_2fa.html', secret=secret, qr_b64=qr_b64)

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    # Only allow access if user just passed the password check
    if 'pending_user_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        token = request.form.get('token')
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['pending_user_id'],)).fetchone()
        conn.close()
        
        totp = pyotp.TOTP(user['totp_secret'])
        if totp.verify(token):
            # 2FA passed, grant full session access
            session['user_id'] = session['pending_user_id']
            session['username'] = session['pending_username']
            session.modified = True
            
            # Clean up temporary session data
            session.pop('pending_user_id', None)
            session.pop('pending_username', None)
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid 2FA code.', 'error')
            
    return render_template('verify_2fa.html')

@app.route('/dashboard')
def dashboard():
    # Security: Route protection (Access Control)
    if 'user_id' not in session:
        flash('Please login first.', 'error')
        return redirect(url_for('login'))
        
    conn = get_db()
    user = conn.execute('SELECT totp_secret FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    has_2fa = bool(user['totp_secret'])
        
    return render_template('dashboard.html', username=session.get('username'), has_2fa=has_2fa)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)