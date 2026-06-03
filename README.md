# Secure Login System

A secure authentication system built with Python, Flask, and SQLite. This project demonstrates core cyber security principles including secure password storage, session management, and Two-Factor Authentication (2FA).

## Security Features Implemented
* **Password Hashing:** Uses `bcrypt` to salt and hash passwords before storing them in the database.
* **SQL Injection Prevention:** Uses parameterized SQLite queries (`?`) for all database interactions.
* **Session Security:** Flask cryptographically signs the session cookie using a secret key. Route protection ensures unauthorized users cannot access the dashboard.
* **Two-Factor Authentication (2FA):** Implements Time-based One-Time Passwords (TOTP) using `pyotp` and QR code generation for Authenticator apps.

## How to Run

1. **Activate Virtual Environment:**
   `venv\Scripts\activate` (Windows) or `source venv/bin/activate` (Mac/Linux)

2. **Install Dependencies:**
   `pip install flask bcrypt pyotp qrcode pillow`

3. **Run the Application:**
   `python app.py`

4. **Access the Web App:**
   Open a browser and go to `http://127.0.0.1:5000`