# =============================
# test_targets/app.py
# Local Vulnerable Test Server for Security Analyzer
# =============================
from flask import Flask, request, render_template_string, make_response

app = Flask(__name__)

# --- 1. Route with Missing Security Headers ---
@app.route('/')
def home():
    html = '''<h2>Welcome to the Vulnerable Test Server</h2>
    <ul>
        <li><a href="/missing-headers">Missing Security Headers</a></li>
        <li><a href="/sqli?user=1' OR '1'='1">SQL Injection Example</a></li>
        <li><a href="/xss?msg=<script>alert('XSS')</script>">XSS Example</a></li>
        <li><a href="/csrf-form">Form Without CSRF Token</a></li>
    </ul>'''
    return html

@app.route('/missing-headers')
def missing_headers():
    html = '<h3>This page is missing security headers!</h3>'
    resp = make_response(html)
    # Intentionally do NOT set security headers
    return resp

# --- 2. Route with SQL Injection Vulnerability ---
@app.route('/sqli')
def sqli():
    user = request.args.get('user', '')
    # Simulate SQLi vulnerability (do NOT use in production!)
    html = f"<h3>SQL Query: SELECT * FROM users WHERE user = '{user}'</h3>"
    return html

# --- 3. Route with XSS Vulnerability ---
@app.route('/xss')
def xss():
    msg = request.args.get('msg', '')
    # Reflected XSS vulnerability
    html = f"<h3>Message: {msg}</h3>"
    return html

# --- 4. Route with Form Missing CSRF Token ---
@app.route('/csrf-form', methods=['GET', 'POST'])
def csrf_form():
    if request.method == 'POST':
        name = request.form.get('name', '')
        return f"<h3>Form submitted! Hello, {name}</h3>"
    html = '''<form method="post">
        <input type="text" name="name" placeholder="Enter your name">
        <button type="submit">Submit</button>
    </form>'''
    return html

if __name__ == '__main__':
    app.run(port=5001, debug=True)
