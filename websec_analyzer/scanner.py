import re
import logging
from bs4 import BeautifulSoup

# --- SQL Injection Detection ---
def detect_sql_injection(input_text: str) -> bool:
    """
    Detects common SQL Injection patterns in the input text.
    Returns True if a pattern is found, else False.
    """
    sql_injection_patterns = [
        r"(\bor\b|\band\b)\s+'?\d+'?\s*=\s*'?\d+'?",  # ' OR '1'='1 pattern
        r"union\s+select",                            # UNION SELECT
        r"(--|#|\/\*)",                              # SQL comment indicators
        r"drop\s+table",                             # DROP TABLE
        r"insert\s+into",                            # INSERT INTO
        r"select\s+\*\s+from",                       # SELECT * FROM
    ]
    input_text = input_text.lower()
    for pattern in sql_injection_patterns:
        if re.search(pattern, input_text):
            logging.warning(f"Possible SQL Injection pattern found: {pattern} in input: {input_text}")
            return True
    return False

# --- Cross-Site Scripting (XSS) Detection ---
def detect_xss(input_text: str) -> bool:
    """
    Detects common XSS patterns in the input text.
    Returns True if a pattern is found, else False.
    """
    xss_patterns = [
        r"<script.*?>",          # <script> tags
        r"onerror\s*=",          # onerror attribute
        r"javascript:",          # javascript: URI
        r"document\.cookie",     # Access to cookies via JS
        r"alert\s*\(",           # alert() calls
    ]
    input_text = input_text.lower()
    for pattern in xss_patterns:
        if re.search(pattern, input_text):
            logging.warning(f"Possible XSS pattern found: {pattern} in input: {input_text}")
            return True
    return False

# --- CSRF Token Check ---
def check_csrf_token(html_content: str) -> bool:
    """
    Checks presence of CSRF token input in HTML forms.
    Returns True if CSRF token found, else False.
    """
    soup = BeautifulSoup(html_content, "html.parser")
    forms = soup.find_all("form")
    for form in forms:
        csrf_input = form.find("input", attrs={"name": re.compile("csrf", re.I)})
        if csrf_input:
            return True
    logging.warning("No CSRF token found in any form.")
    return False

# --- Security Headers Check ---
def check_security_headers(headers: dict) -> dict:
    """
    Checks for missing important security headers in HTTP response headers.
    Returns a dict with header names as keys and bool values (True if missing).
    """
    important_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "Permissions-Policy",
    ]
    missing_headers = {}
    for header in important_headers:
        if header not in headers or not headers.get(header):
            missing_headers[header] = True
            logging.warning(f"Missing security header: {header}")
        else:
            missing_headers[header] = False
    return missing_headers
