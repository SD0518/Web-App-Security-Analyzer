# Optional pretty table (falls back to plain text if not installed)
try:
    from prettytable import PrettyTable  # pip install prettytable
except ImportError:
    PrettyTable = None

import re
import logging
import ssl
import socket
from bs4 import BeautifulSoup
import requests
from urllib.parse import urljoin, urlparse
import validators
import logging
from datetime import datetime
import os

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

# --- Smarter robots.txt + path probing (duplicate clean version) ---

# ====== COMMON SENSITIVE PATHS ======
COMMON_SENSITIVE_PATHS = [
    "admin", "administrator", "login", "backup", "config",
    "test", "uploads", "private", "tmp", "db", "logs", "server-status"
]

# ====== robots.txt + path probing ======
def check_robots_and_paths(base_url):
    findings = []

    if not base_url.startswith(("http://", "https://")):
        base_url = "http://" + base_url

    parsed = urlparse(base_url)
    root_url = f"{parsed.scheme}://{parsed.netloc}/"

    # === 1. robots.txt check ===
    robots_url = urljoin(root_url, "robots.txt")
    try:
        response = requests.get(robots_url, timeout=5)
        if response.status_code == 200 and "Disallow" in response.text:
            findings.append(f"[+] Found robots.txt: {robots_url}")

            disallowed_paths = set()  # ✅ Store unique paths
            for line in response.text.splitlines():
                if line.strip().lower().startswith("disallow"):
                    path = line.split(":")[1].strip()
                    if path:
                        full_path = urljoin(root_url, path.lstrip("/"))
                        disallowed_paths.add(full_path)

            if disallowed_paths:
                    max_display = 5
                    displayed = 0
                    for full_path in sorted(disallowed_paths):
                        if displayed < max_display:
                            findings.append(f"    - Disallowed path: {full_path}")
                            displayed += 1
                    if len(disallowed_paths) > max_display:
                        findings.append(f"    ...and {len(disallowed_paths) - max_display} more disallowed paths.")
            else:
                findings.append("    - No disallowed paths found.")

        else:
            findings.append("[-] No useful robots.txt found.")
    except requests.RequestException as e:
        findings.append(f"[!] Could not fetch robots.txt: {e}")

    # === 2. Common path probing ===
    findings.append("[*] Probing common sensitive paths...")
    for path in COMMON_SENSITIVE_PATHS:
        test_url = urljoin(root_url, path + "/")
        try:
            r = requests.get(test_url, timeout=5)
            if r.status_code == 200 and any(keyword in r.text.lower() for keyword in ["index of", "directory listing"]):
                findings.append(f"[!] Directory listing found: {test_url}")
            elif r.status_code == 200:
                findings.append(f"[?] Accessible path: {test_url}")
            elif r.status_code in [401, 403]:
                findings.append(f"[~] Restricted path (auth required): {test_url}")
        except requests.RequestException:
            pass

    return findings

# --- Cookie Security Flags Check (single-file version) ---
def check_cookie_flags(base_url: str):
    """
    Fetch the URL once, read cookies, and report Secure / HttpOnly / SameSite.
    Prints a nice table (if prettytable is installed) and logs warnings.
    Returns: {"found": bool, "cookies": [ {name, secure, httponly, samesite}, ... ]}
    """
    logging.info(f"Checking cookie security flags for {base_url}")
    result = []

    try:
        resp = requests.get(base_url, timeout=8)
        jar = resp.cookies

        if not jar:
            logging.info("No cookies were set by the server.")
            print("\n[!] No cookies found for this site.\n")
            return {"found": False, "cookies": []}

        rows = []
        for c in jar:
            # Defaults
            secure_flag = bool(getattr(c, "secure", False))

            # Try to read non-standard attrs in a robust way
            httponly_flag = False
            samesite_val = None
            try:
                # Available on http.cookiejar.Cookie in most Python versions
                httponly_flag = c.has_nonstandard_attr("HttpOnly")
                samesite_val = c.get_nonstandard_attr("SameSite")
            except Exception:
                rest = getattr(c, "rest", {}) or getattr(c, "_rest", {}) or {}
                httponly_flag = ("HttpOnly" in rest) or ("httponly" in rest)
                samesite_val = rest.get("SameSite") or rest.get("samesite")

            # Build row + log warnings
            if not secure_flag:
                logging.warning(f"Cookie '{c.name}' missing Secure flag.")
            if not httponly_flag:
                logging.warning(f"Cookie '{c.name}' missing HttpOnly flag.")
            if not samesite_val:
                logging.warning(f"Cookie '{c.name}' missing SameSite attribute.")

            rows.append([
                c.name,
                "✅" if secure_flag else "❌",
                "✅" if httponly_flag else "❌",
                samesite_val if samesite_val else "❌"
            ])

            result.append({
                "name": c.name,
                "secure": secure_flag,
                "httponly": httponly_flag,
                "samesite": samesite_val
            })

        # Pretty print
        print("\n=== Cookie Security Flags Check ===")
        if PrettyTable:
            table = PrettyTable()
            table.field_names = ["Cookie Name", "Secure", "HttpOnly", "SameSite"]
            for r in rows:
                table.add_row(r)
            print(table, "\n")
        else:
            # Plain fallback
            print("Cookie Name\tSecure\tHttpOnly\tSameSite")
            for r in rows:
                print("\t".join(map(str, r)))
            print()

        return {"found": True, "cookies": result}

    except requests.RequestException as e:
        logging.error(f"Error checking cookies: {e}")
        return {"found": False, "cookies": []}

# ====== Existing features (placeholder) ======
def is_valid_url(url: str) -> bool:
    return validators.url(url)

# --- TLS/HTTPS Scan ---
def check_tls_https(base_url: str):
    """
    Checks SSL/TLS certificate validity and expiry for the given site.
    Returns a dict with certificate info.
    """
    try:
        hostname = base_url.replace("https://", "").replace("http://", "").split("/")[0]
        port = 443

        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                # Extract expiry date
                expiry_str = cert.get("notAfter")
                expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry_date - datetime.utcnow()).days

                logging.info(f"TLS Certificate for {hostname}: valid until {expiry_date} ({days_left} days left)")

                # Warnings
                if days_left < 30:
                    logging.warning(f"Certificate will expire in {days_left} days!")
                if days_left < 0:
                    logging.error("Certificate has expired!")

                # Get protocol version used
                protocol = ssock.version()
                logging.info(f"TLS/SSL Protocol: {protocol}")

                print("\n=== TLS/HTTPS Scan ===")
                print(f"Hostname: {hostname}")
                print(f"Certificate Expiry: {expiry_date} ({days_left} days left)")
                print(f"TLS Protocol: {protocol}\n")

                return {
                    "hostname": hostname,
                    "expiry_date": expiry_date,
                    "days_left": days_left,
                    "protocol": protocol
                }

    except Exception as e:
        logging.error(f"Error checking TLS/HTTPS: {e}")
        print(f"[!] Could not check TLS for {base_url}: {e}")
        return None

# ====== MAIN SCAN ======
if __name__ == "__main__":
    import os
    print(f"[i] Current working directory: {os.getcwd()}")

    # --- Improved input prompt and error handling ---
    import sys
    if not sys.stdin.isatty():
        print("[!] Interactive input is not supported in this environment. Run this script in a terminal to enter a URL.")
        target_url = "https://example.com"
    else:
        try:
            target_url = input("Enter URL to scan: ").strip()
            if not target_url:
                print("[!] No input detected. Using default URL: https://example.com")
                target_url = "https://example.com"
        except Exception as e:
            print(f"[!] Input error: {e}. Using default URL: https://example.com")
            target_url = "https://example.com"

    print(f"[*] Scanning {target_url}...\n")

    # --- Validate URL and provide clear error message ---
    if not is_valid_url(target_url):
        print(f"[!] Invalid URL: {target_url}\nPlease enter a valid URL starting with http:// or https://")
        exit(1)

    # --- Call robots.txt + path check ---
    results = check_robots_and_paths(target_url)
    for line in results:
        print(line)

    # --- Cookie Security Flags Check ---
    cookie_results = check_cookie_flags(target_url)
    print("\n[+] Cookie Results:", cookie_results)

    # --- Fetch and process response from target_url ---
    import requests
    try:
        response = requests.get(target_url)
        print("\n[+] Response lines:")
        # Only print first 20 lines for readability
        for i, line in enumerate(response.text.splitlines()):
            print(line)
            if i >= 19:
                print("... (output truncated) ...")
                break
    except Exception as e:
        print(f"[!] Error fetching {target_url}: {e}")

    # --- TLS/HTTPS Scan ---
    tls_results = check_tls_https(target_url)
    print("\n[+] TLS/HTTPS Results:", tls_results)
