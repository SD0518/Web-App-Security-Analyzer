import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from websec_analyzer.scanner import detect_sql_injection, detect_xss, check_csrf_token, check_security_headers
import requests

def test_scan(url):
    print(f"Scanning URL: {url}\n")

    try:
        response = requests.get(url)
    except Exception as e:
        print(f"Failed to fetch URL: {e}")
        return

    # Check for missing security headers
    missing_headers = check_security_headers(response.headers)
    print("Missing Security Headers:")
    for header, missing in missing_headers.items():
        print(f" - {header}: {'Missing' if missing else 'Present'}")

    # Detect SQL Injection patterns in the URL
    if detect_sql_injection(url):
        print("Potential SQL Injection pattern detected in URL.")
    else:
        print("No SQL Injection patterns detected in URL.")

    # Detect XSS patterns in the URL
    if detect_xss(url):
        print("Potential XSS pattern detected in URL.")
    else:
        print("No XSS patterns detected in URL.")

    # Check CSRF token presence in the HTML forms
    if check_csrf_token(response.text):
        print("CSRF token detected in form(s).")
    else:
        print("CSRF token missing in form(s).")

if __name__ == "__main__":
    test_url = input("Enter URL to test scan: ")
    test_scan(test_url)
