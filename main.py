
# =============================
# main.py (Legacy CLI Entrypoint)
# =============================
# This file previously provided a CLI for the security analyzer.
# The application now uses a Flask web UI (see app.py).
#
# If you want to use the CLI, uncomment the code below.
# Otherwise, run `python app.py` to use the web interface.

# from websec_analyzer.utils import is_valid_url, log_info, log_error
# from websec_analyzer.scanner import detect_sql_injection, detect_xss, check_csrf_token, check_security_headers
# import requests
#
# def main():
#     url = input("Enter the target URL: ").strip()
#     if not is_valid_url(url):
#         log_error(f"Invalid URL: {url}")
#         print("❌ Invalid URL format. Please try again.")
#         return
#     log_info(f"Valid URL entered: {url}")
#     print(f"✅ Scanning will start for: {url}")
#
# def run_scan(url):
#     response = requests.get(url)
#     # Check security headers
#     missing_headers = check_security_headers(response.headers)
#     print("Missing Headers:", missing_headers)
#     # Scan URL for SQLi and XSS
#     if detect_sql_injection(url):
#         print("Potential SQL Injection pattern detected in URL.")
#     if detect_xss(url):
#         print("Potential XSS pattern detected in URL.")
#     # Check CSRF tokens in forms
#     if not check_csrf_token(response.text):
#         print("CSRF token missing in forms.")
#
# if __name__ == "__main__":
#     main()
#     target_url = input("Enter URL to scan: ")
#     run_scan(target_url)
