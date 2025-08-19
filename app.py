from flask import Flask, render_template, request
from websec_analyzer.scanner import detect_sql_injection, detect_xss, check_csrf_token, check_security_headers
import requests

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    error = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            error = 'Please enter a URL.'
        else:
            try:
                response = requests.get(url)
                headers_result = check_security_headers(response.headers)
                sqli_result = detect_sql_injection(url)
                xss_result = detect_xss(url)
                csrf_result = check_csrf_token(response.text)

                # New features
                from websec_analyzer.scanner import check_tls_https, check_cookie_flags, check_robots_and_paths
                tls_result = check_tls_https(url)
                cookie_result = check_cookie_flags(url)
                robots_result = check_robots_and_paths(url)

                result = {
                    'url': url,
                    'headers': headers_result,
                    'sqli': sqli_result,
                    'xss': xss_result,
                    'csrf': csrf_result,
                    'tls': tls_result,
                    'cookies': cookie_result,
                    'robots': robots_result
                }
            except Exception as e:
                error = f'Error fetching URL: {e}'
    return render_template('index.html', result=result, error=error)

if __name__ == '__main__':
    app.run(debug=True)
