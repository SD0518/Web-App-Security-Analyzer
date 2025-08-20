from flask import Flask, render_template, request, Response
from websec_analyzer.scanner import detect_sql_injection, detect_xss, check_csrf_token, check_security_headers
from websec_analyzer.report_generator import generate_report_bytes
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
    
    # Use new enhanced template
    return render_template('index_new.html', result=result, error=error)

# New route for PDF report download
@app.route('/download-report')
def download_report():
    """Generate and download PDF report for the scanned URL"""
    url = request.args.get('url', '')
    if not url:
        return "No URL provided", 400
    
    try:
        # Re-run scan to get fresh data for PDF
        response = requests.get(url)
        headers_result = check_security_headers(response.headers)
        sqli_result = detect_sql_injection(url)
        xss_result = detect_xss(url)
        csrf_result = check_csrf_token(response.text)
        
        from websec_analyzer.scanner import check_tls_https, check_cookie_flags, check_robots_and_paths
        tls_result = check_tls_https(url)
        cookie_result = check_cookie_flags(url)
        robots_result = check_robots_and_paths(url)
        
        # Prepare data for PDF generation
        report_data = {
            'target': url,
            'security_headers': {k: ('Missing' if v else 'Present') for k, v in headers_result.items()},
            'vulnerabilities': {
                'SQL Injection': 'Vulnerable' if sqli_result else 'Safe',
                'XSS': 'Vulnerable' if xss_result else 'Safe',
                'CSRF Protection': 'Protected' if csrf_result else 'Missing'
            },
            'tls_https': tls_result,
            'cookies': cookie_result.get('cookies', []) if cookie_result else [],
            'robots': robots_result or []
        }
        
        # Generate PDF
        pdf_data = generate_report_bytes(report_data)
        
        # Create response with PDF
        response = Response(pdf_data, mimetype='application/pdf')
        response.headers['Content-Disposition'] = f'attachment; filename=security_report_{url.replace("://", "_").replace("/", "_")}.pdf'
        return response
        
    except Exception as e:
        return f"Error generating report: {e}", 500

if __name__ == '__main__':
    app.run(debug=True)
