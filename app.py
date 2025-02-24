from flask import Flask, render_template, request, jsonify, send_file
from bs4 import BeautifulSoup
import requests
import threading
import concurrent.futures
from urllib.parse import urljoin, urlparse
import re
import io
import json
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

app = Flask(__name__)

class WebScanner:
    def __init__(self):
        self.stop_scraping = False
        self.session = self._create_session()
        self.vulnerabilities = []
        
    def _create_session(self):
        session = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retries, pool_connections=10, pool_maxsize=10)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
        return session

    def get_risk_and_solution(self, vulnerability):
        risk_solution = {
            "Server information exposed": (
                "High risk of targeted attacks",
                "Hide server information using server configuration."
            ),
            "Insecure cookies": (
                "Session hijacking, XSS attacks",
                "Set 'Secure' and 'HttpOnly' flags for cookies."
            ),
            "Missing Content Security Policy": (
                "Cross-Site Scripting (XSS)",
                "Implement a strong CSP header to prevent XSS."
            ),
            "Missing X-Frame-Options": (
                "Clickjacking attacks",
                "Add 'X-Frame-Options' header to prevent clickjacking."
            ),
            "Missing X-XSS-Protection": (
                "XSS attacks",
                "Enable X-XSS-Protection header for older browsers."
            ),
            "Exposed emails": (
                "Email harvesting, spam",
                "Use obfuscation or remove email addresses from public pages."
            ),
            "Insecure form": (
                "Data interception, MITM attacks",
                "Use HTTPS for secure form submissions."
            ),
            "Vulnerable jQuery version": (
                "Exploitable JavaScript vulnerabilities",
                "Update jQuery to the latest version."
            ),
            "Open directory listing": (
                "Sensitive information exposure",
                "Disable directory listing in server configuration."
            ),
            "Public admin panel": (
                "Unauthorized access to backend",
                "Restrict access using authentication or IP whitelisting."
            )
        }
        return risk_solution.get(vulnerability, ("Unknown risk", "No solution available"))

    def check_security_headers(self, headers):
        security_issues = []
        
        if 'Server' in headers:
            security_issues.append({
                'type': 'Server information exposed',
                'details': headers['Server']
            })

        if 'Set-Cookie' in headers:
            cookies = headers['Set-Cookie']
            if 'Secure' not in cookies or 'HttpOnly' not in cookies:
                security_issues.append({
                    'type': 'Insecure cookies',
                    'details': cookies
                })

        important_headers = {
            'Content-Security-Policy': 'Missing Content Security Policy',
            'X-Frame-Options': 'Missing X-Frame-Options',
            'X-XSS-Protection': 'Missing X-XSS-Protection',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options',
            'Strict-Transport-Security': 'Missing HSTS'
        }

        for header, issue in important_headers.items():
            if header not in headers:
                security_issues.append({
                    'type': issue,
                    'details': f'{header} header not found'
                })

        return security_issues

    def check_content_vulnerabilities(self, url, soup):
        vulnerabilities = []

        # Check for exposed email addresses
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', str(soup))
        if emails:
            vulnerabilities.append({
                'type': 'Exposed emails',
                'details': ', '.join(emails)
            })

        # Check for insecure forms
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            if action and not action.startswith('https://'):
                vulnerabilities.append({
                    'type': 'Insecure form',
                    'details': f'Form action: {action}'
                })

        # Check for vulnerable jQuery versions
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script['src']
            if 'jquery' in src.lower():
                version_match = re.search(r'jquery[.-](\d+\.\d+\.\d+)', src.lower())
                if version_match:
                    version = version_match.group(1)
                    if version.startswith(('1.', '2.')):
                        vulnerabilities.append({
                            'type': 'Vulnerable jQuery version',
                            'details': f'jQuery version {version} detected'
                        })

        # Check for directory listing
        if soup.title and 'Index of' in soup.title.string:
            vulnerabilities.append({
                'type': 'Open directory listing',
                'details': url
            })

        return vulnerabilities

    def check_admin_path(self, base_url, path):
        try:
            url = urljoin(base_url, path)
            response = self.session.get(url, timeout=5)
            if response.status_code == 200:
                return {
                    'type': 'Public admin panel',
                    'details': url
                }
        except requests.exceptions.RequestException:
            pass
        return None

    def scan_admin_panels(self, base_url):
        admin_paths = [
            '/admin', '/login', '/dashboard', '/administrator',
            '/wp-admin', '/controlpanel', '/admin.php'
        ]
        
        vulnerabilities = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(self.check_admin_path, base_url, path)
                for path in admin_paths
            ]
            
            for future in concurrent.futures.as_completed(futures):
                if self.stop_scraping:
                    break
                result = future.result()
                if result:
                    vulnerabilities.append(result)
                
        return vulnerabilities

    def scan_website(self, url):
        try:
            url = self.validate_url(url)
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            all_vulnerabilities = []
            
            # Check security headers
            header_issues = self.check_security_headers(response.headers)
            all_vulnerabilities.extend(header_issues)
            
            # Check content vulnerabilities
            content_issues = self.check_content_vulnerabilities(url, soup)
            all_vulnerabilities.extend(content_issues)
            
            # Scan for admin panels
            admin_issues = self.scan_admin_panels(url)
            all_vulnerabilities.extend(admin_issues)
            
            # Add risk and solution for each vulnerability
            for vuln in all_vulnerabilities:
                risk, solution = self.get_risk_and_solution(vuln['type'])
                vuln['risk'] = risk
                vuln['solution'] = solution
            
            return all_vulnerabilities
            
        except Exception as e:
            raise Exception(f"Scan failed: {str(e)}")

    def validate_url(self, url):
        if not url:
            raise ValueError("URL cannot be empty")
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        try:
            result = urlparse(url)
            if not all([result.scheme, result.netloc]):
                raise ValueError("Invalid URL format")
        except Exception as e:
            raise ValueError(f"Invalid URL: {str(e)}")
            
        return url

    def stop(self):
        self.stop_scraping = True
        self.session.close()

scanner = WebScanner()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.json.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        vulnerabilities = scanner.scan_website(url)
        return jsonify({
            'status': 'success',
            'vulnerabilities': vulnerabilities
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400

@app.route('/export', methods=['POST'])
def export():
    vulnerabilities = request.json.get('vulnerabilities')
    if not vulnerabilities:
        return jsonify({'error': 'No results to export'}), 400
    
    output = io.StringIO()
    output.write("=== Scan Results ===\n\n")
    
    for vuln in vulnerabilities:
        output.write(f"Vulnerability: {vuln['type']}\n")
        output.write(f"Details: {vuln['details']}\n")
        output.write(f"Risk: {vuln['risk']}\n")
        output.write(f"Solution: {vuln['solution']}\n")
        output.write("-" * 50 + "\n")
    
    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8'))
    mem.seek(0)
    output.close()
    
    return send_file(
        mem,
        mimetype='text/plain',
        as_attachment=True,
        download_name='scan_results.txt'
    )

if __name__ == '__main__':
    app.run(debug=True)