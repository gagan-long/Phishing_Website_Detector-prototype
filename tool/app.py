import streamlit as st
from urllib.parse import urlparse, urljoin
import re
import whois
import ssl
import requests
import socket
from bs4 import BeautifulSoup
import json
from concurrent.futures import ThreadPoolExecutor
import os
from dotenv import load_dotenv
import datetime

# --- Screenshot dependencies ---
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from PIL import Image
import io
import time
import base64

from selenium.webdriver.chrome.service import Service



import re

def extract_links(text):
    # Regex for URLs (http, https, www)
    url_pattern = r'(https?://\S+|www\.\S+)'
    return re.findall(url_pattern, text)


def extract_dom_clues(url, timeout=10):
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--window-size=1200,900")

        # Proper driver initialization for Selenium 4.6+
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)

        driver.set_page_load_timeout(timeout)
        driver.get(url)
        time.sleep(2)  # Allow page to load

        forms = driver.find_elements(By.TAG_NAME, "form")
        password_inputs = driver.find_elements(By.XPATH, "//input[@type='password']")
        external_scripts = driver.find_elements(By.XPATH, "//script[@src]")
        images = driver.find_elements(By.TAG_NAME, "img")
        visible_text = driver.find_element(By.TAG_NAME, "body").text.lower()

        suspicious_keywords = [
            "password", "login", "verify", "account", "bank", "urgent", "reset", "confirm", "ssn", "credit card"
        ]
        found_keywords = [kw for kw in suspicious_keywords if kw in visible_text]

        driver.quit()
        return {
            "forms": len(forms),
            "password_inputs": len(password_inputs),
            "external_scripts": len(external_scripts),
            "images": len(images),
            "found_keywords": found_keywords
        }, None
    except Exception as e:
        return None, str(e)

def phishing_quiz():
    st.subheader("🎓 Phishing Awareness Self-Test")
    st.markdown("Test your ability to spot phishing attempts. Can you get all questions right?")

    score = 0

    q1 = st.radio(
        "1️⃣ You receive an email from 'support@micros0ft.com' asking you to reset your password urgently. The link looks like 'http://micros0ft-support.com/reset'. What should you do?",
        [
            "Click the link and reset your password.",
            "Ignore the email or report it as phishing.",
            "Reply to the sender for more info."
        ],
        key="quiz_q1"
    )
    if q1 == "Ignore the email or report it as phishing.":
        score += 1

    q2 = st.radio(
        "2️⃣ A website uses HTTPS and has a green padlock. Does this always mean it's safe?",
        [
            "Yes, HTTPS means the site is always safe.",
            "No, phishing sites can also use HTTPS."
        ],
        key="quiz_q2"
    )
    if q2 == "No, phishing sites can also use HTTPS.":
        score += 1

    q3 = st.radio(
        "3️⃣ You see a login form on a website that looks like your bank, but the URL is 'bankofarnerica.com'. What should you do?",
        [
            "Enter your credentials to see if it works.",
            "Check the URL carefully and do not enter credentials.",
            "Call the phone number on the website."
        ],
        key="quiz_q3"
    )
    if q3 == "Check the URL carefully and do not enter credentials.":
        score += 1

    if st.button("Submit Quiz"):
        if score == 3:
            st.success("🎉 Excellent! You got all answers right.")
        else:
            st.warning(f"You scored {score}/3. Review the explanations below:")
            if q1 != "Ignore the email or report it as phishing.":
                st.info("Q1: The sender's address is suspicious (note the '0' instead of 'o'), and the link is not official. Never click such links.")
            if q2 != "No, phishing sites can also use HTTPS.":
                st.info("Q2: HTTPS only means the connection is encrypted, not that the site is trustworthy.")
            if q3 != "Check the URL carefully and do not enter credentials.":
                st.info("Q3: The URL is a lookalike (note the 'r' instead of 'm'). Always check URLs carefully.")

    st.markdown("---")


COMMUNITY_VOTES_FILE = "community_votes.json"

def load_community_votes():
    try:
        with open(COMMUNITY_VOTES_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception:
        return {}

def save_community_votes(votes):
    with open(COMMUNITY_VOTES_FILE, "w") as f:
        json.dump(votes, f, indent=2)

def add_community_vote(domain, verdict):
    votes = load_community_votes()
    domain = domain.lower()
    if domain not in votes:
        votes[domain] = {"phishing": 0, "safe": 0}
    if verdict == "phishing":
        votes[domain]["phishing"] += 1
    elif verdict == "safe":
        votes[domain]["safe"] += 1
    save_community_votes(votes)


def get_community_verdict(domain):
    votes = load_community_votes()
    domain = domain.lower()
    if domain in votes:
        phishing = votes[domain]["phishing"]
        safe = votes[domain]["safe"]
        total = phishing + safe
        if total == 0:
            return "No community reports yet.", phishing, safe
        verdict = "Phishing" if phishing > safe else "Safe" if safe > phishing else "Mixed"
        return f"Community verdict: {verdict} ({phishing} phishing, {safe} safe)", phishing, safe
    else:
        return "No community reports yet.", 0, 0


def update_blacklist_from_feeds():
    """
    Fetches the latest phishing domains from multiple open threat feeds and merges with your blacklist.
    """
    FEEDS = {
        "PhishTank": "http://data.phishtank.com/data/online-valid.csv",
        "OpenPhish": "https://openphish.com/feed.txt",
        "URLhaus": "https://urlhaus.abuse.ch/downloads/text/"
    }
    all_domains = set()
    messages = []
    for name, url in FEEDS.items():
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code != 200:
                messages.append(f"{name}: Failed to fetch ({resp.status_code}).")
                continue
            if name == "PhishTank":
                lines = resp.text.splitlines()
                for line in lines[1:]:
                    parts = line.split('","')
                    if len(parts) > 1:
                        phish_url = parts[1].strip('"')
                        parsed = urlparse(phish_url)
                        domain = parsed.netloc.lower()
                        if domain:
                            all_domains.add(domain)
                messages.append(f"{name}: {len(lines)-1} entries processed.")
            else:
                # OpenPhish and URLhaus are plain text, one URL per line
                lines = resp.text.splitlines()
                count = 0
                for line in lines:
                    if line.startswith("#") or not line.strip():
                        continue
                    parsed = urlparse(line.strip())
                    domain = parsed.netloc.lower()
                    if domain:
                        all_domains.add(domain)
                        count += 1
                messages.append(f"{name}: {count} entries processed.")
        except Exception as e:
            messages.append(f"{name}: Error - {e}")
    # Merge with existing blacklist
    existing = set(load_blacklist())
    merged = sorted(existing.union(all_domains))
    save_blacklist(list(merged))
    return True, f"Blacklist updated from {len(FEEDS)} feeds. {len(all_domains)} new domains added.\n" + "\n".join(messages)




# --- Screenshot Helper ---

def take_screenshot(url, width=1200, height=900, timeout=10):
    try:
        chrome_options = webdriver.ChromeOptions()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument(f"--window-size={width},{height}")
        chrome_options.add_argument("--disable-dev-shm-usage")
        
        # Use Service() for proper driver initialization
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        
        driver.set_page_load_timeout(timeout)
        driver.get(url)
        time.sleep(2)  # Allow JavaScript/async content to load
        png = driver.get_screenshot_as_png()
        driver.quit()
        
        image = Image.open(io.BytesIO(png))
        return image, None
    except Exception as e:
        return None, str(e)

# --- Load VirusTotal API Key Securely ---
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY", "")

# --- VirusTotal Threat Intelligence Function ---
def check_virustotal_url(url, api_key):
    if not api_key:
        return {"error": "No VirusTotal API key provided."}
    
    # Encode URL for VirusTotal ID
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": "PhishingDetector/1.0"
    }
    
    try:
        # Check existing report first (free tier limited to 4 req/min)
        report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        report = requests.get(report_url, headers=headers)
        
        # If not found, submit for analysis
        if report.status_code == 404:
            submit_url = "https://www.virustotal.com/api/v3/urls"
            data = {"url": url}
            resp = requests.post(
                submit_url,
                headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
                data=data
            )
            
            if resp.status_code not in (200, 201):
                return {"error": f"Submission failed: {resp.status_code} - {resp.text}"}
            
            # Wait for analysis completion (free tier has delays)
            time.sleep(15)
            report = requests.get(report_url, headers=headers)
        
        if report.status_code != 200:
            return {"error": f"Report fetch failed: {report.status_code} - {report.text}"}
        
        data = report.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        
        verdict = "clean"
        if stats.get("malicious", 0) > 5:
            verdict = "malicious"
        elif stats.get("suspicious", 0) > 2 or stats.get("malicious", 0) > 0:
            verdict = "suspicious"
            
        return {
            "verdict": verdict,
            "stats": stats,
            "scan_date": data.get("last_analysis_date"),
            "permalink": f"https://www.virustotal.com/gui/url/{url_id}"
        }
        
    except Exception as e:
        return {"error": str(e)}

# --- Blacklist Data ---
def load_blacklist():
    try:
        with open('tool/blacklist.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []
    except Exception:
        return []

def save_blacklist(blacklist):
    with open('tool/blacklist.json', 'w') as f:
        json.dump(blacklist, f, indent=2)

def add_to_blacklist(domain):
    blacklist = load_blacklist()
    if domain not in blacklist:
        blacklist.append(domain)
        save_blacklist(blacklist)
        st.info(f"Domain {domain} has been added to the blacklist.")

# --- Typosquatting & Lookalike Detection ---
POPULAR_BRANDS = [
    # Tech & Email
    "google.com", "gmail.com", "youtube.com", "apple.com", "icloud.com", "microsoft.com", "outlook.com", "office.com", "live.com",
    "yahoo.com", "aol.com", "protonmail.com", "zoho.com", "mail.com", "gmx.com",

    # Social Media & Messaging
    "facebook.com", "instagram.com", "whatsapp.com", "messenger.com", "twitter.com", "linkedin.com", "tiktok.com", "snapchat.com",
    "reddit.com", "pinterest.com", "discord.com", "telegram.org", "slack.com",

    # Shopping & Payments
    "amazon.com", "ebay.com", "alibaba.com", "aliexpress.com", "walmart.com", "flipkart.com", "shopify.com",
    "paypal.com", "stripe.com", "square.com", "paytm.com", "venmo.com", "skrill.com",

    # Banks & Financial
    "bankofamerica.com", "wellsfargo.com", "chase.com", "citibank.com", "capitalone.com", "americanexpress.com",
    "hsbc.com", "barclays.com", "td.com", "usbank.com", "boa.com", "discover.com",

    # Developer & Cloud
    "github.com", "gitlab.com", "bitbucket.org", "digitalocean.com", "aws.amazon.com", "azure.com", "cloudflare.com",
    "heroku.com", "netlify.com", "vercel.com", "dropbox.com", "box.com", "drive.google.com",

    # Government & Health
    "irs.gov", "gov.uk", "usa.gov", "nhs.uk", "cdc.gov", "who.int",

    # Others
    "netflix.com", "spotify.com", "hulu.com", "zoom.us", "uber.com", "airbnb.com", "booking.com", "expedia.com",
    "wordpress.com", "medium.com", "quora.com", "tumblr.com", "salesforce.com"
]


def generate_typos(domain):
    typos = set()
    if '.' in domain:
        name, tld = domain.rsplit('.', 1)
    else:
        name, tld = domain, ''
    # Missing dot
    typos.add(name.replace('.', '') + ('.' + tld if tld else ''))
    # Swapped adjacent letters
    for i in range(len(name) - 1):
        swapped = list(name)
        swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
        typos.add(''.join(swapped) + ('.' + tld if tld else ''))
    # Missing letter
    for i in range(len(name)):
        typos.add(name[:i] + name[i+1:] + ('.' + tld if tld else ''))
    return typos

def calculate_risk_score(details):
    score = 0
    if details.get('has_at_symbol') == 'Yes':
        score += 5
    if details.get('url_length', 0) > 50:
        score += 10
    if details.get('uses_https') == 'No':
        score += 15
    if details.get('domain_age') == 'N/A':
        score += 10
    if details.get('has_ip_address') == 'Yes':
        score += 20
    if details.get('has_login_form') == 'Yes':
        score += 25
    if details.get('requests_sensitive_info') == 'Yes':
        score += 30
    if details.get('has_unusual_scripts') == 'Yes':
        score += 20
    return score

def crawl_website(target_url):
    base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
    session = requests.Session()
    found_paths = set(['/'])
    def check_path(path):
        try:
            full_url = urljoin(base_url, path)
            response = session.head(full_url, timeout=3, allow_redirects=True)
            if response.status_code < 400:
                return path
        except:
            return None
    common_dirs = [
        'admin', 'login', 'dashboard', 'controlpanel', 
        'wp-admin', 'wp-content', 'wp-includes', 'wp-login',
        'images', 'css', 'js', 'assets', 'uploads', 'media',
        'backup', 'backups', 'api', 'secret', 'private', 
        'tmp', 'temp', 'logs', 'sql', 'db', 'database',
        'cgi-bin', 'includes', 'src', 'lib', 'config',
        'vendor', 'node_modules', '.git', '.svn', '.hg'
    ]

    common_files = [
    'robots.txt', 'sitemap.xml', 'sitemap_index.xml',
    'config.php', 'wp-config.php', 'config.json', 
    'config.yml', 'config.ini', 'settings.py',
    '.env', '.env.example', '.env.local', 
    'package.json', 'package-lock.json', 'yarn.lock',
    'composer.json', 'composer.lock', 'Gemfile',
    'web.config', '.htaccess', 'htpasswd',
    'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
    'error.log', 'access.log', 'debug.log',
    'backup.sql', 'dump.sql', 'backup.zip', 
    'crossdomain.xml', 'security.txt', 'phpinfo.php',
    'LICENSE.txt', 'README.md', 'CHANGELOG.txt',
    '.DS_Store', 'Thumbs.db', 'desktop.ini',
    'service-worker.js', 'manifest.json'
    ]

    with ThreadPoolExecutor(max_workers=10) as executor:
        dir_paths = [f"/{d}/" for d in common_dirs]
        found_paths.update(filter(None, executor.map(check_path, dir_paths)))
        file_paths = [f"/{f}" for f in common_files]
        found_paths.update(filter(None, executor.map(check_path, file_paths)))
    return sorted(found_paths)

def extract_details(url):
    details = {}
    try:
        parsed_url = urlparse(url)
        details['has_at_symbol'] = 'Yes' if '@' in url else 'No'
        details['url_length'] = len(url)
        details['found_paths'] = crawl_website(url)
        details['uses_https'] = 'Yes' if parsed_url.scheme == 'https' else 'No'
        domain = parsed_url.netloc

        # --- Typosquatting & lookalike detection ---
        domain_lower = domain.lower()
        typos = generate_typos(domain_lower)
        lookalike_matches = []
        for brand in POPULAR_BRANDS:
            brand_base = brand.lower()
            if (domain_lower == brand_base or
                domain_lower.replace('www.', '') == brand_base or
                brand_base in typos):
                lookalike_matches.append(brand)
        details['lookalike_brands'] = lookalike_matches if lookalike_matches else None

        try:
            w = whois.whois(domain)
            details['domain_age'] = str(w.creation_date)
            details['registrar'] = w.registrar if hasattr(w, 'registrar') else 'N/A'
        except Exception as e:
            details['whois_error'] = str(e)
            details['domain_age'] = 'N/A'
            details['registrar'] = 'N/A'

        # --- SSL/TLS Certificate Transparency ---
        if parsed_url.scheme == 'https':
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        issuer = cert.get('issuer', (('N/A',),))[0]
                        issuer_name = " ".join([x[1] for x in issuer]) if isinstance(issuer, tuple) else str(issuer)
                        not_before = cert.get('notBefore', 'N/A')
                        not_after = cert.get('notAfter', 'N/A')
                        details['ssl_issuer'] = issuer_name
                        details['ssl_valid_from'] = not_before
                        details['ssl_valid_to'] = not_after
                        # Calculate certificate age
                        try:
                            valid_from_dt = datetime.datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                            valid_to_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            now = datetime.datetime.utcnow()
                            cert_age_days = (now - valid_from_dt).days
                            details['ssl_age_days'] = cert_age_days
                            details['ssl_is_new'] = "Yes" if cert_age_days <= 30 else "No"
                            details['ssl_days_left'] = (valid_to_dt - now).days
                        except Exception as e:
                            details['ssl_age_days'] = 'N/A'
                            details['ssl_is_new'] = 'N/A'
                            details['ssl_days_left'] = 'N/A'
                        # Self-signed or suspicious issuer
                        if "let's encrypt" in issuer_name.lower():
                            details['ssl_issuer_warning'] = "Let's Encrypt (free cert, check carefully)"
                        elif "self" in issuer_name.lower():
                            details['ssl_issuer_warning'] = "Self-signed certificate"
                        else:
                            details['ssl_issuer_warning'] = ""
            except Exception as e:
                details['ssl_error'] = str(e)
                details['ssl_issuer'] = 'N/A'
                details['ssl_valid_from'] = 'N/A'
                details['ssl_valid_to'] = 'N/A'
                details['ssl_age_days'] = 'N/A'
                details['ssl_is_new'] = 'N/A'
                details['ssl_days_left'] = 'N/A'
                details['ssl_issuer_warning'] = ''
        else:
            details['ssl_issuer'] = 'N/A'
            details['ssl_valid_from'] = 'N/A'
            details['ssl_valid_to'] = 'N/A'
            details['ssl_age_days'] = 'N/A'
            details['ssl_is_new'] = 'N/A'
            details['ssl_days_left'] = 'N/A'
            details['ssl_issuer_warning'] = ''

        try:
            response = requests.get(parsed_url.scheme + '://' + parsed_url.netloc + '/favicon.ico', timeout=5)
            details['has_favicon'] = 'Yes' if response.status_code == 200 else 'No'
        except Exception as e:
            details['favicon_error'] = str(e)
            details['has_favicon'] = 'No'
        details['has_ip_address'] = 'Yes' if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed_url.netloc) else 'No'
        details['is_long_url'] = 'Yes' if len(url) > 50 else 'No'
        details['has_unusual_chars'] = 'Yes' if re.search(r'[^a-zA-Z0-9\-\._~:\/\?#\[\]@!\$&\'\(\)\*\+\,\;\=]', url) else 'No'
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            login_form = soup.find('form', {'action': re.compile(r'login', re.IGNORECASE)})
            details['has_login_form'] = 'Yes' if login_form else 'No'
            sensitive_info_patterns = [r'credit card', r'social security number', r'ssn', r'cvv']
            content = soup.get_text().lower()
            details['requests_sensitive_info'] = 'Yes' if any(re.search(pattern, content) for pattern in sensitive_info_patterns) else 'No'
            script_tags = soup.find_all('script')
            details['has_unusual_scripts'] = 'Yes' if any('eval(' in script.text for script in script_tags) else 'No'
        except Exception as e:
            details['content_error'] = str(e)
            details['has_login_form'] = 'N/A'
            details['requests_sensitive_info'] = 'N/A'
            details['has_unusual_scripts'] = 'N/A'
        details['is_blacklisted'] = 'Yes' if domain in load_blacklist() else 'No'
    except Exception as e:
        details['error'] = str(e)
    return details

# --- Port Scan Feature ---
PORT_SERVICE_MAP = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    37: "Time",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    119: "NNTP",
    123: "NTP",
    135: "MS RPC",
    137: "NetBIOS Name",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    179: "BGP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "Printer (LPD)",
    520: "RIP",
    587: "SMTP (submission)",
    631: "IPP (CUPS Printing)",
    636: "LDAPS",
    873: "rsync",
    902: "VMware Server",
    989: "FTPS Data",
    990: "FTPS Control",
    993: "IMAPS",
    995: "POP3S",
    1025: "NFS or IIS",
    1080: "SOCKS Proxy",
    1194: "OpenVPN",
    1433: "MSSQL",
    1434: "MSSQL Monitor",
    1521: "Oracle DB",
    1723: "PPTP",
    1812: "RADIUS",
    1813: "RADIUS Accounting",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel SSL",
    2100: "Oracle XDB",
    2222: "DirectAdmin",
    2375: "Docker API",
    2376: "Docker API SSL",
    2483: "Oracle DB",
    2484: "Oracle DB SSL",
    3306: "MySQL",
    3389: "RDP",
    3690: "Subversion",
    4000: "ICQ",
    4040: "HTTP Proxy",
    4369: "Erlang Port Mapper",
    5000: "UPnP / Flask",
    5060: "SIP",
    5432: "PostgreSQL",
    5500: "VNC",
    5631: "PCAnywhere",
    5900: "VNC",
    6000: "X11",
    6379: "Redis",
    6660: "IRC",
    6667: "IRC",
    7001: "WebLogic",
    8000: "HTTP-alt",
    8008: "HTTP-alt",
    8080: "HTTP-alt",
    8081: "HTTP-alt",
    8443: "HTTPS-alt",
    8888: "HTTP-alt",
    9000: "SonarQube / PHP-FPM",
    9090: "WebSM / HTTP-alt",
    9200: "Elasticsearch",
    10000: "Webmin",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB",
    27019: "MongoDB",
    27020: "MongoDB",
    50000: "DB2",
    50070: "Hadoop NameNode",
    50075: "Hadoop DataNode",
    61616: "ActiveMQ",
    63790: "Redis-alt",
    # Add more as needed
}


def port_scan(target, port_range=(1, 1024), max_threads=100):
    open_ports = []
    closed_ports = []
    target_ip = None
    
    try:
        target_ip = socket.gethostbyname(target)
    except Exception as e:
        return [], [], f"Could not resolve domain to IP: {str(e)}"

    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((target_ip, port))
                if result == 0:
                    service = PORT_SERVICE_MAP.get(port, "Unknown")
                    return (port, service)
        except Exception:
            pass
        return None

    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(scan_port, port) 
                      for port in range(port_range[0], port_range[1] + 1)]
            
            open_ports = [future.result() for future in futures 
                         if future.result() is not None]

        open_ports.sort(key=lambda x: x[0])
        closed_ports = [port for port in range(port_range[0], port_range[1] + 1)
                       if port not in [p[0] for p in open_ports]]
        
        return open_ports, closed_ports, None

    except Exception as e:
        return [], [], f"Port scan failed: {str(e)}"


# --- Text/Message Analysis Feature ---
def analyze_text(text):
    phishing_keywords = [
        "urgent", "verify your account", "update your information", "click here", "password", "login", "bank", "account suspended",
        "security alert", "unusual activity", "confirm", "reset", "limited time", "act now", "win", "free", "prize", "invoice"
    ]
    url_pattern = r'(https?://[^\s]+)'
    found_keywords = [kw for kw in phishing_keywords if kw in text.lower()]
    found_links = re.findall(url_pattern, text)
    found_brands = [brand for brand in POPULAR_BRANDS if brand.split('.')[0] in text.lower()]
    risk_score = len(found_keywords)*10 + len(found_links)*15 + len(found_brands)*20
    if risk_score > 100:
        risk_score = 100
    if risk_score > 50:
        risk_label = "🔴 Highly Likely Phishing"
    elif risk_score > 30:
        risk_label = "🟡 Likely Phishing"
    else:
        risk_label = "🟢 Potentially Safe"
    return {
        "risk_score": risk_score,
        "risk_label": risk_label,
        "keywords": found_keywords,
        "links": found_links,
        "brands": found_brands
    }
    
    links = extract_links(text)
    # Example risk logic (customize as needed)
    risk_score = 0
    keywords = [kw for kw in ["verify", "account", "password", "urgent"] if kw in text.lower()]
    brands = [b for b in ["PayPal", "Amazon", "Google"] if b.lower() in text.lower()]
    if keywords:
        risk_score += 30
    if links:
        risk_score += 20
    if brands:
        risk_score += 10
    risk_label = (
        "Highly Likely Phishing" if risk_score > 50 else
        "Likely Phishing" if risk_score > 30 else
        "Potentially Safe"
    )
    return {
        "risk_score": risk_score,
        "risk_label": risk_label,
        "keywords": keywords,
        "links": links,
        "brands": brands
    }

def main():
    st.markdown("<h1 style='color:#ff4b4b;'>🛡️ Phishing Website Detector, Port & Text Scanner</h1>", unsafe_allow_html=True)
    st.markdown("<p style='color:#111111;font-size:1.1rem;'>Analyze a website, suspicious text, or message for phishing risk!</p>", unsafe_allow_html=True)

    tab1, tab2, tab3 = st.tabs([
        "🔗 Website/Domain Analysis",
        "✉️ Text/Message Analysis",
        "🎓 Phishing Self-Test"
    ])

    # --- Website/Domain Tab ---
    with tab1:
        if st.button("Update Blacklist from Threat Feeds"):
            with st.spinner("Updating blacklist from multiple feeds..."):
                success, msg = update_blacklist_from_feeds()
                if success:
                    st.success(msg)
                else:
                    st.error(msg)

        url = st.text_input("Enter URL to analyze:", placeholder="https://example.com")
        port_scan_enabled = st.checkbox("Perform Port Scan (for open ports)", value=False)
        port_range = (1, 1024)
        if port_scan_enabled:
            colp1, colp2 = st.columns(2)
            with colp1:
                port_start = st.number_input("Port range start", min_value=1, max_value=65535, value=1)
            with colp2:
                port_end = st.number_input("Port range end", min_value=1, max_value=65535, value=1024)
            port_range = (int(port_start), int(port_end))

        if st.button("Analyze", key="analyze_url"):
            if url:
                with st.spinner("Analyzing website..."):
                    details = extract_details(url)
                    risk_score = calculate_risk_score(details)
                    if risk_score > 50:
                        prediction = "🔴 Highly Likely Phishing"
                        pred_color = "#dc3545"
                    elif risk_score > 30:
                        prediction = "🟡 Likely Phishing"
                        pred_color = "#ffc107"
                    else:
                        prediction = "🟢 Potentially Safe"
                        pred_color = "#28a745"
                    st.subheader("Analysis Results")
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown(
                            f"<div class='metric-container'><h3>Risk Score</h3><p style='font-size: 2rem; font-weight: bold;'>{risk_score}/100</p></div>",
                            unsafe_allow_html=True
                        )
                    with col2:
                         st.markdown(
                            f"<div class='metric-container'><h3>Prediction</h3><p style='font-size: 2rem; font-weight: bold; color: {pred_color};'>{prediction}</p></div>",
                         unsafe_allow_html=True
                        )

                    # --- VirusTotal Threat Intelligence ---
                    st.subheader("VirusTotal Threat Intelligence")
                    if VT_API_KEY:
                        vt_result = check_virustotal_url(url, VT_API_KEY)
                        if vt_result.get("error"):
                            st.warning(f"VirusTotal: {vt_result['error']}")
                        else:
                            verdict = vt_result.get("verdict", "unknown")
                            stats = vt_result.get("stats", {})
                            vt_color = (
                                "#dc3545" if verdict == "malicious"
                                else "#ffc107" if verdict == "suspicious"
                                else "#28a745" if verdict == "clean"
                                else "#6c757d"
                            )
                            st.markdown(
                                f"<div class='metric-container'><h3>VirusTotal Verdict</h3>"
                                f"<p style='font-size: 1.5rem; font-weight: bold; color: {vt_color};'>{verdict.title()}</p></div>",
                                unsafe_allow_html=True
                            )
                            st.write(
                                f"**Malicious:** {stats.get('malicious', 0)} | "
                                f"**Suspicious:** {stats.get('suspicious', 0)} | "
                                f"**Harmless:** {stats.get('harmless', 0)} | "
                                f"**Undetected:** {stats.get('undetected', 0)}"
                            )
                            if vt_result.get("permalink"):
                                st.markdown(f"[View full report on VirusTotal]({vt_result['permalink']})")
                    else:
                        st.info("VirusTotal threat intelligence is available if you set your API key in the .env file.")

                    # --- Website Screenshot ---
                    st.subheader("Website Screenshot")
                    screenshot = None
                    screenshot_error = None
                    if url and url.lower().startswith("http"):
                        with st.spinner("Taking screenshot..."):
                            screenshot, screenshot_error = take_screenshot(url)
                        if screenshot:
                            st.image(screenshot, caption="Website Screenshot", use_container_width=True)
                        else:
                            st.warning("Screenshot unavailable." + (f" Error: {screenshot_error}" if screenshot_error else ""))
                    else:
                        st.info("Enter a valid URL (starting with http or https) to take a screenshot.")

                    # --- Technical Details ---
                    st.subheader("Technical Details")
                    st.markdown("<div class='details-list'><ul>", unsafe_allow_html=True)
                    for key, value in details.items():
                        if key not in ['found_paths', 'lookalike_brands']:
                            st.markdown(f"<li><strong>{key}:</strong> {value}</li>", unsafe_allow_html=True)
                    st.markdown("</ul></div>", unsafe_allow_html=True)

                    # --- Advanced DOM Clues ---
                    st.subheader("Advanced DOM Clues")
                    dom_clues, dom_error = extract_dom_clues(url)
                    if dom_clues:
                        st.write(f"**Forms on page:** {dom_clues.get('forms', 0)}")
                        st.write(f"**Password fields:** {dom_clues.get('password_inputs', 0)}")
                        st.write(f"**External scripts:** {dom_clues.get('external_scripts', 0)}")
                        st.write(f"**Images (possible logos):** {dom_clues.get('images', 0)}")
                        found_keywords = dom_clues.get('found_keywords', [])
                        if found_keywords:
                            st.warning(f"Suspicious keywords found: {', '.join(found_keywords)}")
                        else:
                            st.success("No suspicious keywords found in visible text.")
                    else:
                        st.info(f"DOM clue extraction unavailable.{f' Error: {dom_error}' if dom_error else ''}")

                    # --- SSL/TLS Certificate Transparency ---
                    st.subheader("SSL/TLS Certificate Transparency")
                    if details.get('ssl_issuer') and details['ssl_issuer'] != 'N/A':
                        st.info(f"Issuer: **{details['ssl_issuer']}**")
                        st.write(f"Valid from: `{details.get('ssl_valid_from', 'N/A')}` to `{details.get('ssl_valid_to', 'N/A')}`")
                        st.write(f"Certificate age: **{details.get('ssl_age_days', 'N/A')} days**")
                        st.write(f"Days left until expiry: **{details.get('ssl_days_left', 'N/A')} days**")
                        if details.get('ssl_is_new') == "Yes":
                            st.warning("⚠️ Certificate is very new (issued in the last 30 days).")
                        if details.get('ssl_issuer_warning'):
                            st.warning(f"⚠️ {details['ssl_issuer_warning']}")
                    else:
                        st.info("No SSL/TLS certificate details available.")

                    # --- Typosquatting & Lookalike Domain Check ---
                    st.subheader("Typosquatting & Lookalike Domain Check")
                    if details.get('lookalike_brands'):
                        st.warning(f"This domain is a lookalike or typo of: {', '.join(details['lookalike_brands'])}")
                    else:
                        st.success("No lookalike or typosquatting detected for popular brands.")

                    # --- Discovered Paths ---
                    st.subheader("Discovered Paths")
                    found_paths = details.get('found_paths', [])
                    if found_paths:
                        st.markdown("<div class='paths-list'><ul>", unsafe_allow_html=True)
                        for path in found_paths:
                            st.markdown(f"<li><code>{url.rstrip('/')}{path}</code></li>", unsafe_allow_html=True)
                        st.markdown("</ul></div>", unsafe_allow_html=True)
                    else:
                        st.warning("No common paths discovered")

                    # --- Port Scan Section ---
                    if port_scan_enabled:
                        st.subheader(f"Port Scan Results ({port_range[0]}–{port_range[1]})")
                        parsed_url = urlparse(url)
                        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
                        with st.spinner("Scanning ports... (this may take a while)"):
                            open_ports, closed_ports, error = port_scan(domain, port_range)
                            if error:
                                st.error(error)
                            else:
                                st.markdown("<div class='ports-list'><ul>", unsafe_allow_html=True)
                                if open_ports:
                                    st.markdown("<li><strong>Open Ports:</strong></li>", unsafe_allow_html=True)
                                    for port, service in open_ports:
                                        st.markdown(
                                            f"<li style='margin-left:20px;'><strong>Port {port}:</strong> "
                                            f"<span style='color:green;'>OPEN</span> &nbsp; <em>({service})</em></li>",
                                            unsafe_allow_html=True
                                        )
                                else:
                                    st.markdown("<li><strong>No open ports found in the scanned range.</strong></li>", unsafe_allow_html=True)

                                if closed_ports:
                                    st.markdown("<li><strong>Closed Ports (showing up to 20):</strong></li>", unsafe_allow_html=True)
                                    for port in closed_ports[:20]:
                                        st.markdown(
                                            f"<li style='margin-left:20px;'><strong>Port {port}:</strong> "
                                            f"<span style='color:red;'>CLOSED</span></li>",
                                            unsafe_allow_html=True
                                        )
                                    if len(closed_ports) > 20:
                                        st.markdown(
                                            f"<li style='margin-left:20px;'><em>...and {len(closed_ports)-20} more closed ports</em></li>",
                                            unsafe_allow_html=True
                                        )
                                st.markdown("</ul></div>", unsafe_allow_html=True)

                    # --- Feedback Section ---
                    st.subheader("Feedback")
                    feedback = st.radio("Was this prediction accurate?", ("Yes", "No"), horizontal=True)
                    comments = st.text_area("Additional Comments")
                    if st.button("Submit Feedback", key="feedback_url"):
                        st.success("Thank you for your feedback! (Submitted: {})".format(feedback))
                        if feedback == "No":
                            parsed_url = urlparse(url)
                            domain = parsed_url.netloc
                            add_to_blacklist(domain)

                    # --- Community Reporting Section ---
                    st.subheader("Community Reporting")
                    parsed_url = urlparse(url)
                    domain = parsed_url.netloc
                    comm_verdict, phishing_count, safe_count = get_community_verdict(domain)
                    st.info(comm_verdict)
                    col_a, col_b = st.columns(2)
                    with col_a:
                        if st.button("Report as Phishing", key="report_phishing"):
                            add_community_vote(domain, "phishing")
                            st.success("Thank you for reporting! (Phishing)")
                    with col_b:
                        if st.button("Report as Safe", key="report_safe"):
                            add_community_vote(domain, "safe")
                            st.success("Thank you for reporting! (Safe)")
            else:
                st.warning("Please enter a valid URL")

    # --- Text/Message Tab ---
    with tab2:
      st.markdown("## ✉️ Text/Message Analysis")
      st.write("Paste any suspicious email, SMS, or message below to check for phishing risk.")

    text = st.text_area(
        "Paste your message or email here:",
        height=180,
        placeholder="e.g. 'Dear user, your account is locked. Click here to verify...'"
    )

    if st.button("Analyze Text", key="analyze_text"):
        if text.strip():
            result = analyze_text(text)
            st.subheader("Text Analysis Results")

            # --- Risk Score & Prediction ---
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(
                    f"<div class='metric-container'><h3>Risk Score</h3>"
                    f"<p style='font-size: 2rem; font-weight: bold; color:#ff4b4b;'>{result.get('risk_score', 0)}/100</p></div>",
                    unsafe_allow_html=True
                )
            with col2:
                risk_label = result.get('risk_label', 'Unknown')
                color = "#dc3545" if "Highly" in risk_label else "#ffc107" if "Likely" in risk_label else "#28a745"
                emoji = "🔴" if "Highly" in risk_label else "🟡" if "Likely" in risk_label else "🟢"
                st.markdown(
                    f"<div class='metric-container'><h3>Prediction</h3>"
                    f"<p style='font-size: 2rem; font-weight: bold; color: {color};'>{emoji} {risk_label}</p></div>",
                    unsafe_allow_html=True
                )

            # --- Detected Issues ---
            st.markdown("---")
            st.subheader("Detected Issues")

            # Phishing Keywords
            keywords = result.get('keywords', [])
            if keywords:
                st.warning(f"**Phishing keywords detected:**<br> {', '.join(keywords)}", icon="⚠️")
            else:
                st.success("No phishing keywords detected.", icon="✅")

            # Suspicious Links
            links = result.get('links', [])
            if links:
                st.warning("**Suspicious links found:**", icon="🔗")
                for l in links:
                    # Make each link clickable
                    st.markdown(f"- [🔗 {l}]({l})", unsafe_allow_html=True)
            else:
                st.success("No suspicious links found.", icon="🔒")

            # Brand Names
            brands = result.get('brands', [])
            if brands:
                st.info(f"**Brand names detected:**<br> {', '.join(brands)}", icon="🏢")
            else:
                st.info("No popular brand names detected.", icon="ℹ️")

            # Suggestions
            st.markdown("---")
            st.subheader("What should you do?")
            if result.get('risk_score', 0) > 50:
                st.error("**Do NOT click any links or provide information.** This message is highly suspicious and may be a phishing attempt.")
            elif result.get('risk_score', 0) > 30:
                st.warning("**Be cautious.** This message has several suspicious signs. Double-check the sender and avoid clicking links.")
            else:
                st.success("This message appears safe, but always stay alert for phishing attempts.")
        else:
            st.info("Paste some text to analyze.")


    # --- Phishing Awareness Quiz Tab ---
    with tab3:
        phishing_quiz()

if __name__ == "__main__":
    main()
