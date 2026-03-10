"""
Email Analyzer - Feature extraction, link scanning, header analysis
"""

import re
import json
import hashlib
from datetime import datetime
from urllib.parse import urlparse


# ─── PHISHING INDICATORS ─────────────────────────────────────────────────────

URGENCY_PATTERNS = [
    r'\burgent\b', r'\bimmediately\b', r'\basap\b', r'\bright now\b',
    r'\bact now\b', r'\bexpire[sd]?\b', r'\bsuspend(ed)?\b', r'\bwarning\b',
    r'\balert\b', r'\bfinal notice\b', r'\blast chance\b', r'\blimited time\b',
    r'\bdeadline\b', r'\bhours?\b.*\bexpire\b', r'\b24 hours?\b',
    r'\b48 hours?\b', r'\bimminent\b', r'\bcritical\b'
]

THREAT_PATTERNS = [
    r'\barrest(ed)?\b', r'\bjail\b', r'\blegal action\b', r'\bcourt\b',
    r'\blawsuit\b', r'\bpenalt(y|ies)\b', r'\bfine[sd]?\b', r'\bblock(ed)?\b',
    r'\blocked?\b', r'\bfrozen?\b', r'\bsuspended?\b', r'\bterminated?\b',
    r'\bseized?\b', r'\bcriminal\b', r'\bpolice\b', r'\bwill be arrested\b',
    r'\bwarrant\b', r'\bprosecute\b', r'\bcharged\b'
]

FINANCIAL_PATTERNS = [
    r'\b(won|win|winner)\b', r'\bprize\b', r'\breward\b', r'\bfree\b',
    r'\bgift card\b', r'\blottery\b', r'\bsweepstakes\b', r'\bmillion(s)?\b',
    r'\bbillion\b', r'\bcash\b', r'\binvestment\b', r'\bprofit\b',
    r'\bguaranteed\b', r'\blucky winner\b', r'\bunclaimed\b',
    r'\b\$\d+\b', r'\b\d+%\s*(profit|return|bonus)\b'
]

CREDENTIAL_PATTERNS = [
    r'\bverif(y|ication)\b', r'\bvalidat(e|ion)\b',
    r'\bauthenticat(e|ion)\b',
    r'\benter.*?(password|credentials|card|ssn)\b',
    r'\bprovide.*?(password|credentials|account|card)\b',
    r'\bsubmit.*?(password|credentials|details|info)\b',
    r'\bcredential\b',
    r'\baccount.*?detail\b', r'\bpersonal.*?information\b',
    r'\bsocial.*?security\b', r'\bcredit.*?card.*?(number|detail)\b'
]

SUSPICIOUS_TLDS = ['.xyz', '.tk', '.ru', '.ml', '.ga', '.cf', '.gq', '.pw',
                   '.top', '.club', '.info', '.biz', '.cc', '.ws', '.su',
                   '.party', '.loan', '.download', '.win', '.racing']

BRAND_IMPERSONATION = [
    'paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix', 'facebook',
    'instagram', 'twitter', 'linkedin', 'dropbox', 'chase', 'bank of america',
    'wells fargo', 'citi', 'irs', 'fedex', 'ups', 'dhl', 'usps', 'whatsapp',
    'zoom', 'docusign', 'adobe', 'coinbase', 'binance', 'crypto'
]


def extract_urls(text):
    """Extract all URLs from email text."""
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(url_pattern, text)


# Free hosting platforms commonly abused for phishing
URL_SHORTENERS = [
    'tinyurl.com', 'bit.ly', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'tiny.cc', 'cutt.ly', 'rb.gy', 'shorturl.at', 'tiny.one',
    'rebrand.ly', 'bl.ink', 'buff.ly', 'v.gd', 'tr.im', 'shorte.st',
]
FREE_HOSTING_DOMAINS = [
    'jabry.com', 'freehosting.net', '000webhostapp.com', 'weebly.com',
    'wixsite.com', 'blogspot.com', 'wordpress.com', 'tumblr.com',
    'angelfire.com', 'tripod.com', 'geocities.ws', 'freeservers.com',
    'atspace.com', 'byethost.com', 'freehostia.com', 'awardspace.com',
    'x10hosting.com', 'biz.nf', 'co.nf', 'uhostall.com',
    'zxq.net', 'cjb.net', 'url.ph', 'almaktaba.org',
    'ueuo.com', 'co.cc', 'tk', 'ml', 'ga', 'cf', 'gq',
]

# Trusted hosting/platform domains — never flag these
TRUSTED_DOMAINS = [
    'onrender.com', 'netlify.app', 'vercel.app', 'herokuapp.com',
    'github.io', 'github.com', 'gitlab.com', 'pages.dev',
    'azurewebsites.net', 'amazonaws.com', 'cloudfront.net',
    'firebaseapp.com', 'web.app', 'surge.sh', 'fly.dev',
    'railway.app', 'cyclic.app', 'glitch.me', 'replit.dev',
]

def analyze_url(url):
    """Analyze a single URL for suspicious indicators."""
    issues = []
    risk = 0

    # Normalize URL — prepend http:// if missing so urlparse works
    raw_url = url.strip()
    if not raw_url.startswith('http://') and not raw_url.startswith('https://'):
        raw_url = 'http://' + raw_url

    try:
        parsed = urlparse(raw_url)
        domain = parsed.netloc.lower().lstrip('www.')
        path = parsed.path.lower()
        full = raw_url.lower()
    except Exception:
        return {'url': url, 'risk': 50, 'issues': ['Malformed URL'], 'safe': False}

    # Trusted hosting platforms — always safe regardless of other signals
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith('.' + trusted):
            return {'url': url, 'domain': domain, 'risk': 0, 'issues': [], 'safe': True, 'https': url.startswith('https://')}
for shortener in URL_SHORTENERS:
        if domain == shortener or domain.endswith('.' + shortener):
            issues.append(f'URL shortener ({domain}) hides real destination — common in phishing')
            risk += 40
            break

    # Free hosting platforms — commonly abused for phishing pages
    for fh in FREE_HOSTING_DOMAINS:
        if domain == fh or domain.endswith('.' + fh):
            issues.append(f'Hosted on free platform ({fh}) — commonly abused for phishing')
            risk += 45
            break

    # Check suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            issues.append(f'Suspicious TLD: {tld}')
            risk += 30
            break

    # Check for IP address URL
    if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
        issues.append('IP address used instead of domain name')
        risk += 40

    # Numeric subdomain (e.g. users11, ftp2, host99) — common in free hosting phishing
    subdomain = domain.split('.')[0] if domain.count('.') >= 2 else ''
    if re.match(r'^[a-z]+\d+$', subdomain) or re.match(r'^\d+[a-z]+\d*$', subdomain):
        issues.append(f'Numeric subdomain pattern ({subdomain}) — common in phishing/free hosting abuse')
        risk += 20

    # Phishing path patterns — brand names in URL path
    PHISHING_PATH_PATTERNS = [
        r'/(paypal|amazon|apple|microsoft|google|netflix|ebay|chase|wellsfargo|bankofamerica|citibank|hsbc|barclays|aol|yahoo|outlook|gmail)[^/]*(login|signin|update|verify|secure|account|confirm|\.com)',
        r'/(login|signin|verify|update|secure|account|confirm)[^/]*(paypal|amazon|apple|microsoft|google|netflix|ebay)',
        r'/blopp/', r'/phishing/', r'/scam/', r'/fake/',
        # Brand domain appearing IN the path (e.g. /paypal.com/ on a non-paypal domain)
        r'/(paypal|amazon|apple|microsoft|google|netflix|ebay|chase|citibank|hsbc|barclays|aol|yahoo)\.com',
    ]
    for pat in PHISHING_PATH_PATTERNS:
        if re.search(pat, path, re.IGNORECASE):
            issues.append('Suspicious path — known brand name embedded in URL path (classic phishing)')
            risk += 40
            break

    # Long random hex path segments (e.g. /70ffb52d079e55eb0a99bbd77b8fee09/) — phishing obfuscation
    if re.search(r'/[0-9a-f]{16,}/', path):
        issues.append('Obfuscated hex path segment — common phishing obfuscation technique')
        risk += 30

    # Brand impersonation in domain
    # Only flag if brand appears in domain but is NOT the official domain
    # e.g. paypal-verify.xyz -> flag | www.paypal.com -> safe | paypal.com.evil.ru -> flag
    for brand in BRAND_IMPERSONATION:
        if brand in domain:
            clean_domain = domain[4:] if domain.startswith('www.') else domain
            official = f'{brand}.com'
            is_official = (clean_domain == official or clean_domain.endswith(f'.{official}'))
            if not is_official:
                issues.append(f'Brand impersonation: {brand}')
                risk += 35
                break

    # Hyphens in domain (common phishing tactic)
    hyphen_count = domain.count('-')
    if hyphen_count >= 2:
        issues.append(f'Multiple hyphens in domain ({hyphen_count}x)')
        risk += 15

    # Very long domain
    if len(domain) > 40:
        issues.append('Unusually long domain name')
        risk += 10

    # Messaging app redirects used in scams/phishing
    # Legitimate emails rarely direct users to Telegram/WhatsApp channels
    SCAM_REDIRECT_DOMAINS = ['t.me', 'telegram.me', 'wa.me', 'whatsapp.com/group']
    for rd in SCAM_REDIRECT_DOMAINS:
        if rd in domain or rd in full:
            issues.append(f'Redirects to messaging app ({rd}) — common scam tactic')
            risk += 40
            break

    # Suspicious keywords in path/domain
    suspicious_keywords = ['verify', 'secure', 'login', 'confirm', 'update',
                           'validate', 'account', 'payment', 'billing', 'unlock']
    found_keywords = [k for k in suspicious_keywords if k in full]
    if len(found_keywords) >= 2:
        issues.append(f'Suspicious keywords in URL: {", ".join(found_keywords[:3])}')
        risk += 20

    # Gambling / betting / adult keywords in URL path
    scam_path_keywords = ['bet', 'casino', 'poker', 'slot', 'gambl', 'porn',
                          'crypto-profit', 'investment-return', 'forex', 'trading-signal']
    found_scam = [k for k in scam_path_keywords if k in full]
    if found_scam:
        issues.append(f'Scam/gambling keywords in URL: {", ".join(found_scam[:3])}')
        risk += 25

    # Redirect indicators
    if 'redirect' in full or 'url=' in full or 'link=' in full:
        issues.append('URL redirect detected')
        risk += 25

    # HTTP (not HTTPS)
    if url.startswith('http://'):
        issues.append('Insecure HTTP (not HTTPS)')
        risk += 10

    # Subdomain abuse
    subdomain_count = len(domain.split('.')) - 2
    if subdomain_count >= 3:
        issues.append(f'Excessive subdomains ({subdomain_count})')
        risk += 20

    risk = min(100, risk)
    # Safe only if: no issues at all AND low risk AND uses HTTPS
    is_safe = risk == 0 and len(issues) == 0

    return {
        'url': url,
        'domain': domain,
        'risk': risk,
        'issues': issues,
        'safe': is_safe,
        'https': url.startswith('https://')
    }


def analyze_email_features(email_text):
    """Extract comprehensive features from email text."""
    text_lower = email_text.lower()
    features = {}
    indicators = []
    highlighted_keywords = []

    # ── Urgency Analysis ─────────────────────────────────
    urgency_matches = []
    for pattern in URGENCY_PATTERNS:
        matches = re.findall(pattern, text_lower, re.IGNORECASE)
        urgency_matches.extend(matches)
    features['urgency_count'] = len(urgency_matches)
    if urgency_matches:
        indicators.append({
            'type': 'urgency',
            'severity': 'high' if len(urgency_matches) > 2 else 'medium',
            'label': 'Urgency Language',
            'detail': f'Detected {len(urgency_matches)} urgency indicators: {", ".join(set(urgency_matches[:3]))}'
        })
        highlighted_keywords.extend(list(set(urgency_matches[:5])))

    # ── Threat Analysis ───────────────────────────────────
    threat_matches = []
    for pattern in THREAT_PATTERNS:
        matches = re.findall(pattern, text_lower, re.IGNORECASE)
        threat_matches.extend(matches)
    features['threat_count'] = len(threat_matches)
    if threat_matches:
        indicators.append({
            'type': 'threat',
            'severity': 'critical',
            'label': 'Threat/Coercion',
            'detail': f'Threatening language: {", ".join(set(threat_matches[:3]))}'
        })
        highlighted_keywords.extend(list(set(threat_matches[:3])))

    # ── Financial Lures ───────────────────────────────────
    financial_matches = []
    for pattern in FINANCIAL_PATTERNS:
        matches = re.findall(pattern, text_lower, re.IGNORECASE)
        financial_matches.extend(matches)
    features['financial_count'] = len(financial_matches)
    if len(financial_matches) >= 2:
        indicators.append({
            'type': 'financial',
            'severity': 'high',
            'label': 'Financial Lure',
            'detail': f'Financial manipulation detected: {", ".join(set(str(m) for m in financial_matches[:3]))}'
        })

    # ── Credential Harvesting ─────────────────────────────
    cred_matches = []
    for pattern in CREDENTIAL_PATTERNS:
        matches = re.findall(pattern, text_lower, re.IGNORECASE)
        cred_matches.extend(matches)
    features['credential_count'] = len(cred_matches)
    if cred_matches:
        indicators.append({
            'type': 'credential',
            'severity': 'critical',
            'label': 'Credential Harvesting',
            'detail': f'Requests for credentials/personal info: {", ".join(set(str(m) for m in cred_matches[:3]))}'
        })

    # ── URL Analysis ──────────────────────────────────────
    urls = extract_urls(email_text)
    url_analyses = [analyze_url(u) for u in urls[:10]]
    features['url_count'] = len(urls)
    features['suspicious_url_count'] = sum(1 for u in url_analyses if not u['safe'])
    
    if url_analyses:
        suspicious_urls = [u for u in url_analyses if not u['safe']]
        if suspicious_urls:
            indicators.append({
                'type': 'malicious_link',
                'severity': 'critical',
                'label': 'Suspicious URLs',
                'detail': f'{len(suspicious_urls)} suspicious URL(s) detected'
            })

    # ── Suspicious TLDs ───────────────────────────────────
    has_suspicious_tld = any(tld in email_text.lower() for tld in SUSPICIOUS_TLDS)
    features['suspicious_tld'] = 1 if has_suspicious_tld else 0
    if has_suspicious_tld:
        indicators.append({
            'type': 'suspicious_domain',
            'severity': 'high',
            'label': 'Suspicious Domain TLD',
            'detail': 'Email contains domains with high-risk TLDs (.xyz, .tk, .ru, etc.)'
        })

    # ── IP Address URL ────────────────────────────────────
    has_ip_url = bool(re.search(r'http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', email_text))
    features['has_ip_url'] = 1 if has_ip_url else 0
    if has_ip_url:
        indicators.append({
            'type': 'ip_url',
            'severity': 'critical',
            'label': 'IP Address URL',
            'detail': 'Link uses raw IP address instead of domain name (classic phishing tactic)'
        })

    # ── Brand Impersonation ───────────────────────────────
    found_brands = [b for b in BRAND_IMPERSONATION if b in text_lower]
    features['brand_mention'] = len(found_brands)
    if found_brands:
        indicators.append({
            'type': 'spoofed_sender',
            'severity': 'high',
            'label': 'Brand Impersonation',
            'detail': f'Impersonates known brand(s): {", ".join(found_brands[:3])}'
        })
        highlighted_keywords.extend(found_brands[:3])

    # ── Typosquatted Sender Domain ───────────────────────
    # Detect domains like appl3.co, paypa1.com, microsoft.net, g00gle.com
    sender_pattern = r'(?:from|sender|reply-to)[:\s]+[\w\s]+<([^>]+@([^>]+))>'
    sender_match = re.search(sender_pattern, email_text, re.IGNORECASE)
    if not sender_match:
        # Also check bare email addresses
        sender_match = re.search(r'[\w.]+@([\w.-]+\.(?:co|net|org|io|tk|ru|xyz|ml|ga|cf|gq|pw))', email_text, re.IGNORECASE)

    KNOWN_BRANDS_DOMAINS = {
        'apple': ['apple.com', 'icloud.com'],
        'paypal': ['paypal.com'],
        'microsoft': ['microsoft.com', 'outlook.com', 'live.com'],
        'google': ['google.com', 'gmail.com'],
        'amazon': ['amazon.com'],
        'netflix': ['netflix.com'],
        'facebook': ['facebook.com', 'meta.com'],
        'instagram': ['instagram.com'],
        'twitter': ['twitter.com', 'x.com'],
        'linkedin': ['linkedin.com'],
        'dropbox': ['dropbox.com'],
        'spotify': ['spotify.com'],
    }

    typosquat_found = False
    for brand, official_domains in KNOWN_BRANDS_DOMAINS.items():
        if brand in text_lower:
            # Check for digit substitutions and typos in any email address in the text
            email_addresses = re.findall(r'[\w.+-]+@([\w.-]+)', email_text)
            for addr_domain in email_addresses:
                addr_domain_lower = addr_domain.lower()
                # Skip if it's an official domain
                if any(addr_domain_lower == d or addr_domain_lower.endswith('.' + d) for d in official_domains):
                    continue
                # Flag if brand name (with possible digit substitutions) appears in sender domain
                brand_regex = brand.replace('a', '[a4@]').replace('e', '[e3]').replace('i', '[i1!]').replace('o', '[o0]').replace('s', '[s5$]')
                if re.search(brand_regex, addr_domain_lower):
                    features['suspicious_url_count'] = features.get('suspicious_url_count', 0) + 3
                    indicators.append({
                        'type': 'spoofed_sender',
                        'severity': 'critical',
                        'label': 'Typosquatted Sender Domain',
                        'detail': f'Sender domain "{addr_domain}" impersonates {brand} using character substitution'
                    })
                    highlighted_keywords.append(addr_domain)
                    typosquat_found = True
                    break
        if typosquat_found:
            break

    # ── Grammar & Style Analysis ──────────────────────────
    exclamation_count = email_text.count('!')
    all_caps_count = len(re.findall(r'\b[A-Z]{5,}\b', email_text))  # 5+ chars to avoid brand names like VPN, FBI
    features['exclamation_count'] = exclamation_count
    features['all_caps_count'] = all_caps_count
    
    if exclamation_count >= 3 or all_caps_count >= 3:
        indicators.append({
            'type': 'social_engineering',
            'severity': 'medium',
            'label': 'Aggressive Formatting',
            'detail': f'{exclamation_count} exclamation marks, {all_caps_count} ALL CAPS words detected'
        })

    # ── Attachment Mention ────────────────────────────────
    attachment_patterns = r'\b(attachment|attached|click.*?open|download|\.exe|\.zip|\.doc|\.pdf)\b'
    has_attachment_ref = bool(re.search(attachment_patterns, text_lower))
    if has_attachment_ref:
        indicators.append({
            'type': 'suspicious_attachment',
            'severity': 'medium',
            'label': 'Attachment Reference',
            'detail': 'Email references attachments (potential malware delivery vector)'
        })

    # ── Email Length & Structure ──────────────────────────
    features['email_length'] = len(email_text)
    features['word_count'] = len(email_text.split())

    return {
        'features': features,
        'indicators': indicators,
        'urls': url_analyses,
        'highlighted_keywords': list(set(highlighted_keywords))
    }


def analyze_email_header(raw_header_text):
    """Parse and analyze email headers for spoofing indicators."""
    if not raw_header_text:
        return {}
    
    header_issues = []
    parsed = {}
    
    # Extract common headers
    header_patterns = {
        'from': r'From:\s*(.+?)(?:\n|\r)',
        'reply_to': r'Reply-To:\s*(.+?)(?:\n|\r)',
        'return_path': r'Return-Path:\s*(.+?)(?:\n|\r)',
        'received': r'Received:\s*(.+?)(?:\n|\r)',
        'message_id': r'Message-ID:\s*(.+?)(?:\n|\r)',
        'x_originating_ip': r'X-Originating-IP:\s*(.+?)(?:\n|\r)',
        'spf': r'Received-SPF:\s*(.+?)(?:\n|\r)',
        'dkim': r'DKIM-Signature:\s*(.+?)(?:\n|\r)',
    }
    
    for key, pattern in header_patterns.items():
        match = re.search(pattern, raw_header_text, re.IGNORECASE)
        if match:
            parsed[key] = match.group(1).strip()
    
    # Check for spoofing
    if 'from' in parsed and 'reply_to' in parsed:
        from_domain = re.search(r'@([^\s>]+)', parsed['from'])
        reply_domain = re.search(r'@([^\s>]+)', parsed['reply_to'])
        if from_domain and reply_domain and from_domain.group(1) != reply_domain.group(1):
            header_issues.append({
                'type': 'header_spoofing',
                'severity': 'critical',
                'detail': f'From domain ({from_domain.group(1)}) differs from Reply-To ({reply_domain.group(1)})'
            })
    
    # SPF check
    if 'spf' in parsed:
        if 'fail' in parsed['spf'].lower():
            header_issues.append({
                'type': 'spf_fail',
                'severity': 'critical',
                'detail': 'SPF authentication FAILED - sender is not authorized'
            })
        elif 'softfail' in parsed['spf'].lower():
            header_issues.append({
                'type': 'spf_softfail',
                'severity': 'high',
                'detail': 'SPF soft fail - sender may not be authorized'
            })
    
    # DKIM check
    dkim_present = 'dkim' in parsed and bool(parsed.get('dkim', '').strip())
    if not dkim_present:
        header_issues.append({
            'type': 'no_dkim',
            'severity': 'medium',
            'detail': 'No DKIM signature found - email authenticity cannot be verified'
        })
    
    return {
        'parsed_headers': parsed,
        'header_issues': header_issues,
        'spf_pass': 'spf' in parsed and 'pass' in parsed.get('spf', '').lower(),
        'dkim_present': dkim_present
    }


def calculate_risk_score(prediction, confidence, features, indicator_count, url_analyses):
    """Calculate comprehensive risk score 0-100."""
    base_score = int(confidence * 100) if prediction == 1 else int((1 - confidence) * 40)
    
    # Modifier factors
    modifiers = 0
    
    # URL risk contribution
    if url_analyses:
        max_url_risk = max((u['risk'] for u in url_analyses), default=0)
        modifiers += max_url_risk * 0.3
    
    # Indicator severity weights
    severity_weights = {'critical': 15, 'high': 8, 'medium': 4, 'low': 2}
    features_data = features.get('features', {})
    
    indicator_score = sum(severity_weights.get(i.get('severity', 'low'), 2) 
                         for i in features.get('indicators', []))
    modifiers += min(indicator_score, 30)
    
    # Feature boosts
    if features_data.get('has_ip_url'):
        modifiers += 20
    if features_data.get('suspicious_tld'):
        modifiers += 10
    if features_data.get('threat_count', 0) > 0:
        modifiers += 10
    
    total = min(100, int(base_score + modifiers * 0.3))
    
    if prediction == 0:
        total = min(total, 45)
    
    return total


def generate_explanation(prediction, confidence, features_data, risk_score):
    """Generate human-readable explanation of the analysis."""
    indicators = features_data.get('indicators', [])
    urls = features_data.get('urls', [])
    feats = features_data.get('features', {})
    
    explanations = []
    
    if prediction == 1:
        explanations.append(f"This email shows strong indicators of a phishing attempt (confidence: {confidence*100:.1f}%).")
    else:
        explanations.append(f"This email appears to be legitimate (confidence: {confidence*100:.1f}%).")
    
    # Add specific explanations based on findings
    for ind in indicators[:5]:
        explanations.append(f"• {ind['detail']}")
    
    # URL summary
    suspicious_urls = [u for u in urls if not u['safe']]
    if suspicious_urls:
        explanations.append(f"• {len(suspicious_urls)} suspicious URL(s) detected with risk scores: {[u['risk'] for u in suspicious_urls]}")
    
    # Risk level categorization
    if risk_score >= 80:
        risk_label = "CRITICAL - Almost certainly malicious"
    elif risk_score >= 60:
        risk_label = "HIGH - Likely phishing attempt"
    elif risk_score >= 40:
        risk_label = "MEDIUM - Suspicious content detected"
    elif risk_score >= 20:
        risk_label = "LOW - Minor suspicious elements"
    else:
        risk_label = "SAFE - No significant threats detected"
    
    return {
        'summary': explanations[0],
        'details': explanations[1:],
        'risk_label': risk_label,
        'recommendation': get_recommendation(risk_score)
    }


def get_recommendation(risk_score):
    """Get actionable recommendation based on risk score."""
    if risk_score >= 70:
        return "DO NOT click any links or download attachments. Report to your IT security team immediately. Mark as phishing."
    elif risk_score >= 40:
        return "Exercise caution. Do not provide personal information. Verify sender through official channels before responding."
    elif risk_score >= 20:
        return "Review carefully. Minor suspicious elements detected. Confirm sender identity if unsure."
    else:
        return "Email appears safe. Continue exercising standard email security practices."
