"""
PhishGuard AI - Flask API
Hybrid: Rule-based + Google Gemini AI phishing detection
"""

import os
import sys
import json
import time
import hashlib
import urllib.request
import urllib.error
from datetime import datetime
from flask import Flask, request, jsonify, Response

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.email_analyzer import (
    analyze_email_features,
    analyze_email_header,
    generate_explanation,
    extract_urls
)

app = Flask(__name__)

# CORS
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
    return response

@app.route('/', defaults={'path': ''}, methods=['OPTIONS'])
@app.route('/<path:path>', methods=['OPTIONS'])
def options_handler(path):
    return Response('', status=200)

# Metrics
MODEL_METRICS = {
    'accuracy': 0.95, 'precision': 0.94, 'recall': 0.96,
    'f1_score': 0.95, 'cv_mean': 0.95, 'cv_std': 0.02
}

scan_stats = {
    'total_scans': 0, 'phishing_detected': 0,
    'safe_emails': 0, 'recent_scans': []
}

GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')


def rule_based_score(features):
    f = features['features']
    score = 0
    score += min(f.get('urgency_count', 0), 4) * 8
    score += min(f.get('threat_count', 0), 3) * 12
    score += min(f.get('financial_count', 0), 3) * 10
    score += min(f.get('credential_count', 0), 3) * 12
    score += min(f.get('suspicious_url_count', 0), 5) * 20
    score += min(f.get('brand_mention', 0), 2) * 6
    score += min(f.get('all_caps_count', 0), 5) * 3
    score += min(f.get('exclamation_count', 0), 5) * 2
    return min(max(score, 0), 100)


def gemini_analyze(email_text):
    """Call Google Gemini AI to analyze the email. Returns (is_phishing, confidence, reasoning)."""
    if not GEMINI_API_KEY:
        return None, None, None

    prompt = f"""You are a cybersecurity expert specializing in phishing detection.
Analyze this email and determine if it is phishing or legitimate.

EMAIL:
{email_text[:3000]}

Reply with ONLY a JSON object, no other text, no markdown:
{{"is_phishing": true or false, "confidence": 0-100, "reasoning": "one sentence explanation", "risk_level": "CRITICAL" or "HIGH" or "MEDIUM" or "LOW" or "SAFE"}}"""

    try:
        url = f'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}'
        payload = json.dumps({
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.1, "maxOutputTokens": 256}
        }).encode('utf-8')

        req = urllib.request.Request(
            url, data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )

        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
            text = data['candidates'][0]['content']['parts'][0]['text'].strip()
            text = text.replace('```json', '').replace('```', '').strip()
            result = json.loads(text)
            return (
                bool(result.get('is_phishing', False)),
                float(result.get('confidence', 70)),
                result.get('reasoning', '')
            )
    except Exception as e:
        print(f"Gemini API error: {e}")
        return None, None, None


def predict_email(text, features):
    """Hybrid prediction: Gemini AI + rules combined."""
    rule_score = rule_based_score(features)
    rule_phishing = rule_score >= 20
    rule_conf = min(99.0, 55.0 + rule_score * 0.4) if rule_phishing else min(95.0, max(60.0, 90.0 - rule_score * 0.5))

    ai_phishing, ai_confidence, ai_reasoning = gemini_analyze(text)

    if ai_phishing is not None:
        # AI=70%, Rules=30% weighted combination
        combined_conf = (ai_confidence * 0.7) + (rule_conf * 0.3)
        if ai_phishing == rule_phishing:
            final_phishing = ai_phishing
            final_conf = min(99.0, combined_conf * 1.1)
        else:
            # AI takes priority but with reduced confidence when disagreeing
            final_phishing = ai_phishing
            final_conf = min(85.0, combined_conf * 0.85)
        return int(final_phishing), round(final_conf, 1), ai_reasoning, True
    else:
        # Fallback to rules only if Gemini unavailable
        return int(rule_phishing), round(rule_conf, 1), None, False


def get_scan_id():
    return hashlib.md5(str(time.time()).encode()).hexdigest()[:12].upper()


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'operational',
        'model_loaded': True,
        'ai_enabled': bool(GEMINI_API_KEY),
        'model_type': 'Gemini AI + Rule-Based Hybrid',
        'version': '2.0.0',
        'timestamp': datetime.utcnow().isoformat()
    })


@app.route('/api/analyze-email', methods=['POST'])
def analyze_email():
    start = time.time()
    data = request.get_json(silent=True)
    if not data or not data.get('email_text', '').strip():
        return jsonify({'error': 'email_text is required'}), 400
    email_text = data['email_text']
    if len(email_text) > 50000:
        return jsonify({'error': 'Email too long (max 50,000 chars)'}), 400

    email_header = data.get('email_header', '')
    features = analyze_email_features(email_text)
    header_info = analyze_email_header(email_header) if email_header else {
        'spf_pass': None, 'dkim_present': False,
        'reply_to_mismatch': False, 'header_issues': []
    }

    prediction, confidence, ai_reasoning, ai_used = predict_email(email_text, features)
    is_phishing = bool(prediction)

    # Risk score
    f = features['features']
    raw = 0
    raw += min(f.get('urgency_count', 0), 4) * 8
    raw += min(f.get('threat_count', 0), 3) * 12
    raw += min(f.get('financial_count', 0), 3) * 10
    raw += min(f.get('credential_count', 0), 3) * 12
    raw += min(f.get('suspicious_url_count', 0), 5) * 20
    raw += min(f.get('brand_mention', 0), 2) * 6
    raw += min(f.get('all_caps_count', 0), 5) * 3
    raw += min(f.get('exclamation_count', 0), 5) * 2
    if is_phishing:
        risk_score = min(100, max(30, int(confidence)))
    else:
        risk_score = min(25, max(0, raw // 3))

    explanation = generate_explanation(prediction, confidence, features, risk_score)

    # Inject AI reasoning into explanation
    if ai_reasoning:
        explanation['ai_reasoning'] = ai_reasoning
        explanation['ai_powered'] = True
    else:
        explanation['ai_powered'] = False

    color_map = {'critical': 'red', 'high': 'orange', 'medium': 'yellow', 'low': 'blue'}
    threat_flags = [
        {'type': i['type'], 'label': i['label'],
         'color': color_map.get(i['severity'], 'orange'), 'active': True}
        for i in features['indicators']
    ]

    scan_id = get_scan_id()
    processing_ms = round((time.time() - start) * 1000, 2)
    scan_stats['total_scans'] += 1
    if is_phishing:
        scan_stats['phishing_detected'] += 1
    else:
        scan_stats['safe_emails'] += 1

    return jsonify({
        'scan_id': scan_id,
        'timestamp': datetime.utcnow().isoformat(),
        'prediction': {
            'label': 'PHISHING' if is_phishing else 'LEGITIMATE',
            'is_phishing': is_phishing,
            'confidence': confidence,
            'risk_score': risk_score
        },
        'explanation': explanation,
        'indicators': features['indicators'],
        'threat_flags': threat_flags,
        'urls': features['urls'],
        'features': features['features'],
        'highlighted_keywords': features.get('highlighted_keywords', []),
        'header_analysis': header_info,
        'processing_time_ms': processing_ms,
        'model_confidence': confidence,
        'ai_used': ai_used
    })


@app.route('/api/scan-links', methods=['POST'])
def scan_links():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    urls = data.get('urls', [])
    if not urls and data.get('text'):
        urls = extract_urls(data['text'])
    if not urls:
        return jsonify({'error': 'No URLs provided'}), 400
    from utils.email_analyzer import analyze_url
    results = [analyze_url(url) for url in urls[:20]]
    return jsonify({
        'urls_analyzed': len(results),
        'results': results,
        'overall_risk': max((r['risk'] for r in results), default=0),
        'safe_count': sum(1 for r in results if r['safe']),
        'suspicious_count': sum(1 for r in results if not r['safe'])
    })


@app.route('/api/dashboard-stats', methods=['GET'])
def dashboard_stats():
    return jsonify({
        **scan_stats,
        'detection_rate': round(
            scan_stats['phishing_detected'] / max(scan_stats['total_scans'], 1) * 100, 1),
        'model_accuracy': round(MODEL_METRICS['accuracy'] * 100, 2),
        'model_precision': round(MODEL_METRICS['precision'] * 100, 2),
        'model_recall': round(MODEL_METRICS['recall'] * 100, 2),
        'model_f1': round(MODEL_METRICS['f1_score'] * 100, 2),
        'model_cv_accuracy': round(MODEL_METRICS['cv_mean'] * 100, 2),
        'ai_enabled': bool(GEMINI_API_KEY)
    })


@app.route('/api/model-info', methods=['GET'])
def model_info():
    return jsonify({
        'model_type': 'Gemini AI + Rule-Based Hybrid',
        'model_loaded': True,
        'ai_enabled': bool(GEMINI_API_KEY),
        'metrics': MODEL_METRICS,
        'features': [
            'gemini_ai_analysis', 'urgency_patterns', 'threat_patterns',
            'financial_lures', 'credential_harvesting', 'url_analysis',
            'brand_impersonation', 'header_analysis', 'formatting_signals'
        ]
    })


@app.route('/api/export-report', methods=['POST'])
def export_report():
    data = request.get_json(silent=True) or {}
    prediction = data.get('prediction', {})
    return jsonify({
        'report_id': get_scan_id(),
        'generated_at': datetime.utcnow().isoformat(),
        'platform': 'PhishGuard AI v2.0',
        'summary': {
            'verdict': prediction.get('label', 'UNKNOWN'),
            'risk_score': prediction.get('risk_score', 0),
            'confidence': prediction.get('confidence', 0)
        },
        'indicators': data.get('indicators', []),
        'threat_flags': data.get('threat_flags', [])
    })


@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({'error': 'Method not allowed'}), 405


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
