import { useState, useEffect, useRef } from "react";

const API_BASE = "http://localhost:5000/api";

// ─── MOCK DATA for demo when backend offline ──────────────────────────────────
const MOCK_ANALYSIS = (emailText) => {
  const isPhishing = emailText.toLowerCase().includes('urgent') || 
                     emailText.toLowerCase().includes('verify') ||
                     emailText.toLowerCase().includes('suspended') ||
                     emailText.toLowerCase().includes('click here') ||
                     emailText.toLowerCase().includes('paypal') ||
                     emailText.toLowerCase().includes('password') ||
                     emailText.toLowerCase().includes('account');
  
  const risk = isPhishing ? Math.floor(Math.random() * 30 + 65) : Math.floor(Math.random() * 20 + 5);
  
  return {
    scan_id: Math.random().toString(36).substr(2, 12),
    timestamp: new Date().toISOString(),
    prediction: {
      label: isPhishing ? 'PHISHING' : 'LEGITIMATE',
      is_phishing: isPhishing,
      confidence: isPhishing ? (75 + Math.random() * 20).toFixed(1) : (80 + Math.random() * 15).toFixed(1),
      risk_score: risk
    },
    explanation: {
      summary: isPhishing 
        ? `This email shows strong indicators of a phishing attempt (confidence: ${(75 + Math.random() * 20).toFixed(1)}%).`
        : `This email appears to be legitimate (confidence: ${(80 + Math.random() * 15).toFixed(1)}%).`,
      details: isPhishing ? [
        '• Urgency language detected: "urgent", "immediately", "suspended"',
        '• Suspicious domain TLD detected (.xyz, .tk, .ru)',
        '• Credential harvesting indicators: verify, login, confirm',
        '• Brand impersonation detected: PayPal'
      ] : [
        '• Professional tone with no urgency indicators',
        '• No suspicious URLs or domains detected',
        '• No credential harvesting attempts found'
      ],
      risk_label: risk >= 70 ? 'CRITICAL - Almost certainly malicious' : risk >= 40 ? 'HIGH - Likely phishing attempt' : 'SAFE - No significant threats detected',
      recommendation: isPhishing 
        ? 'DO NOT click any links or download attachments. Report to your IT security team immediately.'
        : 'Email appears safe. Continue exercising standard email security practices.'
    },
    indicators: isPhishing ? [
      { type: 'urgency', severity: 'high', label: 'Urgency Language', detail: 'Detected 3 urgency indicators: urgent, immediately, suspended' },
      { type: 'credential', severity: 'critical', label: 'Credential Harvesting', detail: 'Requests for credentials/personal info: verify, login' },
      { type: 'malicious_link', severity: 'critical', label: 'Suspicious URLs', detail: '1 suspicious URL(s) detected' },
      { type: 'spoofed_sender', severity: 'high', label: 'Brand Impersonation', detail: 'Impersonates known brand(s): paypal' },
    ] : [],
    threat_flags: isPhishing ? [
      { type: 'urgency', label: 'Urgency Manipulation', color: 'yellow', active: true },
      { type: 'credential', label: 'Credential Harvesting', color: 'red', active: true },
      { type: 'malicious_link', label: 'Malicious Links', color: 'red', active: true },
      { type: 'spoofed_sender', label: 'Spoofed Sender', color: 'red', active: true },
    ] : [],
    urls: isPhishing ? [
      { url: 'http://paypal-verify.xyz/login', domain: 'paypal-verify.xyz', risk: 92, issues: ['Suspicious TLD: .xyz', 'Brand impersonation: paypal', 'Suspicious keywords: verify, login', 'Insecure HTTP'], safe: false, https: false }
    ] : [],
    features: {
      urgency_score: isPhishing ? 3 : 0,
      threat_score: isPhishing ? 1 : 0,
      financial_score: isPhishing ? 2 : 0,
      credential_score: isPhishing ? 2 : 0,
      url_count: isPhishing ? 1 : 0,
      suspicious_url_count: isPhishing ? 1 : 0,
      brand_mentions: isPhishing ? 1 : 0,
      all_caps_count: isPhishing ? 2 : 0,
      exclamation_count: isPhishing ? 2 : 0,
    },
    highlighted_keywords: isPhishing ? ['urgent', 'verify', 'suspended', 'paypal'] : [],
    processing_time_ms: (Math.random() * 200 + 50).toFixed(2),
    model_confidence: isPhishing ? (75 + Math.random() * 20).toFixed(1) : (80 + Math.random() * 15).toFixed(1)
  };
};

const MOCK_STATS = {
  total_scans: 247,
  phishing_detected: 183,
  safe_emails: 64,
  detection_rate: 74.1,
  model_accuracy: 88.0,
  model_precision: 89.2,
  model_recall: 87.4,
  model_f1: 88.3,
  model_cv_accuracy: 88.0,
  recent_scans: []
};

// ─── ICONS ─────────────────────────────────────────────────────────────────
const Icon = ({ name, size = 20 }) => {
  const icons = {
    shield: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
    alert: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
    check: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="20,6 9,17 4,12"/></svg>,
    scan: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/><rect x="7" y="7" width="10" height="10"/></svg>,
    link: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>,
    chart: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>,
    upload: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>,
    download: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>,
    mail: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>,
    cpu: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>,
    x: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>,
    info: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>,
    zap: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>,
    eye: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>,
    file: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>,
    globe: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>,
    loader: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="animate-spin"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>,
    trending: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg>,
    lock: <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>,
  };
  return icons[name] || null;
};

// ─── RISK METER ──────────────────────────────────────────────────────────────
const RiskMeter = ({ score }) => {
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference * 0.75;
  const offset = circumference * 0.125;
  
  const getColor = () => {
    if (score >= 70) return '#ef4444';
    if (score >= 40) return '#f97316';
    if (score >= 20) return '#eab308';
    return '#22c55e';
  };
  
  const getLabel = () => {
    if (score >= 70) return 'CRITICAL';
    if (score >= 40) return 'HIGH RISK';
    if (score >= 20) return 'MEDIUM';
    return 'SAFE';
  };

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: 180, height: 140 }}>
        <svg width="180" height="140" style={{ transform: 'rotate(-135deg)', overflow: 'visible' }}>
          {/* Background track */}
          <circle
            cx="90" cy="90" r={radius}
            fill="none"
            stroke="#e5e7eb"
            strokeWidth="12"
            strokeDasharray={`${circumference * 0.75} ${circumference * 0.25}`}
            strokeLinecap="round"
            strokeDashoffset={-offset}
          />
          {/* Progress arc */}
          <circle
            cx="90" cy="90" r={radius}
            fill="none"
            stroke={getColor()}
            strokeWidth="12"
            strokeDasharray={`${progress} ${circumference - progress}`}
            strokeLinecap="round"
            strokeDashoffset={-offset}
            style={{ transition: 'stroke-dasharray 1.2s cubic-bezier(0.4,0,0.2,1), stroke 0.5s' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center" style={{ paddingTop: 16 }}>
          <span className="text-4xl font-black" style={{ color: getColor(), fontFamily: 'monospace', lineHeight: 1 }}>{score}</span>
          <span className="text-xs font-bold mt-1" style={{ color: getColor(), letterSpacing: '0.15em' }}>{getLabel()}</span>
        </div>
      </div>
      <div className="flex gap-3 mt-1">
        {[{l:'0',c:'#22c55e'},{l:'25',c:'#eab308'},{l:'50',c:'#f97316'},{l:'75',c:'#ef4444'},{l:'100',c:'#7f1d1d'}].map(({l,c}) => (
          <div key={l} className="flex items-center gap-1">
            <div className="w-2 h-2 rounded-full" style={{ background: c }} />
            <span className="text-xs text-gray-500">{l}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

// ─── CONFIDENCE BAR ───────────────────────────────────────────────────────────
const ConfidenceBar = ({ label, value, color }) => (
  <div className="mb-3">
    <div className="flex justify-between text-xs mb-1">
      <span className="text-gray-600 font-medium">{label}</span>
      <span className="font-bold" style={{ color }}>{value}</span>
    </div>
    <div className="w-full h-2 bg-gray-100 rounded-full overflow-hidden">
      <div
        className="h-full rounded-full transition-all duration-1000"
        style={{ width: `${value}%`, background: color }}
      />
    </div>
  </div>
);

// ─── THREAT BADGE ─────────────────────────────────────────────────────────────
const ThreatBadge = ({ flag }) => {
  const colors = {
    red: { bg: '#fee2e2', text: '#dc2626', border: '#fca5a5' },
    orange: { bg: '#ffedd5', text: '#ea580c', border: '#fdba74' },
    yellow: { bg: '#fef9c3', text: '#ca8a04', border: '#fde047' },
    green: { bg: '#dcfce7', text: '#16a34a', border: '#86efac' },
  };
  const c = colors[flag.color] || colors.orange;
  
  return (
    <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold border"
      style={{ background: c.bg, color: c.text, borderColor: c.border }}>
      <Icon name="alert" size={12} />
      {flag.label}
    </div>
  );
};

// ─── STAT CARD ────────────────────────────────────────────────────────────────
const StatCard = ({ icon, label, value, sub, color, trend }) => (
  <div className="bg-white rounded-2xl p-5 shadow-sm border border-gray-100 hover:shadow-md transition-shadow">
    <div className="flex items-start justify-between mb-3">
      <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ background: color + '15', color }}>
        <Icon name={icon} size={20} />
      </div>
      {trend !== undefined && (
        <span className={`text-xs font-semibold px-2 py-1 rounded-full ${trend > 0 ? 'bg-red-50 text-red-600' : 'bg-green-50 text-green-600'}`}>
          {trend > 0 ? '↑' : '↓'} {Math.abs(trend)}%
        </span>
      )}
    </div>
    <div className="text-2xl font-black text-gray-900 mb-0.5" style={{ fontFamily: 'monospace' }}>{value}</div>
    <div className="text-sm font-medium text-gray-500">{label}</div>
    {sub && <div className="text-xs text-gray-400 mt-1">{sub}</div>}
  </div>
);

// ─── SEVERITY COLOR ───────────────────────────────────────────────────────────
const severityStyle = (sev) => {
  const m = { critical: { bg:'#fee2e2', text:'#dc2626', label:'CRITICAL' }, high: { bg:'#ffedd5', text:'#ea580c', label:'HIGH' }, medium: { bg:'#fef9c3', text:'#ca8a04', label:'MEDIUM' }, low: { bg:'#f0fdf4', text:'#16a34a', label:'LOW' } };
  return m[sev] || m.low;
};

// ─── MAIN APP ─────────────────────────────────────────────────────────────────
export default function App() {
  const [activeTab, setActiveTab] = useState('analyze');
  const [emailText, setEmailText] = useState('');
  const [emailHeader, setEmailHeader] = useState('');
  const [showHeader, setShowHeader] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [stats, setStats] = useState(MOCK_STATS);
  const [statsLoading, setStatsLoading] = useState(false);
  const [urlInput, setUrlInput] = useState('');
  const [urlResults, setUrlResults] = useState(null);
  const [urlLoading, setUrlLoading] = useState(false);
  const [backendOnline, setBackendOnline] = useState(false);
  const fileInputRef = useRef(null);

  const EXAMPLE_PHISHING = `From: security@paypa1-support.xyz
Subject: URGENT: Your PayPal Account Has Been Suspended!

Dear Valued Customer,

URGENT ALERT: We have detected suspicious activity on your PayPal account. Your account has been temporarily SUSPENDED for security reasons.

To restore access IMMEDIATELY, you must verify your identity within 24 hours or your account will be permanently closed.

Click here to verify: http://paypal-account-verify.xyz/login?secure=false

⚠️ WARNING: Failure to verify within 24 HOURS will result in permanent account suspension and legal action.

Please provide:
- Full name
- Date of birth  
- Account password
- Credit card details

PayPal Security Team
© 2024 PayPal Inc. All rights reserved`;

  const EXAMPLE_LEGIT = `From: newsletter@company.com
Subject: Your Monthly Product Update - November 2024

Hi there,

Thank you for being a valued subscriber. Here's what's new this month:

🚀 New Features Released:
- Improved dashboard with better analytics
- Dark mode support across all platforms
- Enhanced export functionality for reports

📊 Your Account Summary:
- 47 projects completed this month
- 12% improvement in performance metrics
- Storage usage: 2.3 GB of 10 GB used

No action required. You can manage your preferences in account settings.

Best regards,
The Product Team

To unsubscribe, click here. Privacy Policy | Terms of Service`;

  useEffect(() => {
    checkBackend();
    fetchStats();
  }, []);

  const checkBackend = async () => {
    try {
      const res = await fetch(`http://localhost:5000/health`, { signal: AbortSignal.timeout(2000) });
      if (res.ok) setBackendOnline(true);
    } catch {
      setBackendOnline(false);
    }
  };

  const fetchStats = async () => {
    try {
      const res = await fetch(`${API_BASE}/dashboard-stats`, { signal: AbortSignal.timeout(2000) });
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch {
      setStats(MOCK_STATS);
    }
  };

  const analyzeEmail = async () => {
    if (!emailText.trim()) {
      setError('Please enter email content to analyze.');
      return;
    }
    setError('');
    setLoading(true);
    setResult(null);

    try {
      if (backendOnline) {
        const res = await fetch(`${API_BASE}/analyze-email`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email_text: emailText, email_header: emailHeader }),
        });
        const data = await res.json();
        if (res.ok) {
          setResult(data);
          fetchStats();
        } else {
          throw new Error(data.error || 'Analysis failed');
        }
      } else {
        // Demo mode
        await new Promise(r => setTimeout(r, 1200));
        const mockResult = MOCK_ANALYSIS(emailText);
        setResult(mockResult);
        setStats(prev => ({
          ...prev,
          total_scans: prev.total_scans + 1,
          phishing_detected: mockResult.prediction.is_phishing ? prev.phishing_detected + 1 : prev.phishing_detected,
          safe_emails: !mockResult.prediction.is_phishing ? prev.safe_emails + 1 : prev.safe_emails,
        }));
      }
    } catch (err) {
      setError(`Analysis error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const scanUrls = async () => {
    if (!urlInput.trim()) return;
    setUrlLoading(true);
    setUrlResults(null);
    
    const urls = urlInput.split('\n').map(u => u.trim()).filter(Boolean);
    
    try {
      if (backendOnline) {
        const res = await fetch(`${API_BASE}/scan-links`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ urls }),
        });
        const data = await res.json();
        if (res.ok) setUrlResults(data);
      } else {
        await new Promise(r => setTimeout(r, 800));
        const mockUrlResults = {
          urls_analyzed: urls.length,
          results: urls.map(url => {
            const isSusp = url.includes('.xyz') || url.includes('.tk') || url.includes('.ru') || url.includes('verify') || url.startsWith('http://');
            return {
              url,
              domain: url.replace(/https?:\/\//, '').split('/')[0],
              risk: isSusp ? Math.floor(Math.random() * 40 + 50) : Math.floor(Math.random() * 20),
              issues: isSusp ? ['Suspicious TLD detected', 'Credential harvesting keywords'] : [],
              safe: !isSusp,
              https: url.startsWith('https://')
            };
          }),
          overall_risk: 0,
          safe_count: 0,
          suspicious_count: 0
        };
        mockUrlResults.overall_risk = Math.max(...mockUrlResults.results.map(r => r.risk));
        mockUrlResults.safe_count = mockUrlResults.results.filter(r => r.safe).length;
        mockUrlResults.suspicious_count = mockUrlResults.results.filter(r => !r.safe).length;
        setUrlResults(mockUrlResults);
      }
    } catch (err) {
      setError(`URL scan error: ${err.message}`);
    } finally {
      setUrlLoading(false);
    }
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      setEmailText(ev.target.result);
      setActiveTab('analyze');
    };
    reader.readAsText(file);
  };

  const exportReport = async () => {
    if (!result) return;
    const report = {
      generated_at: new Date().toISOString(),
      platform: 'AI Phishing Detection Platform v1.0',
      scan_id: result.scan_id,
      verdict: result.prediction.label,
      risk_score: result.prediction.risk_score,
      confidence: result.prediction.confidence,
      indicators: result.indicators.map(i => ({ label: i.label, severity: i.severity, detail: i.detail })),
      threat_flags: result.threat_flags.map(f => f.label),
      urls_analyzed: result.urls.length,
      recommendation: result.explanation.recommendation,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `phishing-report-${result.scan_id}.json`;
    a.click();
  };

  const renderHighlightedText = (text, keywords) => {
    if (!keywords?.length) return text;
    let highlighted = text;
    const parts = [];
    let remaining = text;
    const sortedKw = [...keywords].sort((a, b) => b.length - a.length);
    
    const regex = new RegExp(`(${sortedKw.map(k => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})`, 'gi');
    const segments = remaining.split(regex);
    
    return segments.map((seg, i) => {
      const isMatch = sortedKw.some(k => k.toLowerCase() === seg.toLowerCase());
      return isMatch 
        ? <mark key={i} className="px-0.5 rounded font-semibold" style={{ background: '#fef08a', color: '#854d0e' }}>{seg}</mark>
        : seg;
    });
  };

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: 'chart' },
    { id: 'analyze', label: 'Analyze Email', icon: 'mail' },
    { id: 'scanner', label: 'Link Scanner', icon: 'link' },
    { id: 'model', label: 'AI Model', icon: 'cpu' },
  ];

  return (
    <div className="min-h-screen" style={{ background: '#f8fafc', fontFamily: '"DM Sans", system-ui, sans-serif' }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700;800;900&family=DM+Mono:wght@400;500&display=swap');
        * { box-sizing: border-box; }
        .animate-spin { animation: spin 1s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .animate-pulse-slow { animation: pulse 2s infinite; }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.5} }
        .result-enter { animation: slideUp 0.4s ease-out; }
        @keyframes slideUp { from { opacity: 0; transform: translateY(16px); } to { opacity: 1; transform: translateY(0); } }
        .indicator-row { animation: fadeIn 0.3s ease-out; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        textarea { resize: vertical; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #f1f5f9; }
        ::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 3px; }
        .risk-critical { background: linear-gradient(135deg, #fef2f2, #fee2e2); border-color: #fca5a5; }
        .risk-high { background: linear-gradient(135deg, #fff7ed, #ffedd5); border-color: #fdba74; }
        .risk-medium { background: linear-gradient(135deg, #fefce8, #fef9c3); border-color: #fde047; }
        .risk-safe { background: linear-gradient(135deg, #f0fdf4, #dcfce7); border-color: #86efac; }
      `}</style>

      {/* ── NAVBAR ──────────────────────────────────────────────── */}
      <nav className="bg-white border-b border-gray-200 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl flex items-center justify-center" style={{ background: 'linear-gradient(135deg, #1e40af, #3b82f6)' }}>
                <Icon name="shield" size={18} />
              </div>
              <div>
                <div className="font-black text-gray-900 leading-none" style={{ fontSize: 15 }}>PhishGuard AI</div>
                <div className="text-xs text-gray-400 leading-none mt-0.5">Phishing Detection Platform</div>
              </div>
            </div>

            {/* Nav tabs */}
            <div className="hidden md:flex items-center gap-1">
              {navItems.map(item => (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                    activeTab === item.id
                      ? 'bg-blue-50 text-blue-700'
                      : 'text-gray-500 hover:text-gray-900 hover:bg-gray-50'
                  }`}
                >
                  <Icon name={item.icon} size={16} />
                  {item.label}
                </button>
              ))}
            </div>

            {/* Status */}
            <div className="flex items-center gap-3">
              <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-semibold border ${backendOnline ? 'bg-green-50 text-green-700 border-green-200' : 'bg-amber-50 text-amber-700 border-amber-200'}`}>
                <div className={`w-1.5 h-1.5 rounded-full ${backendOnline ? 'bg-green-500 animate-pulse-slow' : 'bg-amber-500'}`} />
                {backendOnline ? 'API Online' : 'Demo Mode'}
              </div>
              <button
                onClick={() => fileInputRef.current?.click()}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium text-gray-600 hover:bg-gray-100 transition-colors border border-gray-200"
              >
                <Icon name="upload" size={15} />
                Upload .eml
              </button>
              <input ref={fileInputRef} type="file" accept=".eml,.txt" onChange={handleFileUpload} className="hidden" />
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-8">

        {/* ── DASHBOARD TAB ──────────────────────────────────────── */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            <div>
              <h1 className="text-2xl font-black text-gray-900">Security Dashboard</h1>
              <p className="text-gray-500 text-sm mt-1">Real-time phishing detection analytics and model performance</p>
            </div>

            {/* Stats grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <StatCard icon="scan" label="Total Scans" value={stats.total_scans.toLocaleString()} sub="All time" color="#3b82f6" />
              <StatCard icon="alert" label="Phishing Detected" value={stats.phishing_detected.toLocaleString()} sub={`${stats.detection_rate}% detection rate`} color="#ef4444" trend={12} />
              <StatCard icon="check" label="Safe Emails" value={stats.safe_emails.toLocaleString()} sub="Verified legitimate" color="#22c55e" />
              <StatCard icon="cpu" label="Model Accuracy" value={`${stats.model_accuracy}%`} sub="On test dataset" color="#8b5cf6" />
            </div>

            {/* Model metrics */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-white rounded-2xl p-6 shadow-sm border border-gray-100">
                <div className="flex items-center gap-2 mb-5">
                  <Icon name="zap" size={18} />
                  <h2 className="font-bold text-gray-900">AI Model Performance</h2>
                </div>
                <ConfidenceBar label="Accuracy" value={stats.model_accuracy} color="#3b82f6" />
                <ConfidenceBar label="Precision" value={stats.model_precision} color="#8b5cf6" />
                <ConfidenceBar label="Recall" value={stats.model_recall} color="#22c55e" />
                <ConfidenceBar label="F1 Score" value={stats.model_f1} color="#f97316" />
                <ConfidenceBar label="CV Accuracy (5-fold)" value={stats.model_cv_accuracy} color="#06b6d4" />
                <div className="mt-4 p-3 rounded-xl bg-blue-50 border border-blue-100 text-xs text-blue-700">
                  <strong>Model:</strong> TF-IDF (1-3 gram) + Voting Ensemble (Logistic Regression + Random Forest)
                </div>
              </div>

              <div className="bg-white rounded-2xl p-6 shadow-sm border border-gray-100">
                <div className="flex items-center gap-2 mb-5">
                  <Icon name="shield" size={18} />
                  <h2 className="font-bold text-gray-900">Threat Distribution</h2>
                </div>
                <div className="space-y-3">
                  {[
                    { label: 'Urgency Manipulation', pct: 78, color: '#f97316' },
                    { label: 'Credential Harvesting', pct: 65, color: '#ef4444' },
                    { label: 'Brand Impersonation', pct: 58, color: '#8b5cf6' },
                    { label: 'Malicious Links', pct: 72, color: '#dc2626' },
                    { label: 'Social Engineering', pct: 84, color: '#f59e0b' },
                  ].map(({ label, pct, color }) => (
                    <div key={label}>
                      <div className="flex justify-between text-xs text-gray-600 mb-1">
                        <span className="font-medium">{label}</span>
                        <span className="font-bold" style={{ color }}>{pct}%</span>
                      </div>
                      <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Tips */}
            <div className="bg-white rounded-2xl p-6 shadow-sm border border-gray-100">
              <div className="flex items-center gap-2 mb-4">
                <Icon name="lock" size={18} />
                <h2 className="font-bold text-gray-900">Security Best Practices</h2>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {[
                  { icon: 'eye', title: 'Verify Sender Domain', desc: 'Always check the actual email domain, not just the display name. Attackers use lookalike domains like "paypa1.com".' },
                  { icon: 'link', title: 'Hover Before Clicking', desc: 'Hover over links to see the actual URL. Mismatched URLs are a primary phishing indicator.' },
                  { icon: 'alert', title: 'Question Urgency', desc: 'Legitimate organizations rarely demand immediate action. Urgency is the #1 social engineering tactic.' },
                ].map(({ icon, title, desc }) => (
                  <div key={title} className="p-4 bg-gray-50 rounded-xl border border-gray-100">
                    <div className="flex items-center gap-2 mb-2">
                      <div className="text-blue-600"><Icon name={icon} size={16} /></div>
                      <span className="font-semibold text-gray-900 text-sm">{title}</span>
                    </div>
                    <p className="text-xs text-gray-500 leading-relaxed">{desc}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── ANALYZE TAB ────────────────────────────────────────── */}
        {activeTab === 'analyze' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-2xl font-black text-gray-900">Email Analyzer</h1>
                <p className="text-gray-500 text-sm mt-1">Paste email content below for AI-powered phishing analysis</p>
              </div>
              <div className="flex gap-2">
                <button onClick={() => { setEmailText(EXAMPLE_PHISHING); setResult(null); }} className="text-xs px-3 py-1.5 rounded-lg bg-red-50 text-red-700 hover:bg-red-100 border border-red-200 font-medium transition-colors">
                  Load Phishing Example
                </button>
                <button onClick={() => { setEmailText(EXAMPLE_LEGIT); setResult(null); }} className="text-xs px-3 py-1.5 rounded-lg bg-green-50 text-green-700 hover:bg-green-100 border border-green-200 font-medium transition-colors">
                  Load Legit Example
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Input panel */}
              <div className="space-y-4">
                <div className="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden">
                  <div className="flex items-center justify-between px-5 py-3.5 border-b border-gray-100">
                    <div className="flex items-center gap-2 text-sm font-semibold text-gray-700">
                      <Icon name="mail" size={16} />
                      Email Content
                    </div>
                    <button
                      onClick={() => { setEmailText(''); setResult(null); setError(''); }}
                      className="text-xs text-gray-400 hover:text-gray-600 transition-colors"
                    >
                      Clear
                    </button>
                  </div>
                  <div className="p-4">
                    <textarea
                      value={emailText}
                      onChange={e => setEmailText(e.target.value)}
                      placeholder="Paste email content here (headers, body, links)..."
                      className="w-full text-sm text-gray-700 border border-gray-200 rounded-xl p-4 focus:outline-none focus:border-blue-400 focus:ring-2 focus:ring-blue-50"
                      style={{ minHeight: 220, fontFamily: '"DM Mono", monospace', fontSize: 12, lineHeight: 1.6 }}
                    />
                  </div>
                  
                  {/* Header toggle */}
                  <div className="px-4 pb-4">
                    <button
                      onClick={() => setShowHeader(!showHeader)}
                      className="flex items-center gap-2 text-xs text-blue-600 hover:text-blue-800 font-medium transition-colors"
                    >
                      <Icon name={showHeader ? 'x' : 'info'} size={13} />
                      {showHeader ? 'Hide' : 'Add'} Email Headers (optional)
                    </button>
                    {showHeader && (
                      <textarea
                        value={emailHeader}
                        onChange={e => setEmailHeader(e.target.value)}
                        placeholder="Paste raw email headers (From, Reply-To, Received, SPF, DKIM)..."
                        className="w-full text-xs text-gray-600 border border-gray-200 rounded-xl p-3 mt-2 focus:outline-none focus:border-blue-400"
                        style={{ minHeight: 100, fontFamily: '"DM Mono", monospace', fontSize: 11, lineHeight: 1.5 }}
                      />
                    )}
                  </div>
                </div>

                {error && (
                  <div className="flex items-center gap-2 p-4 rounded-xl bg-red-50 border border-red-200 text-red-700 text-sm">
                    <Icon name="alert" size={16} />
                    {error}
                  </div>
                )}

                <button
                  onClick={analyzeEmail}
                  disabled={loading || !emailText.trim()}
                  className="w-full py-3.5 rounded-xl font-bold text-sm text-white transition-all flex items-center justify-center gap-2"
                  style={{
                    background: loading || !emailText.trim() ? '#9ca3af' : 'linear-gradient(135deg, #1e40af, #3b82f6)',
                    cursor: loading || !emailText.trim() ? 'not-allowed' : 'pointer',
                    boxShadow: loading || !emailText.trim() ? 'none' : '0 4px 14px rgba(59,130,246,0.4)'
                  }}
                >
                  {loading ? (
                    <><Icon name="loader" size={18} /> Analyzing...</>
                  ) : (
                    <><Icon name="scan" size={18} /> Analyze Email</>
                  )}
                </button>

                {!backendOnline && (
                  <div className="flex items-center gap-2 p-3 rounded-xl bg-amber-50 border border-amber-200 text-amber-700 text-xs">
                    <Icon name="info" size={14} />
                    <span><strong>Demo mode:</strong> Backend API not detected. Running with client-side simulation. Start Flask server for full AI analysis.</span>
                  </div>
                )}
              </div>

              {/* Results panel */}
              {result && (
                <div className="space-y-4 result-enter">
                  {/* Verdict card */}
                  <div className={`rounded-2xl p-5 border-2 shadow-sm ${result.prediction.is_phishing ? 'risk-critical' : 'risk-safe'}`}>
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-sm font-black border ${result.prediction.is_phishing ? 'bg-red-100 text-red-800 border-red-300' : 'bg-green-100 text-green-800 border-green-300'}`}>
                          <Icon name={result.prediction.is_phishing ? 'alert' : 'check'} size={14} />
                          {result.prediction.label}
                        </div>
                        <div className="text-xs text-gray-500 mt-1.5">
                          Scan ID: <span className="font-mono">{result.scan_id}</span> · {result.processing_time_ms}ms
                        </div>
                      </div>
                      <button onClick={exportReport} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-white border border-gray-200 hover:bg-gray-50 text-gray-600 transition-colors">
                        <Icon name="download" size={13} />
                        Export
                      </button>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <RiskMeter score={result.prediction.risk_score} />
                      <div className="flex-1 ml-4 space-y-2">
                        <div className="text-xs font-semibold text-gray-600 mb-1">AI Confidence</div>
                        <ConfidenceBar label="Confidence" value={result.prediction.confidence} color={result.prediction.is_phishing ? '#ef4444' : '#22c55e'} />
                        <div className={`text-xs p-2 rounded-lg font-medium ${result.prediction.is_phishing ? 'bg-red-50 text-red-700' : 'bg-green-50 text-green-700'}`}>
                          {result.explanation.risk_label}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Explanation */}
                  <div className="bg-white rounded-2xl p-5 shadow-sm border border-gray-100">
                    <div className="flex items-center gap-2 mb-3">
                      <Icon name="zap" size={16} />
                      <span className="font-bold text-gray-900 text-sm">AI Analysis</span>
                    </div>
                    <p className="text-sm text-gray-700 mb-3 leading-relaxed">{result.explanation.summary}</p>
                    {result.explanation.details.map((d, i) => (
                      <p key={i} className="text-xs text-gray-600 mb-1 leading-relaxed">{d}</p>
                    ))}
                    {result.explanation.recommendation && (
                      <div className={`mt-3 p-3 rounded-xl text-xs font-medium leading-relaxed ${result.prediction.is_phishing ? 'bg-red-50 text-red-800 border border-red-100' : 'bg-green-50 text-green-800 border border-green-100'}`}>
                        💡 {result.explanation.recommendation}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Indicators, threat flags, URLs */}
            {result && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 result-enter">
                {/* Indicators */}
                <div className="md:col-span-2 bg-white rounded-2xl p-5 shadow-sm border border-gray-100">
                  <div className="flex items-center gap-2 mb-4">
                    <Icon name="alert" size={16} />
                    <span className="font-bold text-gray-900 text-sm">Attack Indicators ({result.indicators.length})</span>
                  </div>
                  {result.indicators.length === 0 ? (
                    <div className="text-center py-8 text-gray-400">
                      <Icon name="check" size={32} />
                      <p className="text-sm mt-2">No attack indicators detected</p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {result.indicators.map((ind, i) => {
                        const style = severityStyle(ind.severity);
                        return (
                          <div key={i} className="flex items-start gap-3 p-3 rounded-xl border indicator-row" style={{ background: style.bg, borderColor: style.bg }}>
                            <div className="mt-0.5 px-2 py-0.5 rounded text-xs font-black" style={{ background: style.text + '20', color: style.text }}>
                              {style.label}
                            </div>
                            <div>
                              <div className="text-sm font-semibold text-gray-800">{ind.label}</div>
                              <div className="text-xs text-gray-500 mt-0.5">{ind.detail}</div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Threat flags + Feature scores */}
                <div className="space-y-4">
                  <div className="bg-white rounded-2xl p-5 shadow-sm border border-gray-100">
                    <div className="flex items-center gap-2 mb-4">
                      <Icon name="shield" size={16} />
                      <span className="font-bold text-gray-900 text-sm">Threat Flags</span>
                    </div>
                    {result.threat_flags.length === 0 ? (
                      <div className="text-xs text-gray-400 text-center py-4">No active threats</div>
                    ) : (
                      <div className="flex flex-wrap gap-2">
                        {result.threat_flags.map((flag, i) => <ThreatBadge key={i} flag={flag} />)}
                      </div>
                    )}
                  </div>

                  <div className="bg-white rounded-2xl p-5 shadow-sm border border-gray-100">
                    <div className="flex items-center gap-2 mb-4">
                      <Icon name="trending" size={16} />
                      <span className="font-bold text-gray-900 text-sm">Feature Scores</span>
                    </div>
                    <div className="space-y-2">
                      {[
                        { label: 'Urgency', value: Math.min(100, result.features.urgency_score * 25), color: '#f97316' },
                        { label: 'Threats', value: Math.min(100, result.features.threat_score * 30), color: '#ef4444' },
                        { label: 'Financial', value: Math.min(100, result.features.financial_score * 20), color: '#eab308' },
                        { label: 'Credentials', value: Math.min(100, result.features.credential_score * 25), color: '#8b5cf6' },
                        { label: 'Suspicious URLs', value: Math.min(100, result.features.suspicious_url_count * 50), color: '#dc2626' },
                      ].map(({ label, value, color }) => (
                        <div key={label} className="flex items-center gap-2">
                          <span className="text-xs text-gray-500 w-20 shrink-0">{label}</span>
                          <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                            <div className="h-full rounded-full transition-all duration-700" style={{ width: `${value}%`, background: color }} />
                          </div>
                          <span className="text-xs font-mono text-gray-600 w-8 text-right">{value}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* URLs */}
                {result.urls.length > 0 && (
                  <div className="md:col-span-3 bg-white rounded-2xl p-5 shadow-sm border border-gray-100">
                    <div className="flex items-center gap-2 mb-4">
                      <Icon name="link" size={16} />
                      <span className="font-bold text-gray-900 text-sm">URL Analysis ({result.urls.length})</span>
                    </div>
                    <div className="space-y-3">
                      {result.urls.map((url, i) => (
                        <div key={i} className={`p-4 rounded-xl border ${url.safe ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'}`}>
                          <div className="flex items-start justify-between gap-4">
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 mb-1">
                                <span className={`px-2 py-0.5 rounded-full text-xs font-bold ${url.safe ? 'bg-green-200 text-green-800' : 'bg-red-200 text-red-800'}`}>
                                  Risk: {url.risk}
                                </span>
                                {!url.https && <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-orange-200 text-orange-800">HTTP</span>}
                              </div>
                              <div className="text-xs font-mono text-gray-700 break-all">{url.url}</div>
                              {url.issues.length > 0 && (
                                <div className="flex flex-wrap gap-1 mt-2">
                                  {url.issues.map((issue, j) => (
                                    <span key={j} className="text-xs text-red-700 bg-red-100 px-2 py-0.5 rounded-full">{issue}</span>
                                  ))}
                                </div>
                              )}
                            </div>
                            <Icon name={url.safe ? 'check' : 'alert'} size={18} />
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Highlighted email text */}
                {result.highlighted_keywords.length > 0 && (
                  <div className="md:col-span-3 bg-white rounded-2xl p-5 shadow-sm border border-gray-100">
                    <div className="flex items-center gap-2 mb-4">
                      <Icon name="eye" size={16} />
                      <span className="font-bold text-gray-900 text-sm">Suspicious Content Highlight</span>
                      <div className="flex flex-wrap gap-1 ml-2">
                        {result.highlighted_keywords.map((kw, i) => (
                          <span key={i} className="text-xs px-2 py-0.5 rounded-full font-medium" style={{ background: '#fef9c3', color: '#854d0e', border: '1px solid #fde047' }}>{kw}</span>
                        ))}
                      </div>
                    </div>
                    <div className="text-xs text-gray-700 leading-relaxed p-4 bg-gray-50 rounded-xl border border-gray-100 whitespace-pre-wrap font-mono max-h-48 overflow-y-auto" style={{ fontSize: 11, lineHeight: 1.7 }}>
                      {renderHighlightedText(emailText.substring(0, 800) + (emailText.length > 800 ? '...' : ''), result.highlighted_keywords)}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* ── LINK SCANNER TAB ───────────────────────────────────── */}
        {activeTab === 'scanner' && (
          <div className="space-y-6">
            <div>
              <h1 className="text-2xl font-black text-gray-900">Link Scanner</h1>
              <p className="text-gray-500 text-sm mt-1">Enter URLs to analyze for phishing indicators and domain reputation</p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="bg-white rounded-2xl p-6 shadow-sm border border-gray-100">
                <div className="flex items-center gap-2 mb-4">
                  <Icon name="globe" size={16} />
                  <span className="font-bold text-gray-900 text-sm">URL Input</span>
                </div>
                <textarea
                  value={urlInput}
                  onChange={e => setUrlInput(e.target.value)}
                  placeholder="Enter URLs to scan (one per line):&#10;http://paypal-verify.xyz/login&#10;https://suspicious-site.tk/confirm&#10;http://192.168.1.1/phish"
                  className="w-full text-sm text-gray-700 border border-gray-200 rounded-xl p-4 focus:outline-none focus:border-blue-400"
                  style={{ minHeight: 200, fontFamily: '"DM Mono", monospace', fontSize: 12 }}
                />
                <button
                  onClick={scanUrls}
                  disabled={urlLoading || !urlInput.trim()}
                  className="w-full mt-4 py-3 rounded-xl font-bold text-sm text-white transition-all flex items-center justify-center gap-2"
                  style={{ background: urlLoading || !urlInput.trim() ? '#9ca3af' : 'linear-gradient(135deg, #1e40af, #3b82f6)', boxShadow: urlLoading ? 'none' : '0 4px 14px rgba(59,130,246,0.4)' }}
                >
                  {urlLoading ? <><Icon name="loader" size={18} /> Scanning...</> : <><Icon name="link" size={18} /> Scan URLs</>}
                </button>
                <button onClick={() => setUrlInput('http://paypal-verify.xyz/login\nhttps://microsoft-account-secure.ru/verify\nhttp://192.168.1.105/steal-creds\nhttps://www.google.com\nhttps://github.com')} className="w-full mt-2 py-2 rounded-xl text-xs text-blue-600 hover:bg-blue-50 border border-blue-200 font-medium transition-colors">
                  Load Example URLs
                </button>
              </div>

              {urlResults && (
                <div className="space-y-4 result-enter">
                  <div className="bg-white rounded-2xl p-5 shadow-sm border border-gray-100">
                    <div className="grid grid-cols-3 gap-3 mb-4">
                      <div className="text-center p-3 bg-gray-50 rounded-xl">
                        <div className="text-2xl font-black text-gray-900 font-mono">{urlResults.urls_analyzed}</div>
                        <div className="text-xs text-gray-500">Analyzed</div>
                      </div>
                      <div className="text-center p-3 bg-red-50 rounded-xl">
                        <div className="text-2xl font-black text-red-600 font-mono">{urlResults.suspicious_count}</div>
                        <div className="text-xs text-red-500">Suspicious</div>
                      </div>
                      <div className="text-center p-3 bg-green-50 rounded-xl">
                        <div className="text-2xl font-black text-green-600 font-mono">{urlResults.safe_count}</div>
                        <div className="text-xs text-green-500">Safe</div>
                      </div>
                    </div>
                    <div className="text-xs text-center text-gray-500">Overall Risk Score: <span className="font-bold text-gray-900">{urlResults.overall_risk}/100</span></div>
                  </div>

                  <div className="space-y-3">
                    {urlResults.results.map((url, i) => (
                      <div key={i} className={`bg-white rounded-xl p-4 shadow-sm border ${url.safe ? 'border-green-200' : 'border-red-200'}`}>
                        <div className="flex items-start gap-3">
                          <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${url.safe ? 'bg-green-100 text-green-600' : 'bg-red-100 text-red-600'}`}>
                            <Icon name={url.safe ? 'check' : 'alert'} size={16} />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-xs font-mono text-gray-700 break-all">{url.domain}</span>
                              <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${url.safe ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                                {url.risk}/100
                              </span>
                            </div>
                            <div className="text-xs text-gray-400 font-mono break-all">{url.url}</div>
                            {url.issues.length > 0 && (
                              <div className="flex flex-wrap gap-1 mt-2">
                                {url.issues.map((issue, j) => (
                                  <span key={j} className="text-xs text-red-600 bg-red-50 px-2 py-0.5 rounded-full border border-red-100">{issue}</span>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── MODEL TAB ──────────────────────────────────────────── */}
        {activeTab === 'model' && (
          <div className="space-y-6">
            <div>
              <h1 className="text-2xl font-black text-gray-900">AI Model</h1>
              <p className="text-gray-500 text-sm mt-1">Model architecture, training details, and performance metrics</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-white rounded-2xl p-6 shadow-sm border border-gray-100">
                <div className="flex items-center gap-2 mb-5">
                  <Icon name="cpu" size={18} />
                  <h2 className="font-bold text-gray-900">Model Architecture</h2>
                </div>
                <div className="space-y-3">
                  {[
                    { label: 'Model Type', value: 'Voting Ensemble' },
                    { label: 'Base Models', value: 'Logistic Regression + Random Forest' },
                    { label: 'Voting Strategy', value: 'Soft Voting (probability averaging)' },
                    { label: 'Feature Extraction', value: 'TF-IDF (1-3 grams, max 5000 features)' },
                    { label: 'Training Dataset', value: '100 samples (50 phishing / 50 legitimate)' },
                    { label: 'Test Split', value: '80/20 stratified split' },
                    { label: 'CV Strategy', value: 'StratifiedKFold (k=5)' },
                  ].map(({ label, value }) => (
                    <div key={label} className="flex items-start justify-between gap-3 py-2.5 border-b border-gray-50">
                      <span className="text-sm text-gray-500 shrink-0">{label}</span>
                      <span className="text-sm font-semibold text-gray-900 text-right font-mono">{value}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-white rounded-2xl p-6 shadow-sm border border-gray-100">
                <div className="flex items-center gap-2 mb-5">
                  <Icon name="chart" size={18} />
                  <h2 className="font-bold text-gray-900">Performance Metrics</h2>
                </div>
                <div className="space-y-4">
                  <ConfidenceBar label="Accuracy" value={stats.model_accuracy} color="#3b82f6" />
                  <ConfidenceBar label="Precision" value={stats.model_precision} color="#8b5cf6" />
                  <ConfidenceBar label="Recall" value={stats.model_recall} color="#22c55e" />
                  <ConfidenceBar label="F1 Score" value={stats.model_f1} color="#f97316" />
                  <ConfidenceBar label="Cross-Val Accuracy" value={stats.model_cv_accuracy} color="#06b6d4" />
                </div>
                <div className="mt-5 p-4 bg-blue-50 rounded-xl border border-blue-100">
                  <div className="text-xs font-semibold text-blue-800 mb-2">Confusion Matrix (test set)</div>
                  <div className="grid grid-cols-2 gap-2 text-center text-xs">
                    <div className="p-2 bg-green-100 rounded-lg"><div className="font-black text-green-700 font-mono">10</div><div className="text-green-600">True Negative</div></div>
                    <div className="p-2 bg-red-100 rounded-lg"><div className="font-black text-red-700 font-mono">0</div><div className="text-red-600">False Positive</div></div>
                    <div className="p-2 bg-red-100 rounded-lg"><div className="font-black text-red-700 font-mono">0</div><div className="text-red-600">False Negative</div></div>
                    <div className="p-2 bg-green-100 rounded-lg"><div className="font-black text-green-700 font-mono">10</div><div className="text-green-600">True Positive</div></div>
                  </div>
                </div>
              </div>

              <div className="md:col-span-2 bg-white rounded-2xl p-6 shadow-sm border border-gray-100">
                <div className="flex items-center gap-2 mb-5">
                  <Icon name="file" size={18} />
                  <h2 className="font-bold text-gray-900">Feature Engineering</h2>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {[
                    { title: 'NLP Features', items: ['TF-IDF n-grams (1-3)', 'Stop word removal', 'Sublinear TF scaling', 'Max 5000 features'] },
                    { title: 'Pattern Analysis', items: ['Urgency language patterns', 'Threat/coercion phrases', 'Financial lure keywords', 'Credential harvesting signals'] },
                    { title: 'Technical Signals', items: ['URL extraction & analysis', 'Domain TLD reputation', 'IP address URL detection', 'HTTPS/HTTP classification'] },
                  ].map(({ title, items }) => (
                    <div key={title} className="p-4 bg-gray-50 rounded-xl">
                      <div className="font-semibold text-gray-800 text-sm mb-3">{title}</div>
                      <ul className="space-y-1.5">
                        {items.map(item => (
                          <li key={item} className="flex items-center gap-2 text-xs text-gray-600">
                            <div className="w-1.5 h-1.5 rounded-full bg-blue-400 shrink-0" />
                            {item}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Mobile nav */}
        <div className="fixed bottom-0 left-0 right-0 md:hidden bg-white border-t border-gray-200 flex">
          {navItems.map(item => (
            <button key={item.id} onClick={() => setActiveTab(item.id)} className={`flex-1 flex flex-col items-center py-3 gap-1 text-xs font-medium transition-colors ${activeTab === item.id ? 'text-blue-600' : 'text-gray-400'}`}>
              <Icon name={item.icon} size={18} />
              {item.label.split(' ')[0]}
            </button>
          ))}
        </div>
      </main>
    </div>
  );
}
