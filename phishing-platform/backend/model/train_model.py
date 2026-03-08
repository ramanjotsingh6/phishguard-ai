"""
Phishing Detection Model Trainer
Trains a TF-IDF + Logistic Regression / Random Forest ensemble
"""

import os
import pickle
import json
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
import re
import warnings
warnings.filterwarnings('ignore')

# ─── SYNTHETIC DATASET ────────────────────────────────────────────────────────

PHISHING_EMAILS = [
    "URGENT: Your account has been compromised. Click here immediately to verify your identity and prevent suspension: http://secure-bank-verify.xyz/login",
    "Dear valued customer, We have detected suspicious activity on your PayPal account. Your account will be suspended in 24 hours unless you verify: http://paypal-secure-login.ru/verify",
    "Congratulations! You have been selected as a winner of $1,000,000 lottery. To claim your prize, send your bank details to claims@lottery-winner.com",
    "ALERT: Your Apple ID has been locked due to too many failed login attempts. Restore access now: http://apple-id-restore.tk/unlock",
    "Your Netflix subscription is about to expire. Update your payment method now to continue: http://netflix-billing-update.xyz",
    "IRS Notice: You owe $3,200 in back taxes. Pay immediately to avoid arrest. Call 1-800-TAX-SCAM or visit http://irs-payment-center.ru",
    "Your package from FedEx could not be delivered. Confirm your address and pay $2.99 fee: http://fedex-delivery-confirm.xyz/track",
    "FINAL WARNING: Your email account will be deleted in 48 hours. Click to verify: http://mail-verify-account.tk/confirm",
    "Dear user, Your password will expire today. Update now: http://microsoft-password-reset.ru/update?user=victim",
    "You have received a secure document from DocuSign. Review and sign immediately: http://docusign-secure.xyz/document?id=FAKE123",
    "SECURITY ALERT: Someone tried to login to your Gmail account from Russia. Secure your account: http://gmail-secure-verify.tk/protect",
    "Congratulations! Your Amazon account has been selected for a free gift. Claim here: http://amazon-rewards-claim.xyz/gift",
    "Your bank account has been temporarily restricted. Verify your information to restore access: http://bankofamerica-verify.ru/secure",
    "URGENT ACTION REQUIRED: Your Social Security Number has been suspended. Call immediately: 1-888-FAKE-GOV",
    "You have been approved for a $50,000 personal loan. Provide your bank details to receive funds: loans@quickcash-instant.com",
    "Your Dropbox storage is full. Your files will be deleted in 24 hours. Upgrade: http://dropbox-storage-upgrade.xyz",
    "NOTICE: Your computer has been infected with virus. Call Microsoft Support immediately: 1-800-VIRUS-FAKE",
    "Dear Customer, Please update your Chase bank account information to avoid suspension: http://chase-secure-update.ru/login",
    "You have a pending Bitcoin reward of 0.5 BTC. Complete verification to claim: http://bitcoin-rewards-verify.xyz",
    "IMPORTANT: Your health insurance will be cancelled unless you update your details: http://healthcare-update-required.tk",
    "Urgent: Wire transfer of $25,000 awaiting your authorization. Login to confirm: http://wire-transfer-confirm.xyz/auth",
    "Your WhatsApp account has been compromised. Scan QR code to secure: http://whatsapp-secure-scan.ru",
    "Congratulations winner! You've won an iPhone 15 Pro. Claim your prize now: http://apple-prize-winner.xyz/claim",
    "ALERT: Unusual sign-in activity detected on your Microsoft account. Verify: http://microsoft-account-verify.tk",
    "Your DHL parcel is on hold. Pay customs fee of $4.50 to release: http://dhl-customs-payment.xyz",
    "Dear Account Holder, Your account verification is required immediately or your account will be closed within 24 hours.",
    "FINAL NOTICE: You owe outstanding balance. Failure to pay will result in legal action. Click here to pay now.",
    "We detected a login attempt from an unrecognized device. If this wasn't you, secure your account immediately by clicking this link.",
    "Your subscription has been charged $299. If you did not authorize this, click here to cancel and get refund immediately.",
    "SECURITY BREACH: Your personal data may have been exposed. Click here to protect your identity now.",
    "You have won a $500 gift card! Claim your reward by entering your credit card details for shipping.",
    "ACCOUNT SUSPENDED: Unusual activity detected. Provide identification to restore access immediately.",
    "Tax refund of $1,847 is pending your claim. Submit your information to IRS portal within 48 hours.",
    "Your password has been stolen! Change it immediately using this secure link before someone accesses your accounts.",
    "URGENT: Your domain is expiring in 24 hours. Renew immediately to avoid losing your website: http://domain-renew-urgent.xyz",
    "Dear valued employee, HR requires immediate verification of your direct deposit information. Update here.",
    "CRYPTO ALERT: Your account shows unauthorized trading activity. Secure assets now at: http://crypto-exchange-secure.tk",
    "Warning: Your email has been blacklisted for spam. Verify identity to continue using email services.",
    "PRIZE NOTIFICATION: Your phone number won $750,000 in international sweepstakes. Claim now!",
    "Your Amazon order has been cancelled. Suspicious activity detected on order #AMZ-FAKE. Verify account.",
    "Limited time offer: Earn $500/hour working from home. No experience needed. Apply: http://easy-money-jobs.xyz",
    "URGENT: Complete your KYC verification or your bank account will be frozen within 2 hours.",
    "Your Netflix account was accessed from Romania. Change password immediately: http://netflix-security-alert.ru",
    "Congratulations! You've been pre-approved for a credit card with $10,000 limit. Accept offer now.",
    "SYSTEM ALERT: Your device has critical security vulnerabilities. Download security patch immediately.",
    "Dear customer, your account password will expire in 2 hours. Reset now to maintain access.",
    "You have been selected for an exclusive investment opportunity with guaranteed 500% returns.",
    "FINAL WARNING: Pay your outstanding invoice of $2,340 or face immediate legal proceedings.",
    "Your iCloud storage is 99% full. Your photos will be lost unless you upgrade NOW.",
    "PHISHING TEST: Employees who click this link will be reported to management for security training.",
]

LEGITIMATE_EMAILS = [
    "Hi John, I wanted to follow up on our meeting from last Tuesday. Can we schedule a call this week to discuss the project timeline? Best regards, Sarah",
    "Dear Mr. Johnson, Thank you for your recent purchase. Your order #12345 has been shipped and will arrive in 3-5 business days. Order details: 2x Blue T-Shirt, Size M.",
    "Hello team, The quarterly review meeting is scheduled for Friday at 2 PM in Conference Room B. Please bring your department reports. Thanks, Management",
    "Hi! Just wanted to check in and see how you're doing. Haven't heard from you in a while. Hope everything is going well with the new job!",
    "Dear valued customer, Your monthly account statement for October 2024 is now available. Log in to your account at our official website to view your statement.",
    "Thank you for contacting our support team. We've received your ticket #58901 regarding your billing inquiry. Our team will respond within 24 hours.",
    "Hi Alex, Great news! The code review is complete and your pull request has been approved. Please merge when ready. Let me know if you need anything else.",
    "Newsletter: This month's top articles include: 10 Tips for Better Productivity, The Future of Remote Work, and Understanding Cloud Security.",
    "Dear subscriber, Your annual subscription to Premium has been renewed successfully. Next billing date: December 1, 2025. Amount: $9.99/month.",
    "Hi Mom, Just landed in Chicago. The flight was smooth. Will call you tonight when I get to the hotel. Love you!",
    "Meeting reminder: You have a dentist appointment tomorrow at 3:30 PM at Downtown Dental Clinic. Please call if you need to reschedule.",
    "Hello Dr. Smith, I'm writing to confirm my appointment on November 15th at 10:00 AM. Please let me know if this time still works for you.",
    "Your GitHub repository 'awesome-project' has 3 new pull requests waiting for review. Visit github.com to review them.",
    "Team update: Sprint 14 has been completed successfully. Velocity increased by 15%. Next sprint planning session is on Monday.",
    "Hi there! Your food delivery from Italian Garden is on its way. Estimated delivery time: 25-30 minutes. Track your order in the app.",
    "Dear John, We are pleased to inform you that your loan application has been reviewed. Please visit your nearest branch with required documents.",
    "Your electricity bill for October 2024 is $127.45. Payment due date: November 15. You can pay online at our website or at any payment center.",
    "Hi, This is a reminder that your library books are due in 3 days. Please return or renew them to avoid late fees.",
    "Good morning! Your daily weather forecast: Sunny, high of 72°F. Perfect day for outdoor activities. Check the full forecast on our app.",
    "Hello team, Please note that the office will be closed on Thursday for the holiday. Regular hours resume Friday morning.",
    "Thank you for attending the webinar on cybersecurity best practices. Here's a summary of key points discussed and resources mentioned.",
    "Hi, Your Zoom meeting starts in 15 minutes. Join link: https://zoom.us/j/LEGITIMATE_ID Meeting topic: Weekly Team Standup",
    "Dear Parent, This is a reminder about the school's parent-teacher conference scheduled for next Tuesday from 4-8 PM.",
    "Your flight confirmation: AA1234, New York (JFK) to Los Angeles (LAX), November 10, 2024, 8:30 AM. Gate information will be available 2 hours before departure.",
    "Hello, The package you ordered has been delivered to your front door. It was signed for by a resident at 2:45 PM today.",
    "Good afternoon, I hope this email finds you well. I'm reaching out regarding the job posting for Software Engineer. I'd like to apply for this position.",
    "Dear Student, Your assignment has been graded. You received 87/100 on your Python programming assignment. Feedback has been added to the portal.",
    "Monthly digest: Here's a roundup of new features added to the platform this month, including improved search, dark mode, and export functionality.",
    "Hi, Just a heads up that I'll be out of office from Dec 20-Jan 2. For urgent matters, please contact my colleague Michael at michael@company.com",
    "Your bank statement: Account ending in 4521. Opening balance: $2,340.50. Closing balance: $1,892.30. 12 transactions this month.",
    "Congratulations! Your professional certification exam results are in. You passed with a score of 92%. Your certificate will be mailed within 10 business days.",
    "Hello, This is a confirmation that your restaurant reservation at The Grand Bistro has been confirmed for Saturday, November 12 at 7:30 PM for 4 guests.",
    "Hi team, Attached is the Q3 financial summary. Revenue up 23% year-over-year. Expenses slightly above forecast. Full report in SharePoint.",
    "Dear User, Your password was successfully changed. If you did not make this change, please contact support immediately through our official website.",
    "Good news! Your insurance claim #CLM-98765 has been approved. Payment of $1,234 will be deposited to your account within 5 business days.",
    "Hi, I wanted to share this interesting article about machine learning trends in 2025. Thought you might find it useful for your research.",
    "Your subscription renewal: Adobe Creative Cloud - Annual Plan. Renewal date: January 15, 2025. Amount: $599.88/year. Manage at adobe.com/account",
    "Hello, The IT department will perform scheduled maintenance on Sunday from 2-6 AM. Services may be temporarily unavailable during this window.",
    "Dear Customer, Thank you for your feedback. We've reviewed your complaint and have issued a credit of $25 to your account as an apology.",
    "Hi Sarah, Looking forward to the team lunch tomorrow! Should we meet at the restaurant at noon or carpool from the office? Let me know.",
    "Reminder: Your vehicle registration expires next month. Visit the DMV website or any licensed office to renew.",
    "Hi, Thank you for signing up for our newsletter. You'll receive weekly updates about industry news, tips, and our latest products.",
    "Performance review scheduled: Your annual performance review is set for December 5th at 2 PM with your manager, David Chen.",
    "Your Spotify Premium receipt: $9.99 charged to Visa ending 4521 on November 1, 2024. Family Plan - 6 members. Manage at spotify.com/account",
    "Hello, We noticed you haven't logged in recently. Here are some new features you might have missed. Visit our platform to explore.",
    "Hi, The project proposal you submitted has been reviewed by the committee and approved with minor revisions. Please see attached feedback.",
    "Dear valued customer, We are updating our privacy policy effective January 1, 2025. Key changes include improved data transparency.",
    "Good morning! Your daily briefing: 3 meetings today, 12 unread emails, 2 tasks due today. Have a productive day!",
    "Invitation: You're invited to the annual company holiday party on December 19th at 6 PM at The Rooftop Venue. RSVP by December 10th.",
    "Hi, This is your weekly backup report. All systems backed up successfully. Total data: 2.3TB. No errors detected. Next backup: Sunday 2 AM.",
]

def extract_features_text(email_text):
    """Extract additional features from email text."""
    features = {}
    text_lower = email_text.lower()
    
    # Urgency indicators
    urgency_words = ['urgent', 'immediately', 'asap', 'now', 'expire', 'suspended',
                     'warning', 'alert', 'final notice', 'act now', 'limited time',
                     'hours', 'deadline', 'last chance']
    features['urgency_score'] = sum(1 for w in urgency_words if w in text_lower)
    
    # Suspicious patterns
    features['has_url'] = 1 if re.search(r'http[s]?://', email_text) else 0
    features['suspicious_tld'] = 1 if re.search(r'\.(xyz|tk|ru|top|club|info|biz|ml)', text_lower) else 0
    features['has_ip_url'] = 1 if re.search(r'http://\d+\.\d+\.\d+\.\d+', email_text) else 0
    features['exclamation_count'] = email_text.count('!')
    features['all_caps_words'] = len(re.findall(r'\b[A-Z]{3,}\b', email_text))
    
    # Financial keywords
    financial_words = ['win', 'won', 'prize', 'reward', 'free', 'gift', 'money',
                       'cash', 'lottery', 'million', 'billion', 'investment', 'profit']
    features['financial_score'] = sum(1 for w in financial_words if w in text_lower)
    
    # Threat indicators
    threat_words = ['arrest', 'legal', 'penalty', 'court', 'irs', 'police',
                    'criminal', 'jail', 'fine', 'seized', 'block', 'locked']
    features['threat_score'] = sum(1 for w in threat_words if w in text_lower)
    
    # Social engineering
    social_words = ['verify', 'confirm', 'validate', 'authenticate', 'secure',
                    'protect', 'update information', 'account details']
    features['social_eng_score'] = sum(1 for w in social_words if w in text_lower)
    
    return features


def build_dataset():
    """Build training dataset."""
    texts = PHISHING_EMAILS + LEGITIMATE_EMAILS
    labels = [1] * len(PHISHING_EMAILS) + [0] * len(LEGITIMATE_EMAILS)
    return texts, labels


def train_model():
    """Train and save the phishing detection model."""
    print("=" * 60)
    print("  PHISHING DETECTION MODEL TRAINER")
    print("=" * 60)
    
    texts, labels = build_dataset()
    print(f"\n✓ Dataset loaded: {len(texts)} samples")
    print(f"  - Phishing: {sum(labels)} ({sum(labels)/len(labels)*100:.1f}%)")
    print(f"  - Legitimate: {len(labels)-sum(labels)} ({(len(labels)-sum(labels))/len(labels)*100:.1f}%)")
    
    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )
    
    # Build pipeline
    tfidf = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 3),
        analyzer='word',
        stop_words='english',
        min_df=1,
        sublinear_tf=True
    )
    
    lr = LogisticRegression(C=1.0, max_iter=1000, random_state=42)
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    
    # Voting ensemble
    ensemble = VotingClassifier(
        estimators=[('lr', lr), ('rf', rf)],
        voting='soft'
    )
    
    pipeline = Pipeline([
        ('tfidf', tfidf),
        ('clf', ensemble)
    ])
    
    print("\n⚙  Training model...")
    pipeline.fit(X_train, y_train)
    
    # Evaluate
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    print("\n─── EVALUATION METRICS ─────────────────────────────")
    print(f"  Accuracy:  {acc:.4f} ({acc*100:.2f}%)")
    print(f"  Precision: {prec:.4f}")
    print(f"  Recall:    {rec:.4f}")
    print(f"  F1 Score:  {f1:.4f}")
    
    # Cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(pipeline, texts, labels, cv=cv, scoring='accuracy')
    print(f"\n  5-Fold CV Accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    print(f"  CV Scores: {[f'{s:.3f}' for s in cv_scores]}")
    
    print("\n─── CONFUSION MATRIX ────────────────────────────────")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"  FN={cm[1][0]}  TP={cm[1][1]}")
    
    print("\n─── CLASSIFICATION REPORT ───────────────────────────")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    
    # Save model and metrics
    os.makedirs('/home/claude/phishing-platform/backend/model', exist_ok=True)
    
    model_path = '/home/claude/phishing-platform/backend/model/phishing_model.pkl'
    with open(model_path, 'wb') as f:
        pickle.dump(pipeline, f)
    
    metrics = {
        'accuracy': float(acc),
        'precision': float(prec),
        'recall': float(rec),
        'f1_score': float(f1),
        'cv_mean': float(cv_scores.mean()),
        'cv_std': float(cv_scores.std()),
        'training_samples': len(X_train),
        'test_samples': len(X_test),
        'total_samples': len(texts),
        'confusion_matrix': cm.tolist()
    }
    
    metrics_path = '/home/claude/phishing-platform/backend/model/metrics.json'
    with open(metrics_path, 'w') as f:
        json.dump(metrics, f, indent=2)
    
    print(f"\n✓ Model saved to: {model_path}")
    print(f"✓ Metrics saved to: {metrics_path}")
    print("=" * 60)
    
    return pipeline, metrics


if __name__ == '__main__':
    train_model()
