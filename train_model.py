import os
import json
from datetime import datetime, timezone
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from app.services.ml_engine import extract_url_features, FEATURE_NAMES, FEATURE_LABELS

# Comprehensive representative URLs for training defensive phishing detection
LEGITIMATE_URLS = [
    "https://www.google.com",
    "https://www.google.com/search?q=cybersecurity+defense",
    "https://en.wikipedia.org/wiki/Computer_security",
    "https://en.wikipedia.org/wiki/Transport_Layer_Security",
    "https://github.com/explore",
    "https://github.com/torvalds/linux",
    "https://stackoverflow.com/questions/tagged/python",
    "https://stackoverflow.com/questions/tagged/flask",
    "https://www.amazon.com/gp/bestsellers",
    "https://www.amazon.com/gp/help/customer/display.html",
    "https://www.apple.com/macbook-pro",
    "https://support.apple.com/en-us/HT201222",
    "https://www.microsoft.com/en-us/windows",
    "https://docs.microsoft.com/en-us/azure/",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.netflix.com/browse",
    "https://www.linkedin.com/feed",
    "https://twitter.com/home",
    "https://www.reddit.com/r/netsec",
    "https://www.reddit.com/r/Python",
    "https://www.nytimes.com/section/technology",
    "https://www.bbc.com/news/technology",
    "https://www.cloudflare.com/learning/ssl/what-is-ssl/",
    "https://owasp.org/www-project-top-ten/",
    "https://pypi.org/project/scikit-learn/",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP",
    "https://www.paypal.com/us/home",
    "https://www.paypal.com/us/security",
    "https://www.chase.com/personal/banking",
    "https://www.bankofamerica.com/security-center/overview/",
    "https://www.wellsfargo.com/privacy-security/",
    "https://cve.mitre.org/cve/",
    "https://nvd.nist.gov/vuln/detail/CVE-2023-4863",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "https://flask.palletsprojects.com/en/latest/",
    "https://jinja.palletsprojects.com/en/latest/",
    "https://docs.pytest.org/en/latest/",
    "https://scikit-learn.org/stable/modules/ensemble.html",
    "https://numpy.org/doc/stable/",
    "https://www.w3.org/TR/CSP3/",
    "https://news.ycombinator.com/item?id=3849102",
    "https://medium.com/tag/cybersecurity",
    "https://arxiv.org/abs/2301.00001",
    "https://www.cnn.com/world",
    "https://www.theverge.com/tech",
    "https://www.techcrunch.com/startups",
    "https://gitlab.com/explore",
    "https://bitbucket.org/product",
    "https://www.spotify.com/us/premium",
    "https://zoom.us/pricing"
]

PHISHING_URLS = [
    "http://192.168.1.100/paypal/login.php?cmd=verify",
    "http://10.0.0.15/bankofamerica/signin.htm",
    "http://172.16.254.1/auth/chase-online.html",
    "http://paypal.com.account-verify.xyz/login?token=urgent",
    "http://chase.com.security-alert-update.club/auth",
    "https://appleid.apple.com.manage-security.top/verify",
    "http://netflix.com.billing-recovery-notice.live/restore",
    "http://amazon.com.customer-order-tracking.work/confirm",
    "http://microsoft.com.office365-passcode-reset.link/login",
    "http://user:pass@www.secure-paypal-login.com/webscr",
    "http://admin@login-bankofamerica.tk/verification",
    "http://bit.ly/3xPaypalUrgentUpdate",
    "http://tinyurl.com/apple-id-verify-now",
    "http://is.gd/chase_online_secure",
    "http://paypa1-security-check.com/update-account",
    "http://micros0ft-support-desk.com/antivirus/alert",
    "http://faceb00k-password-reset.info/checkpoint",
    "http://goog1e-drive-file-share.com/view/document",
    "http://wellsfarg0-fraud-alert.cc/dispute",
    "http://www.secure-banking-verification-center-update-auth.com/portal/login/step1",
    "http://account-recovery-immediate-action-required-now.top/auth/verify",
    "http://wallet-connect-crypto-airdrop-claim-now.xyz/metamask",
    "http://irs-tax-refund-claim-deposit-direct.buzz/form",
    "http://dhl-express-package-delivery-redirection.rest/tracking",
    "http://usps-address-confirmation-package-alert.top/redeliver",
    "http://ups-shipping-reschedule-fee-payment.work/fee",
    "http://fedex-parcel-hold-notice-confirm.bid/release",
    "http://steam-community-free-skin-gift.win/trade",
    "http://discord-nitro-free-3months-generator.cf/claim",
    "http://instagram-verified-badge-apply-free.ml/badge",
    "http://www.netflix-account-suspended-reactivate.gq/login",
    "http://secure-chase-portal.com?login=1&user=client&ref=email&auth=38190",
    "http://bank-of-america-safe-passcode.info/sign-in.php",
    "http://citi-card-fraud-prevention-alert.club/case-review",
    "http://coinbase-account-locked-security-auth.top/signin",
    "http://binance-kyc-verification-urgent-action.live/verify",
    "http://metamask-seed-phrase-validation.stream/restore",
    "http://kraken-exchange-two-factor-reset.download/auth",
    "http://adobe-pdf-shared-document-view-online.club/doc",
    "http://dropbox-file-transfer-download-invoice.xyz/inv",
    "http://docusign-electronic-signature-review.work/sign",
    "http://login.live.com.user-verification-step.info/login",
    "http://yahoo-mail-storage-quota-full-upgrade.top/upgrade",
    "http://outlook-web-app-security-patch-login.bid/owa",
    "http://secure-webmail-corporate-access.link/webmail",
    "http://whatsapp-web-chat-backup-restore.cc/auth",
    "http://telegram-premium-gift-code-free.win/claim",
    "http://spotify-family-plan-invitation-accept.rest/invite",
    "http://hulu-subscription-billing-update-now.buzz/card",
    "http://disneyplus-membership-renewal-payment.top/pay"
]

def train_and_evaluate():
    print("=" * 60)
    print("Starting ML Model Training for CyberSec Phishing Detection")
    print("=" * 60)

    X_vectors = []
    y_labels = []

    # Legitimate (y = 0)
    for url in LEGITIMATE_URLS:
        _, vec = extract_url_features(url)
        X_vectors.append(vec)
        y_labels.append(0)

    # Phishing (y = 1)
    for url in PHISHING_URLS:
        _, vec = extract_url_features(url)
        X_vectors.append(vec)
        y_labels.append(1)

    X = np.array(X_vectors)
    y = np.array(y_labels)

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    # Random Forest Classifier
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=2,
        random_state=42
    )
    rf.fit(X_train, y_train)

    # Predict on test set
    y_pred = rf.predict(X_test)
    y_proba = rf.predict_proba(X_test)[:, 1]

    # Metrics
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()

    print(f"Dataset Size: {len(X)} samples ({len(X_train)} train, {len(X_test)} test)")
    print(f"Model Accuracy:  {acc * 100:.2f}%")
    print(f"Model Precision: {prec * 100:.2f}%")
    print(f"Model Recall:    {rec * 100:.2f}%")
    print(f"Model F1-Score:  {f1 * 100:.2f}%")
    print(f"Confusion Matrix: TN={cm[0][0]}, FP={cm[0][1]}, FN={cm[1][0]}, TP={cm[1][1]}")

    # Ranked Feature Importances
    importances = rf.feature_importances_
    feat_list = []
    for i, name in enumerate(FEATURE_NAMES):
        feat_list.append({
            'name': name,
            'label': FEATURE_LABELS[name],
            'importance': round(float(importances[i]) * 100, 2)
        })
    feat_list.sort(key=lambda x: x['importance'], reverse=True)

    print("\nTop 5 Feature Importances:")
    for f in feat_list[:5]:
        print(f"  - {f['label']} ({f['name']}): {f['importance']}%")

    # Output paths
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, 'data')
    os.makedirs(data_dir, exist_ok=True)

    model_path = os.path.join(data_dir, 'phishing_model.joblib')
    metrics_path = os.path.join(data_dir, 'model_metrics.json')

    # Save model bundle
    bundle = {
        'model': rf,
        'feature_importances': importances.tolist(),
        'feature_names': FEATURE_NAMES
    }
    joblib.dump(bundle, model_path)
    print(f"\nModel saved successfully -> {model_path}")

    # Save metrics JSON for Model Info page
    metrics_data = {
        'model_name': 'Random Forest URL Phishing Classifier',
        'algorithm': 'RandomForestClassifier (n_estimators=100, max_depth=10)',
        'trained_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        'total_samples': len(X),
        'train_samples': len(X_train),
        'test_samples': len(X_test),
        'accuracy': round(acc * 100, 2),
        'precision': round(prec * 100, 2),
        'recall': round(rec * 100, 2),
        'f1_score': round(f1 * 100, 2),
        'confusion_matrix': {
            'true_negative': cm[0][0],
            'false_positive': cm[0][1],
            'false_negative': cm[1][0],
            'true_positive': cm[1][1],
            'matrix': cm
        },
        'feature_importances': feat_list
    }

    with open(metrics_path, 'w', encoding='utf-8') as f:
        json.dump(metrics_data, f, indent=2)
    print(f"Metrics saved successfully -> {metrics_path}")

    return metrics_data

if __name__ == '__main__':
    train_and_evaluate()
