import pandas as pd
import numpy as np
import random
import re
import tldextract
import joblib
import time
import os
import warnings
from urllib.parse import urlparse, parse_qs
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import classification_report
from sklearn.model_selection import RandomizedSearchCV
from xgboost import XGBClassifier
from scipy.stats import randint, uniform

# Suppress warnings
warnings.filterwarnings('ignore', category=UserWarning)

# Constants
RANDOM_STATE = 42
np.random.seed(RANDOM_STATE)
random.seed(RANDOM_STATE)

PHISHING_KEYWORDS = [
    'login', 'secure', 'account', 'bank', 'paypal', 'verify', 'update', 'confirm',
    'password', 'signin', 'ebayisapi', 'webscr', 'click', 'limited', 'offer',
    'gift', 'free', 'bonus', 'claim', 'discount', 'urgent', 'support'
]

SHORTENED_DOMAINS = [
    'bit.ly', 'goo.gl', 'tinyurl', 't.co', 'is.gd', 'buff.ly', 'adf.ly', 
    'cutt.ly', 'shorte.st', 'bc.vc', 'adfoc.us', 'clk.sh'
]

SUSPICIOUS_TLDS = ['tk', 'xyz', 'icu', 'cf', 'ga', 'gq', 'ml', 'top', 'pw', 'cc']

# Create directories
os.makedirs("models", exist_ok=True)
os.makedirs("reports", exist_ok=True)

def extract_single_features(url):
    """Extract security features from a single URL"""
    try:
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        domain = parsed.netloc
        
        # Basic URL stats
        url_len = len(url)
        digit_count = sum(c.isdigit() for c in url)
        letter_count = sum(c.isalpha() for c in url)
        
        # Entropy calculation for randomness detection
        char_counts = np.array([url.count(c) for c in set(url)])
        probabilities = char_counts / max(url_len, 1)
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-9))
        
        # Create feature dictionary
        features = {
            'url_length': url_len,
            'domain_length': len(domain),
            'path_length': len(parsed.path),
            'query_length': len(parsed.query),
            'digit_ratio': digit_count / max(url_len, 1),
            'letter_ratio': letter_count / max(url_len, 1),
            'special_char_count': len(re.findall(r'[^\w\s]', url)),
            'entropy': entropy,
            'tld_length': len(ext.suffix),
            'tld_in_subdomain': int(ext.suffix in ext.subdomain),
            'subdomain_length': len(ext.subdomain),
            'subdomain_count': len(ext.subdomain.split('.')) if ext.subdomain else 0,
            'has_suspicious_tld': int(ext.suffix in SUSPICIOUS_TLDS),
            'has_https': int(parsed.scheme == 'https'),
            'has_http': int(parsed.scheme == 'http'),
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'num_slash': url.count('/'),
            'num_questionmark': url.count('?'),
            'num_equal': url.count('='),
            'num_at': url.count('@'),
            'num_and': url.count('&'),
            'num_percent': url.count('%'),
            'path_segments': parsed.path.count('/'),
            'query_params': len(parse_qs(parsed.query)),
            'ip_in_domain': int(bool(re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain))),
            'is_shortened': int(any(sd in domain for sd in SHORTENED_DOMAINS)),
            'has_phish_words': int(any(word in url.lower() for word in PHISHING_KEYWORDS)),
        }
        return features
    except Exception as e:
        print(f"⚠️ Error processing URL: {str(e)}")
        return None

def generate_random_string(length=8, character_set='abcdefghijklmnopqrstuvwxyz'):
    return ''.join(random.choices(character_set, k=length))

def generate_synthetic_urls(n=500, mal_ratio=0.5):
    """Generate realistic synthetic URLs"""
    BENIGN_PATTERNS = [
        ("https://{domain}/articles/{category}/{id}", 
         ["wikipedia.org", "nytimes.com", "medium.com"],
         {'category': ['tech', 'science', 'business'],
          'id': lambda: np.random.randint(10000)}),
         
        ("https://{domain}/users/{user_id}", 
         ["github.com", "gitlab.com"],
         {'user_id': lambda: generate_random_string(6)}),
         
        ("https://{domain}/search?q={query}", 
         ["google.com", "bing.com"],
         {'query': lambda: generate_random_string(8)})
    ]
    
    MALICIOUS_PATTERNS = [
        ("http://{domain}/login?session={session}", 
         ["paypal-update.com"],
         {'session': lambda: generate_random_string(32)}),
         
        ("https://{domain}/free/{item}", 
         ["free-gifts.ru", "vbucks-generator.cc"],
         {'item': ['ipad', 'iphone', 'giftcard']})
    ]
    
    urls, labels = [], []
    n_malicious = int(n * mal_ratio)
    
    # Generate benign URLs
    for _ in range(n - n_malicious):
        template, domains, params = random.choice(BENIGN_PATTERNS)
        domain = random.choice(domains)
        
        # Handle different param types
        format_params = {'domain': domain}
        for k, v in params.items():
            if callable(v):
                format_params[k] = v()
            elif isinstance(v, list):
                format_params[k] = random.choice(v)
            else:
                format_params[k] = v
                
        try:
            url = template.format(**format_params)
            urls.append(url)
            labels.append('benign')
        except:
            continue
    
    # Generate malicious URLs
    for _ in range(n_malicious):
        template, domains, params = random.choice(MALICIOUS_PATTERNS)
        
        # Select suspicious domain in 60% of cases
        if random.random() < 0.6:
            domain = f"{generate_random_string(8)}.{random.choice(SUSPICIOUS_TLDS)}"
        else:
            domain = random.choice(domains)
        
        format_params = {'domain': domain}
        for k, v in params.items():
            if callable(v):
                format_params[k] = v()
            elif isinstance(v, list):
                format_params[k] = random.choice(v)
            else:
                format_params[k] = v
                
        try:
            url = template.format(**format_params)
            urls.append(url)
            labels.append('malicious')
        except:
            continue
    
    return pd.DataFrame({"url": urls, "label": labels})

def extract_features_batch(urls):
    """Batch feature extraction"""
    features = []
    for url in urls:
        feat = extract_single_features(url)
        if feat:
            features.append(feat)
    return pd.DataFrame(features)

def train_model(X_train, y_train, X_val, y_val):
    """Train XGBoost model with hyperparameter tuning"""
    # Hyperparameter space
    param_dist = {
        'max_depth': randint(3, 10),
        'n_estimators': randint(100, 500),
        'learning_rate': uniform(0.01, 0.3),
        'subsample': uniform(0.6, 0.4),
        'colsample_bytree': uniform(0.6, 0.4),
        'gamma': uniform(0, 2),
        'reg_alpha': uniform(0, 1),
        'reg_lambda': uniform(0, 1)
    }
    
    # Base classifier without early stopping
    base_clf = XGBClassifier(
        random_state=RANDOM_STATE,
        eval_metric='logloss',
        use_label_encoder=False
    )
    
    print("Starting hyperparameter tuning...")
    search = RandomizedSearchCV(
        base_clf, 
        param_distributions=param_dist,
        n_iter=10,
        scoring='f1_weighted',
        cv=StratifiedKFold(n_splits=3),
        n_jobs=-1,
        random_state=RANDOM_STATE
    )
    
    # Fit without validation set
    search.fit(X_train, y_train)
    
    print("\nBest parameters found:\n", search.best_params_)
    
    print("\nTraining final model with early stopping...")
    # Create new classifier with best params and early stopping
    best_clf = XGBClassifier(
        **search.best_params_,
        random_state=RANDOM_STATE,
        eval_metric='logloss',
        use_label_encoder=False,
        early_stopping_rounds=10
    )
    
    # Train with validation set
    best_clf.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=False
    )
    
    # Set feature names
    best_clf.feature_names_ = list(X_train.columns)
    
    return best_clf, search.best_params_

def evaluate_model(model, X, y):
    """Evaluate model performance"""
    y_pred = model.predict(X)
    report = classification_report(y, y_pred, target_names=['benign', 'malicious'])
    print("\nClassification Report:\n", report)
    
    # Save report
    with open("reports/classification_report.txt", "w") as f:
        f.write(report)
    
    return report

def main():
    print("Generating synthetic URLs...")
    df = generate_synthetic_urls(1000, mal_ratio=0.5)
    print(f"Generated {len(df)} URLs")
    
    print("Extracting features...")
    X = extract_features_batch(df["url"])
    le = LabelEncoder()
    y = le.fit_transform(df["label"])
    
    # Remove failed extractions
    valid_idx = X.index
    X = X.loc[valid_idx]
    y = y[valid_idx]
    
    print(f"Final dataset size: {X.shape[0]} samples, {X.shape[1]} features")
    
    print("Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train, y_train, test_size=0.125, random_state=RANDOM_STATE, stratify=y_train
    )
    
    print(f"Train: {X_train.shape[0]}, Val: {X_val.shape[0]}, Test: {X_test.shape[0]}")
    
    print("Training model...")
    start_time = time.time()
    model, best_params = train_model(X_train, y_train, X_val, y_val)
    print(f"Training time: {time.time() - start_time:.2f}s")
    
    # Save artifacts
    joblib.dump(model, "models/xgb_url_classifier.pkl")
    joblib.dump(le, "models/label_encoder.pkl")
    
    # Save feature names
    with open("models/feature_names.txt", "w") as f:
        f.write("\n".join(X.columns))
    
    print("Model saved to models/xgb_url_classifier.pkl")
    print("Label encoder saved to models/label_encoder.pkl")
    print("Feature names saved to models/feature_names.txt")
    
    print("\nEvaluating on test set...")
    evaluate_model(model, X_test, y_test)

if __name__ == "__main__":
    main()