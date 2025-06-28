from flask import Flask, request, render_template, jsonify
import joblib
import pandas as pd
import numpy as np
from urllib.parse import urlparse, parse_qs
import re
import tldextract
from datetime import datetime
import os

app = Flask(__name__)

# Security constants
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

# Load models safely
def load_models():
    try:
        model = joblib.load('models/xgb_url_classifier.pkl')
        le = joblib.load('models/label_encoder.pkl')
        
        # Load feature names from file
        with open('models/feature_names.txt', 'r') as f:
            required_features = [line.strip() for line in f]
            
        print("✅ Models and features loaded successfully")
        return model, le, required_features
    except Exception as e:
        print(f"❌ Model loading error: {str(e)}")
        return None, None, []

model, le, required_features = load_models()

def extract_features(url):
    """Extract security features from URL"""
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
        
        return pd.DataFrame([features])
    
    except Exception as e:
        app.logger.error(f"Feature extraction error: {str(e)}")
        return pd.DataFrame()

@app.route('/')
def home():
    return render_template('index.html', domain_display="")

@app.route('/predict', methods=['POST'])
def predict():
    # Check if models are loaded
    if model is None or le is None:
        return render_template('index.html', error="Model not loaded. Run training first.")
        
    try:
        url = request.form.get('url', '').strip()
        if not url:
            return render_template('index.html', error="Please enter a URL")
        
        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Extract features
        features_df = extract_features(url)
        if features_df.empty:
            return render_template('index.html', error="Feature extraction failed")
            
        # Align features with model requirements
        features_df = features_df.reindex(columns=required_features, fill_value=0)
        
        # Prediction
        proba = model.predict_proba(features_df)[0]
        pred = model.predict(features_df)[0]
        label = le.inverse_transform([pred])[0]
        threat_score = int(proba[1] * 100)  # Malicious probability
        
        # Set UI elements
        if label == 'benign':
            result_class = 'border-green-300'
            result_icon = 'fa-check-circle text-green-600'
            result_title = 'SAFE URL'
            result_description = 'This URL appears to be safe based on our analysis.'
            score_bar_class = 'bg-green-500'
        else:
            result_class = 'border-red-300'
            result_icon = 'fa-exclamation-triangle text-red-600'
            result_title = 'MALICIOUS URL'
            result_description = 'This URL is potentially malicious. Do not proceed!'
            score_bar_class = 'bg-red-500'
        
        # Generate warnings
        warnings = []
        features_dict = features_df.iloc[0].to_dict()
        
        if features_dict['has_phish_words']:
            warnings.append("Phishing keywords detected in URL")
        if features_dict['is_shortened']:
            warnings.append("URL is shortened (may hide true destination)")
        if features_dict['has_suspicious_tld']:
            warnings.append("Suspicious top-level domain detected")
        if features_dict['ip_in_domain']:
            warnings.append("IP address used in domain name")
            
        # Format features for display
        formatted_features = {}
        for key, value in features_dict.items():
            if isinstance(value, float):
                formatted_features[key] = f"{value:.4f}"
            else:
                formatted_features[key] = str(value)
                
        return render_template(
            'index.html', 
            result=True,
            result_class=result_class,
            result_icon=result_icon,
            result_title=result_title,
            result_description=result_description,
            threat_score=threat_score,
            warnings=warnings,
            features=formatted_features,
            domain_display=url,
            score_bar_class=score_bar_class
        )
        
    except Exception as e:
        app.logger.error(f"Prediction error: {str(e)}")
        return render_template('index.html', error="An error occurred during analysis")

@app.route('/health')
def health():
    return jsonify({
        'status': 'ok' if model else 'error',
        'model_loaded': bool(model),
        'features': len(required_features),
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    # Create models directory if missing
    os.makedirs('models', exist_ok=True)
    app.run(host='0.0.0.0', port=5000, debug=True)