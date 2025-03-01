#!/usr/bin/env python3
"""
extractor.py - URL feature extraction for phishing detection
"""
import re
import tldextract
from urllib.parse import urlparse
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
import ipaddress

class URLFeatureExtractor:
    """Class to extract features from URLs for phishing detection"""
    
    def __init__(self):
        self.vectorizer = None
        self.suspicious_words = [
            'secure', 'account', 'webscr', 'login', 'ebayisapi', 
            'sign', 'banking', 'confirm', 'signin', 'bank', 'update', 
            'verify', 'customer', 'paypal', 'password', 'verification'
        ]
    
    def fit_vectorizer(self, urls):
        """Fit the token vectorizer on a list of URLs"""
        self.vectorizer = CountVectorizer(
            analyzer='char', 
            ngram_range=(3, 5),
            max_features=100
        )
        self.vectorizer.fit(urls)
        return self.vectorizer
    
    def extract_features(self, url):
        """Extract features from a single URL"""
        features = {}
        
        # Basic URL length features
        features['url_length'] = len(url)
        
        # TLD extraction
        extracted = tldextract.extract(url)
        features['domain_length'] = len(extracted.domain) if extracted.domain else 0
        features['subdomain_length'] = len(extracted.subdomain) if extracted.subdomain else 0
        features['tld_length'] = len(extracted.suffix) if extracted.suffix else 0
        
        # Count special characters
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_equal_signs'] = url.count('=')
        features['num_at_symbols'] = url.count('@')
        features['num_ampersands'] = url.count('&')
        features['num_exclamation'] = url.count('!')
        features['num_tildes'] = url.count('~')
        features['num_percent'] = url.count('%')
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_digits_in_domain'] = sum(c.isdigit() for c in extracted.domain) if extracted.domain else 0
        
        # Calculate digit ratio
        features['digit_ratio'] = features['num_digits'] / features['url_length'] if features['url_length'] > 0 else 0
        
        # Check for IP address
        try:
            ipaddress.ip_address(extracted.domain)
            features['has_ip'] = 1
        except ValueError:
            features['has_ip'] = 0
        
        # URL parsing
        parsed = urlparse(url)
        features['protocol'] = 1 if parsed.scheme == 'https' else 0  # 1 for https, 0 for http
        features['has_protocol'] = 1 if parsed.scheme else 0
        features['path_length'] = len(parsed.path)
        features['has_query'] = 1 if parsed.query else 0
        features['query_length'] = len(parsed.query)
        features['num_params'] = parsed.query.count('&') + 1 if parsed.query else 0
        features['has_fragment'] = 1 if parsed.fragment else 0
        features['fragment_length'] = len(parsed.fragment)
        
        # Check for common TLDs (more phishing happens on less common TLDs)
        common_tlds = ['.com', '.org', '.net', '.edu', '.gov']
        features['has_common_tld'] = 1 if any(extracted.suffix == tld[1:] for tld in common_tlds) else 0
        
        # Check for suspicious words
        features['has_suspicious_words'] = 1 if any(word in url.lower() for word in self.suspicious_words) else 0
        features['num_suspicious_words'] = sum(1 for word in self.suspicious_words if word in url.lower())
        
        # Special cases
        features['has_multiple_subdomains'] = 1 if extracted.subdomain.count('.') >= 1 else 0
        features['has_long_subdomain'] = 1 if len(extracted.subdomain) > 20 else 0
        
        # Check for abnormally long hostnames
        features['hostname_length'] = len(parsed.netloc)
        features['has_long_hostname'] = 1 if features['hostname_length'] > 30 else 0
        
        # Check for port in URL
        features['has_port'] = 1 if ':' in parsed.netloc and parsed.netloc.split(':')[-1].isdigit() else 0
        
        # Check for encoded characters
        features['has_encoded_chars'] = 1 if '%' in url else 0
        
        return features
    
    def extract_features_bulk(self, urls):
        """Extract features from a list of URLs"""
        features_list = []
        for url in urls:
            features_list.append(self.extract_features(url))
        
        # Convert to DataFrame
        features_df = pd.DataFrame(features_list)
        
        # Add n-gram features if vectorizer is trained
        if self.vectorizer is not None:
            ngram_features = self.vectorizer.transform(urls).toarray()
            ngram_df = pd.DataFrame(
                ngram_features, 
                columns=[f'ngram_{i}' for i in range(ngram_features.shape[1])]
            )
            # Combine base features with n-gram features
            features_df = pd.concat([features_df, ngram_df], axis=1)
        
        return features_df

if __name__ == "__main__":
    # Example usage
    extractor = URLFeatureExtractor()
    example_url = "https://www.example.com/path/to/page?param1=value1&param2=value2"
    features = extractor.extract_features(example_url)
    
    print("Example URL:", example_url)
    print("Extracted features:")
    for k, v in features.items():
        print(f"{k}: {v}")