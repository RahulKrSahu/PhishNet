#!/usr/bin/env python3
"""
preprocess.py - Script to preprocess and combine datasets
"""
import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from tqdm import tqdm
import re

def process_uci_dataset():
    """Process UCI dataset from ARFF to CSV format"""
    print("Processing UCI dataset...")
    
    if not os.path.exists('data/raw/uci_phishing.arff'):
        print("UCI dataset file not found. Please run download.py first.")
        return None
    
    # Read ARFF file
    with open('data/raw/uci_phishing.arff', 'r') as f:
        content = f.readlines()
    
    # Find where data begins
    data_index = 0
    for i, line in enumerate(content):
        if '@data' in line:
            data_index = i + 1
            break
    
    # Extract data
    data_lines = content[data_index:]
    rows = []
    
    for line in data_lines:
        line = line.strip()
        if line:
            values = line.split(',')
            row = {}
            for i, val in enumerate(values[:-1]):
                row[f'feature_{i+1}'] = val
            # Last value is the class
            row['label'] = 1 if values[-1] == '-1' else 0  # -1 is phishing, 1 is legitimate in UCI
            rows.append(row)
    
    df = pd.DataFrame(rows)
    df.to_csv('data/processed/uci_phishing.csv', index=False)
    print(f"UCI dataset processed: {len(df)} records")
    return df

def combine_phishing_legitimate_datasets():
    """Combine all datasets into a single training set"""
    print("Combining phishing and legitimate datasets...")
    
    datasets = []
    
    # PhishTank
    if os.path.exists('data/raw/phishtank_simplified.csv'):
        phishtank_df = pd.read_csv('data/raw/phishtank_simplified.csv')
        print(f"Found PhishTank data: {len(phishtank_df)} records")
        datasets.append(phishtank_df)
    
    # OpenPhish
    if os.path.exists('data/raw/openphish_simplified.csv'):
        openphish_df = pd.read_csv('data/raw/openphish_simplified.csv')
        print(f"Found OpenPhish data: {len(openphish_df)} records")
        datasets.append(openphish_df)
    
    # Alexa (legitimate)
    if os.path.exists('data/raw/alexa_simplified.csv'):
        alexa_df = pd.read_csv('data/raw/alexa_simplified.csv')
        print(f"Found Alexa data: {len(alexa_df)} records")
        datasets.append(alexa_df)
    
    if not datasets:
        print("No datasets found. Please run download.py first.")
        return
    
    # Combine all datasets
    combined_df = pd.concat(datasets, ignore_index=True)
    
    # Remove duplicates
    combined_df.drop_duplicates(subset=['url'], inplace=True)
    
    # Count final dataset balance
    phishing_count = combined_df[combined_df['label'] == 1].shape[0]
    legitimate_count = combined_df[combined_df['label'] == 0].shape[0]
    
    print(f"Combined dataset: {len(combined_df)} URLs")
    print(f"  - Phishing: {phishing_count} ({phishing_count/len(combined_df)*100:.1f}%)")
    print(f"  - Legitimate: {legitimate_count} ({legitimate_count/len(combined_df)*100:.1f}%)")
    
    # Split into train, validation and test sets
    train_df, temp_df = train_test_split(combined_df, test_size=0.3, stratify=combined_df['label'], random_state=42)
    val_df, test_df = train_test_split(temp_df, test_size=0.5, stratify=temp_df['label'], random_state=42)
    
    # Save datasets
    train_df.to_csv('data/processed/train.csv', index=False)
    val_df.to_csv('data/processed/validation.csv', index=False)
    test_df.to_csv('data/processed/test.csv', index=False)
    combined_df.to_csv('data/processed/combined.csv', index=False)
    
    print(f"Training set: {len(train_df)} URLs")
    print(f"Validation set: {len(val_df)} URLs")
    print(f"Test set: {len(test_df)} URLs")
    print("Datasets saved to data/processed/")
    
    return combined_df

def clean_urls(df):
    """Perform basic cleaning on URLs"""
    print("Cleaning URLs...")
    
    # Remove URLs that are too short
    df = df[df['url'].str.len() > 10].copy()
    
    # Ensure URLs start with http:// or https://
    def add_scheme(url):
        if not url.startswith('http://') and not url.startswith('https://'):
            return 'http://' + url
        return url
    
    df['url'] = df['url'].apply(add_scheme)
    
    # Remove malformed URLs
    def is_valid_url(url):
        # Simple regex to check URL format
        pattern = re.compile(r'^(http|https)://[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}(/.*)?$')
        return bool(pattern.match(url))
    
    df = df[df['url'].apply(is_valid_url)]
    
    print(f"After cleaning: {len(df)} URLs")
    return df

if __name__ == "__main__":
    print("Starting data preprocessing...")
    
    # Process UCI dataset
    uci_df = process_uci_dataset()
    
    # Combine and clean other datasets
    combined_df = combine_phishing_legitimate_datasets()
    
    if combined_df is not None:
        cleaned_df = clean_urls(combined_df)
        cleaned_df.to_csv('data/processed/cleaned_combined.csv', index=False)
        print("Preprocessing complete!")
    else:
        print("Preprocessing failed - no datasets found.")