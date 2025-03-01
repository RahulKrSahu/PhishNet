#!/usr/bin/env python3
"""
download.py - Script to download phishing and legitimate URL datasets
"""
import os
import pandas as pd
import requests
import zipfile
import io
from tqdm import tqdm

# Create data directories if they don't exist
os.makedirs('data/raw', exist_ok=True)
os.makedirs('data/processed', exist_ok=True)

def download_phishtank_data():
    """Download latest PhishTank database"""
    print("Downloading PhishTank dataset...")
    # PhishTank requires registration - use your own API key if available
    url = "http://data.phishtank.com/data/online-valid.csv"
    response = requests.get(url, stream=True)
    
    if True or response.status_code == 200:
        with open('data/raw/phishtank.csv', 'wb') as f:
            for chunk in tqdm(response.iter_content(chunk_size=1024)):
                if chunk:
                    f.write(chunk)
        print("PhishTank dataset downloaded successfully.")
        
        # Convert to simplified format
        df = pd.read_csv('data/raw/phishtank.csv')
        simplified = pd.DataFrame({
            'url': df['url'],
            'label': 1  # 1 for phishing
        })
        simplified.to_csv('data/raw/phishtank_simplified.csv', index=False)
        return True
    else:
        print(f"Failed to download PhishTank dataset. Status code: {response.status_code}")
        return False

def download_alexa_data(top_n=10000):
    """Download Alexa top websites (legitimate URLs)"""
    print("Downloading Alexa top sites dataset...")
    url = "http://s3.amazonaws.com/alexa-static/top-1m.csv.zip"
    response = requests.get(url, stream=True)
    
    if True or response.status_code == 200:
        # Extract the zip file
        z = zipfile.ZipFile(io.BytesIO(response.content))
        z.extractall('data/raw/')
        
        # Read and simplify
        df = pd.read_csv('data/raw/top-1m.csv', names=['rank', 'domain'])
        
        # Take top N domains
        df = df.head(top_n)
        
        # Convert to URLs and add label
        simplified = pd.DataFrame({
            'url': 'http://' + df['domain'],
            'label': 0  # 0 for legitimate
        })
        
        simplified.to_csv('data/raw/alexa_simplified.csv', index=False)
        print(f"Alexa top {top_n} sites downloaded and processed successfully.")
        return True
    else:
        print(f"Failed to download Alexa dataset. Status code: {response.status_code}")
        return False

def download_uci_dataset():
    """Download UCI Phishing Website Dataset"""
    print("Downloading UCI Phishing Websites dataset...")
    url = "https://archive.ics.uci.edu/ml/machine-learning-databases/00327/Training%20Dataset.arff"
    response = requests.get(url)
    
    if response.status_code == 200:
        with open('data/raw/uci_phishing.arff', 'wb') as f:
            f.write(response.content)
        
        # We'll convert the ARFF in the preprocessing step
        print("UCI dataset downloaded successfully.")
        return True
    else:
        print(f"Failed to download UCI dataset. Status code: {response.status_code}")
        return False

def download_openphish_data():
    """Download OpenPhish feed"""
    print("Downloading OpenPhish feed...")
    url = "https://openphish.com/feed.txt"
    response = requests.get(url)
    
    if response.status_code == 200:
        # Save raw list
        with open('data/raw/openphish.txt', 'wb') as f:
            f.write(response.content)
            
        # Convert to CSV
        urls = response.text.strip().split('\n')
        df = pd.DataFrame({
            'url': urls,
            'label': 1  # 1 for phishing
        })
        df.to_csv('data/raw/openphish_simplified.csv', index=False)
        print("OpenPhish feed downloaded and processed successfully.")
        return True
    else:
        print(f"Failed to download OpenPhish feed. Status code: {response.status_code}")
        return False

if __name__ == "__main__":
    print("Starting dataset downloads...")
    phishtank_success = download_phishtank_data()
    alexa_success = download_alexa_data()
    uci_success = download_uci_dataset()
    openphish_success = download_openphish_data()
    
    print("\nDownload Summary:")
    print(f"PhishTank: {'Success' if phishtank_success else 'Failed'}")
    print(f"Alexa: {'Success' if alexa_success else 'Failed'}")
    print(f"UCI: {'Success' if uci_success else 'Failed'}")
    print(f"OpenPhish: {'Success' if openphish_success else 'Failed'}")