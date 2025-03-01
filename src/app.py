#!/usr/bin/env python3
"""
app.py - Flask API for phishing URL detection
"""
import os
import sys
import logging
import joblib
import pandas as pd
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import time

# Add parent directory to path to import from src
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from features.extractor import URLFeatureExtractor

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('api.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for browser extension

# Global variables to store model and extractor
model = None
extractor = None
optimal_threshold = 0.5
feature_names = None

def load_model():
    """Load the model, extractor, and other required files"""
    global model, extractor, optimal_threshold, feature_names
    
    try:
        model_path = 'models/production_model.pkl'
        extractor_path = 'models/url_extractor.pkl'
        threshold_path = 'models/optimal_threshold.txt'
        feature_names_path = 'models/feature_names.pkl'
        
        model = joblib.load(model_path)
        extractor = joblib.load(extractor_path)
        
        if os.path.exists(threshold_path):
            with open(threshold_path, 'r') as f:
                optimal_threshold = float(f.read().strip())
        
        if os.path.exists(feature_names_path):
            feature_names = joblib.load(feature_names_path)
        
        logger.info("Model and dependencies loaded successfully")
        logger.info(f"Using optimal threshold: {optimal_threshold}")
        return True
    except Exception as e:
        logger.error(f"Error loading model: {str(e)}")
        return False

@app.route('/')
def home():
    """Render home page with API documentation"""
    return render_template('index.html')

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    if model is not None and extractor is not None:
        return jsonify({"status": "healthy", "model_loaded": True})
    else:
        return jsonify({"status": "unhealthy", "model_loaded": False}), 503

@app.route('/predict', methods=['POST'])
def predict_url():
    """Predict if a URL is phishing or legitimate"""
    try:
        # Get URL from request
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({"error": "URL is required"}), 400
        
        url = data['url']
        logger.info(f"Prediction request for URL: {url}")
        
        # Extract features
        start_time = time.time()
        features = extractor.extract_features(url)
        
        # Convert to DataFrame
        features_df = pd.DataFrame([features])
        
        # Ensure all expected features are present
        if feature_names is not None:
            for feature in feature_names:
                if feature not in features_df.columns:
                    features_df[feature] = 0
            # Ensure columns are in the right order
            features_df = features_df[feature_names]
        
        # Make prediction
        probability = model.predict_proba(features_df)[0][1]  # Probability of phishing class
        prediction = 1 if probability >= optimal_threshold else 0
        
        # Get top features
        if hasattr(model, 'feature_importances_') and feature_names is not None:
            importances = model.feature_importances_
            indices = importances.argsort()[::-1]
            top_features = [feature_names[i] for i in indices[:5]]
        else:
            top_features = []
        
        processing_time = time.time() - start_time
        
        # Return prediction
        result = {
            "url": url,
            "is_phishing": bool(prediction),
            "probability": float(probability),
            "confidence": float(abs(probability - 0.5) * 2),  # Scale to 0-1
            "processing_time_ms": int(processing_time * 1000),
            "top_features": top_features
        }
        
        logger.info(f"Prediction: {result['is_phishing']} (prob: {result['probability']:.4f})")
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/batch', methods=['POST'])
def batch_predict():
    """Predict multiple URLs in one request"""
    try:
        # Get URLs from request
        data = request.get_json()
        
        if not data or 'urls' not in data or not isinstance(data['urls'], list):
            return jsonify({"error": "List of URLs is required"}), 400
        
        urls = data['urls']
        logger.info(f"Batch prediction request for {len(urls)} URLs")
        
        results = []
        for url in urls:
            # Extract features
            features = extractor.extract_features(url)
            
            # Convert to DataFrame
            features_df = pd.DataFrame([features])
            
            # Ensure all expected features are present
            if feature_names is not None:
                for feature in feature_names:
                    if feature not in features_df.columns:
                        features_df[feature] = 0
                # Ensure columns are in the right order
                features_df = features_df[feature_names]
            
            # Make prediction
            probability = model.predict_proba(features_df)[0][1]
            prediction = 1 if probability >= optimal_threshold else 0
            
            # Add to results
            results.append({
                "url": url,
                "is_phishing": bool(prediction),
                "probability": float(probability)
            })
        
        return jsonify({"results": results})
    
    except Exception as e:
        logger.error(f"Error processing batch request: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/feedback', methods=['POST'])
def submit_feedback():
    """Submit feedback for a URL prediction"""
    try:
        data = request.get_json()
        
        if not data or 'url' not in data or 'actual_label' not in data:
            return jsonify({"error": "URL and actual_label are required"}), 400
        
        url = data['url']
        actual_label = int(data['actual_label'])
        predicted_label = data.get('predicted_label')
        
        logger.info(f"Feedback received - URL: {url}, Actual: {actual_label}, Predicted: {predicted_label}")
        
        # Store feedback for future model improvements
        feedback_file = 'data/feedback.csv'
        feedback_exists = os.path.exists(feedback_file)
        
        feedback_df = pd.DataFrame([{
            'url': url,
            'actual_label': actual_label,
            'predicted_label': predicted_label,
            'timestamp': pd.Timestamp.now()
        }])
        
        feedback_df.to_csv(feedback_file, mode='a', header=not feedback_exists, index=False)
        
        return jsonify({"status": "success", "message": "Feedback recorded"})
    
    except Exception as e:
        logger.error(f"Error processing feedback: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    # Load model before starting the server
    if load_model():
        # Create templates directory if it doesn't exist
        os.makedirs('templates', exist_ok=True)
        
        # Create a simple HTML template
        with open('templates/index.html', 'w') as f:
            f.write("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Phishing URL Detection API</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
                    h1 { color: #333; }
                    pre { background-color: #f4f4f4; padding: 15px; border-radius: 5px; }
                </style>
            </head>
            <body>
                <h1>Phishing URL Detection API</h1>
                <p>This API provides phishing detection for URLs.</p>
                
                <h2>Endpoints</h2>
                
                <h3>1. Predict a Single URL</h3>
                <pre>
                POST /predict
                Content-Type: application/json
                
                {
                    "url": "https://example.com"
                }
                </pre>
                
                <h3>2. Batch Prediction</h3>
                <pre>
                POST /batch
                Content-Type: application/json
                
                {
                    "urls": [
                        "https://example1.com",
                        "https://example2.com"
                    ]
                }
                </pre>
                
                <h3>3. Submit Feedback</h3>
                <pre>
                POST /feedback
                Content-Type: application/json
                
                {
                    "url": "https://example.com",
                    "actual_label": 1,
                    "predicted_label": 0
                }
                </pre>
                
                <h3>4. Health Check</h3>
                <pre>
                GET /health
                </pre>
            </body>
            </html>
            """)
        
        # Run the Flask app
        app.run(host='0.0.0.0', port=5000, debug=False)
    else:
        logger.error("Failed to load model. API server not started.")