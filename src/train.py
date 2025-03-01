#!/usr/bin/env python3
"""
train.py - Train and save phishing detection model
"""
import os
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
import sys
import time
import logging

# Add parent directory to path to import from src
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from features.extractor import URLFeatureExtractor

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('model_training.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Create directories if they don't exist
os.makedirs('models', exist_ok=True)

def load_data():
    """Load training and validation data"""
    logger.info("Loading datasets...")
    
    train_path = '../data/processed/train.csv'
    val_path = '../data/processed/validation.csv'
    
    if not os.path.exists(train_path) or not os.path.exists(val_path):
        logger.error("Training or validation data not found. Run preprocess.py first.")
        return None, None
    
    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)
    
    logger.info(f"Training data: {len(train_df)} samples")
    logger.info(f"Validation data: {len(val_df)} samples")
    
    return train_df, val_df

def extract_features(train_df, val_df):
    """Extract features from URLs"""
    logger.info("Extracting features from URLs...")
    
    extractor = URLFeatureExtractor()
    
    # Fit the vectorizer on training data only
    extractor.fit_vectorizer(train_df['url'])
    
    # Extract features
    X_train = extractor.extract_features_bulk(train_df['url'])
    y_train = train_df['label']
    
    X_val = extractor.extract_features_bulk(val_df['url'])
    y_val = val_df['label']
    
    logger.info(f"Extracted {X_train.shape[1]} features")
    
    # Save the extractor for later use
    joblib.dump(extractor, 'models/url_extractor.pkl')
    logger.info("Feature extractor saved to models/url_extractor.pkl")
    
    return X_train, y_train, X_val, y_val, extractor

def train_random_forest(X_train, y_train, X_val, y_val):
    """Train a Random Forest model with hyperparameter tuning"""
    logger.info("Training Random Forest model...")
    
    # Define parameter grid for tuning
    param_grid = {
        'n_estimators': [100, 200],
        'max_depth': [None, 20, 30],
        'min_samples_split': [2, 5],
        'min_samples_leaf': [1, 2]
    }
    
    # Create base model
    rf = RandomForestClassifier(random_state=42, n_jobs=-1)
    
    # Use grid search with cross-validation
    grid_search = GridSearchCV(
        estimator=rf,
        param_grid=param_grid,
        cv=3,
        scoring='f1',
        verbose=1,
        n_jobs=-1
    )
    
    start_time = time.time()
    grid_search.fit(X_train, y_train)
    training_time = time.time() - start_time
    
    # Get best model
    best_model = grid_search.best_estimator_
    logger.info(f"Best parameters: {grid_search.best_params_}")
    
    # Evaluate on validation set
    y_pred = best_model.predict(X_val)
    accuracy = accuracy_score(y_val, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_val, y_pred, average='binary')
    
    logger.info(f"Training time: {training_time:.2f} seconds")
    logger.info(f"Validation metrics - Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}, F1: {f1:.4f}")
    logger.info("\nClassification Report:\n" + classification_report(y_val, y_pred))
    
    # Save model
    joblib.dump(best_model, 'models/rf_model.pkl')
    logger.info("Random Forest model saved to models/rf_model.pkl")
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': X_train.columns,
        'importance': best_model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    logger.info("\nTop 10 important features:")
    logger.info(feature_importance.head(10))
    
    return best_model, feature_importance

def train_gradient_boosting(X_train, y_train, X_val, y_val):
    """Train a Gradient Boosting model"""
    logger.info("Training Gradient Boosting model...")
    
    # Define parameter grid for tuning
    param_grid = {
        'n_estimators': [100, 200],
        'learning_rate': [0.05, 0.1],
        'max_depth': [3, 5],
        'min_samples_split': [2, 5]
    }
    
    # Create base model
    gb = GradientBoostingClassifier(random_state=42)
    
    # Use grid search with cross-validation
    grid_search = GridSearchCV(
        estimator=gb,
        param_grid=param_grid,
        cv=3,
        scoring='f1',
        verbose=1,
        n_jobs=-1
    )
    
    start_time = time.time()
    grid_search.fit(X_train, y_train)
    training_time = time.time() - start_time
    
    # Get best model
    best_model = grid_search.best_estimator_
    logger.info(f"Best parameters: {grid_search.best_params_}")
    
    # Evaluate on validation set
    y_pred = best_model.predict(X_val)
    accuracy = accuracy_score(y_val, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_val, y_pred, average='binary')
    
    logger.info(f"Training time: {training_time:.2f} seconds")
    logger.info(f"Validation metrics - Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}, F1: {f1:.4f}")
    logger.info("\nClassification Report:\n" + classification_report(y_val, y_pred))
    
    # Save model
    joblib.dump(best_model, 'models/gb_model.pkl')
    logger.info("Gradient Boosting model saved to models/gb_model.pkl")
    
    return best_model

def save_best_model(rf_model, gb_model, X_val, y_val):
    """Compare models and save the best one as the production model"""
    logger.info("Comparing models and selecting the best one...")
    
    # Get predictions from both models
    rf_pred = rf_model.predict(X_val)
    gb_pred = gb_model.predict(X_val)
    
    # Calculate F1 scores
    rf_f1 = precision_recall_fscore_support(y_val, rf_pred, average='binary')[2]
    gb_f1 = precision_recall_fscore_support(y_val, gb_pred, average='binary')[2]
    
    logger.info(f"Random Forest F1: {rf_f1:.4f}")
    logger.info(f"Gradient Boosting F1: {gb_f1:.4f}")
    
    # Select the best model
    if rf_f1 >= gb_f1:
        best_model = rf_model
        best_name = "Random Forest"
    else:
        best_model = gb_model
        best_name = "Gradient Boosting"
    
    logger.info(f"Best model: {best_name}")
    
    # Save as production model
    joblib.dump(best_model, 'models/production_model.pkl')
    logger.info("Best model saved as models/production_model.pkl")
    
    # Return best model and name
    return best_model, best_name

if __name__ == "__main__":
    logger.info("Starting phishing detection model training...")
    
    # Load data
    train_df, val_df = load_data()
    if train_df is None or val_df is None:
        sys.exit(1)
    
    # Extract features
    X_train, y_train, X_val, y_val, extractor = extract_features(train_df, val_df)
    
    # Train Random Forest model
    rf_model, feature_importance = train_random_forest(X_train, y_train, X_val, y_val)
    
    # Train Gradient Boosting model
    gb_model = train_gradient_boosting(X_train, y_train, X_val, y_val)
    
    # Choose and save the best model
    best_model, best_name = save_best_model(rf_model, gb_model, X_val, y_val)
    
    # Save the feature names
    joblib.dump(X_train.columns.tolist(), 'models/feature_names.pkl')
    
    # Save metadata
    metadata = {
        'training_date': pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S'),
        'train_samples': len(train_df),
        'features_count': X_train.shape[1],
        'best_model': best_name,
        'feature_importance': feature_importance.head(20).to_dict()
    }
    joblib.dump(metadata, 'models/metadata.pkl')
    
    logger.info("Model training completed successfully.")