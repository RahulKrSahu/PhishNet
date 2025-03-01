#!/usr/bin/env python3
"""
evaluate.py - Evaluate the trained model on the test set
"""
import os
import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support, roc_curve, auc
import matplotlib.pyplot as plt
import sys
import logging

# Add parent directory to path to import from src
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('model_evaluation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_test_data():
    """Load test data"""
    logger.info("Loading test dataset...")
    
    test_path = 'data/processed/test.csv'
    
    if not os.path.exists(test_path):
        logger.error("Test data not found. Run preprocess.py first.")
        return None
    
    test_df = pd.read_csv(test_path)
    logger.info(f"Test data: {len(test_df)} samples")
    
    return test_df

def load_model_and_extractor():
    """Load the production model and feature extractor"""
    logger.info("Loading model and feature extractor...")
    
    model_path = 'models/production_model.pkl'
    extractor_path = 'models/url_extractor.pkl'
    
    if not os.path.exists(model_path) or not os.path.exists(extractor_path):
        logger.error("Model or feature extractor not found. Run train.py first.")
        return None, None
    
    model = joblib.load(model_path)
    extractor = joblib.load(extractor_path)
    
    logger.info(f"Model loaded: {type(model).__name__}")
    
    return model, extractor

def evaluate_model(model, extractor, test_df):
    """Evaluate the model on test data"""
    logger.info("Evaluating model on test data...")
    
    # Extract features
    X_test = extractor.extract_features_bulk(test_df['url'])
    y_test = test_df['label']
    
    # Make predictions
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]  # Probability of phishing class
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='binary')
    
    # Print results
    logger.info(f"Test metrics - Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}, F1: {f1:.4f}")
    logger.info("\nClassification Report:\n" + classification_report(y_test, y_pred))
    
    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    logger.info("\nConfusion Matrix:")
    logger.info(f"{cm[0][0]} {cm[0][1]}")
    logger.info(f"{cm[1][0]} {cm[1][1]}")
    
    # Create a directory for plots
    os.makedirs('evaluation', exist_ok=True)
    
    # Plot confusion matrix
    plt.figure(figsize=(8, 6))
    plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    plt.title('Confusion Matrix')
    plt.colorbar()
    plt.xticks([0, 1], ['Legitimate', 'Phishing'])
    plt.yticks([0, 1], ['Legitimate', 'Phishing'])
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    
    # Display values in cells
    for i in range(2):
        for j in range(2):
            plt.text(j, i, str(cm[i, j]), ha='center', va='center',
                    color='white' if cm[i, j] > cm.max() / 2 else 'black')
    
    plt.tight_layout()
    plt.savefig('evaluation/confusion_matrix.png')
    logger.info("Confusion matrix saved to evaluation/confusion_matrix.png")
    
    # ROC curve
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    roc_auc = auc(fpr, tpr)
    
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.2f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic')
    plt.legend(loc='lower right')
    plt.savefig('evaluation/roc_curve.png')
    logger.info(f"ROC curve saved to evaluation/roc_curve.png (AUC: {roc_auc:.4f})")
    
    # Find URLs where model made errors
    test_df['predicted'] = y_pred
    test_df['phishing_probability'] = y_prob
    
    false_positives = test_df[(test_df['label'] == 0) & (test_df['predicted'] == 1)]
    false_negatives = test_df[(test_df['label'] == 1) & (test_df['predicted'] == 0)]
    
    # Save error analysis
    false_positives.to_csv('evaluation/false_positives.csv', index=False)
    false_negatives.to_csv('evaluation/false_negatives.csv', index=False)
    
    logger.info(f"False positives: {len(false_positives)} URLs")
    logger.info(f"False negatives: {len(false_negatives)} URLs")
    logger.info("Error analysis saved to evaluation directory")
    
    # Calculate threshold analysis
    thresholds = np.arange(0.1, 1.0, 0.05)
    results = []
    
    for threshold in thresholds:
        y_pred_t = (y_prob >= threshold).astype(int)
        precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred_t, average='binary')
        results.append([threshold, precision, recall, f1])
    
    threshold_df = pd.DataFrame(results, columns=['threshold', 'precision', 'recall', 'f1'])
    threshold_df.to_csv('evaluation/threshold_analysis.csv', index=False)
    
    # Plot threshold analysis
    plt.figure(figsize=(10, 6))
    plt.plot(threshold_df['threshold'], threshold_df['precision'], 'b-', label='Precision')
    plt.plot(threshold_df['threshold'], threshold_df['recall'], 'g-', label='Recall')
    plt.plot(threshold_df['threshold'], threshold_df['f1'], 'r-', label='F1 Score')
    plt.xlabel('Threshold')
    plt.ylabel('Score')
    plt.title('Precision, Recall, and F1 Score vs. Threshold')
    plt.legend()
    plt.grid(True)
    plt.savefig('evaluation/threshold_analysis.png')
    logger.info("Threshold analysis saved to evaluation/threshold_analysis.csv and .png")
    
    # Find optimal threshold for F1
    best_threshold = threshold_df.loc[threshold_df['f1'].idxmax(), 'threshold']
    logger.info(f"Optimal threshold for F1 score: {best_threshold:.2f}")
    
    # Save results summary
    results_summary = {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'roc_auc': roc_auc,
        'optimal_threshold': best_threshold,
        'test_size': len(test_df),
        'confusion_matrix': cm.tolist()
    }
    joblib.dump(results_summary, 'evaluation/results_summary.pkl')
    
    return results_summary

if __name__ == "__main__":
    logger.info("Starting model evaluation...")
    
    # Load test data
    test_df = load_test_data()
    if test_df is None:
        sys.exit(1)
    
    # Load model and extractor
    model, extractor = load_model_and_extractor()
    if model is None or extractor is None:
        sys.exit(1)
    
    # Evaluate model
    results = evaluate_model(model, extractor, test_df)
    
    logger.info("Model evaluation completed successfully.")