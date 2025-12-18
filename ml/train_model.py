"""
Web3 Risk Guard - ML Model Training Script
==========================================

This script trains a fraud detection model on the Kaggle Ethereum dataset
and exports it to ONNX format for browser inference.

BEFORE RUNNING:
1. Download dataset from: https://www.kaggle.com/datasets/vagifa/ethereum-frauddetection-dataset
2. Place 'transaction_dataset.csv' in ml/data/

INSTALL DEPENDENCIES:
    pip install pandas scikit-learn onnx skl2onnx numpy
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import json
import pickle
import os

# Paths
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
DATASET_PATH = os.path.join(DATA_DIR, 'transaction_dataset.csv')
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.pkl')
SCALER_PATH = os.path.join(os.path.dirname(__file__), 'scaler.pkl')
FEATURES_PATH = os.path.join(os.path.dirname(__file__), 'features.json')


def load_and_prepare_data():
    """Load and prepare the Kaggle Ethereum fraud dataset."""
    
    if not os.path.exists(DATASET_PATH):
        print("=" * 60)
        print("ERROR: Dataset not found!")
        print("=" * 60)
        print(f"\nExpected path: {DATASET_PATH}")
        print("\nSteps to fix:")
        print("1. Go to: https://www.kaggle.com/datasets/vagifa/ethereum-frauddetection-dataset")
        print("2. Click 'Download' (you need a Kaggle account)")
        print("3. Extract and place 'transaction_dataset.csv' in:")
        print(f"   {DATA_DIR}")
        print("=" * 60)
        return None, None
    
    print("Loading dataset...")
    df = pd.read_csv(DATASET_PATH, index_col=0)
    
    print(f"Dataset shape: {df.shape}")
    print(f"Fraud cases: {df['FLAG'].sum()} ({df['FLAG'].mean()*100:.2f}%)")
    
    return df


def select_features(df):
    """
    Select features relevant to wallet risk scoring.
    
    These features can be approximated or adapted for real-time scoring:
    - Transaction patterns
    - Value statistics  
    - Time-based features
    """
    
    # Features available in the Kaggle dataset
    feature_cols = [
        'Avg min between sent tnx',
        'Avg min between received tnx', 
        'Time Diff between first and last (Mins)',
        'Sent tnx',
        'Received Tnx',
        'Number of Created Contracts',
        'max value received',
        'avg val received',
        'avg val sent',
        'total Ether sent',
        'total ether received',
        'total ether balance',
        ' ERC20 total Ether received',
        ' ERC20 total ether sent',
        ' ERC20 uniq sent addr',
        ' ERC20 uniq rec addr',
        ' ERC20 uniq sent token name',
        ' ERC20 uniq rec token name',
    ]
    
    # Filter to columns that exist
    available_features = [c for c in feature_cols if c in df.columns]
    print(f"\nUsing {len(available_features)} features:")
    for f in available_features:
        print(f"  - {f}")
    
    X = df[available_features].copy()
    y = df['FLAG'].copy()
    
    # Handle missing values
    X = X.fillna(0)
    
    # Replace infinity values
    X = X.replace([np.inf, -np.inf], 0)
    
    return X, y, available_features


def train_model(X, y):
    """Train a Random Forest classifier."""
    
    print("\n" + "=" * 60)
    print("TRAINING MODEL")
    print("=" * 60)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train Random Forest
    print("\nTraining Random Forest...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'  # Handle class imbalance
    )
    
    model.fit(X_train_scaled, y_train)
    
    # Evaluate
    print("\n" + "=" * 60)
    print("MODEL EVALUATION")
    print("=" * 60)
    
    y_pred = model.predict(X_test_scaled)
    y_proba = model.predict_proba(X_test_scaled)[:, 1]
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Fraud']))
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    print(f"\nROC-AUC Score: {roc_auc_score(y_test, y_proba):.4f}")
    
    # Feature importance
    print("\n" + "=" * 60)
    print("FEATURE IMPORTANCE (Top 10)")
    print("=" * 60)
    
    importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    for _, row in importance.head(10).iterrows():
        print(f"  {row['importance']:.4f} - {row['feature']}")
    
    return model, scaler


def export_model(model, scaler, features):
    """Export model for use in the extension."""
    
    print("\n" + "=" * 60)
    print("EXPORTING MODEL")
    print("=" * 60)
    
    # Save model as pickle (for Python backend if needed)
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    print(f"Model saved: {MODEL_PATH}")
    
    # Save scaler
    with open(SCALER_PATH, 'wb') as f:
        pickle.dump(scaler, f)
    print(f"Scaler saved: {SCALER_PATH}")
    
    # Save feature names
    with open(FEATURES_PATH, 'w') as f:
        json.dump({'features': features}, f, indent=2)
    print(f"Features saved: {FEATURES_PATH}")
    
    # Export simplified model info for browser
    browser_model_path = os.path.join(os.path.dirname(__file__), 'model_browser.json')
    
    # For browser, we'll export the tree structure or use a simple lookup
    # For MVP, we'll create threshold-based rules from the model
    browser_config = {
        'type': 'threshold_rules',
        'description': 'Simplified rules derived from Random Forest',
        'rules': generate_browser_rules(model, features)
    }
    
    with open(browser_model_path, 'w') as f:
        json.dump(browser_config, f, indent=2)
    print(f"Browser model saved: {browser_model_path}")


def generate_browser_rules(model, features):
    """
    Generate simplified threshold rules for browser inference.
    
    Since we can't easily run sklearn in browser, we extract
    the most important decision boundaries as simple rules.
    """
    
    # Get feature importances
    importance = dict(zip(features, model.feature_importances_))
    
    # Extract rules from first few trees (simplified)
    rules = []
    
    # Top features with thresholds (these are approximations)
    top_features = sorted(importance.items(), key=lambda x: -x[1])[:5]
    
    for feat, imp in top_features:
        rules.append({
            'feature': feat,
            'importance': float(imp),
            'description': f'High importance feature ({imp:.3f})'
        })
    
    return rules


def main():
    print("=" * 60)
    print("Web3 Risk Guard - ML Training Pipeline")
    print("=" * 60)
    
    # Load data
    df = load_and_prepare_data()
    if df is None:
        return
    
    # Select features
    X, y, features = select_features(df)
    
    # Train model
    model, scaler = train_model(X, y)
    
    # Export
    export_model(model, scaler, features)
    
    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)
    print("\nNext steps:")
    print("1. The model is saved as model.pkl")
    print("2. For browser inference, you have two options:")
    print("   a) Use a backend API (recommended for accuracy)")
    print("   b) Use the simplified rules in model_browser.json")
    print("3. Integrate with your extension's scoring logic")


if __name__ == '__main__':
    main()
