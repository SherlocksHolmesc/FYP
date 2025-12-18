"""
Train ML Model on Real-World Data
==================================

This script trains a model on REAL malicious addresses that were:
1. Verified by GoPlus Security API
2. In our darklist from MyEtherWallet
3. Known safe addresses (exchanges, DeFi protocols)

The key insight: This model learns patterns that PREDICT
whether an address will be flagged by GoPlus - potentially
BEFORE GoPlus adds it to their database.

Usage:
    python train_real_model.py
"""

import os
import json
import pickle
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)
import warnings
warnings.filterwarnings('ignore')

# ============================================================
# CONFIGURATION
# ============================================================

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
DATASET_PATH = os.path.join(DATA_DIR, 'real_world_dataset.csv')
MODEL_OUTPUT = os.path.join(os.path.dirname(__file__), 'model_v2.pkl')
SCALER_OUTPUT = os.path.join(os.path.dirname(__file__), 'scaler_v2.pkl')
FEATURES_OUTPUT = os.path.join(os.path.dirname(__file__), 'features_v2.json')

# Features to use (excluding metadata columns)
EXCLUDE_COLUMNS = ['address', 'FLAG', 'source', 'goplus_verified', 'goplus_flags']

# ============================================================
# DATA LOADING & PREPROCESSING
# ============================================================

def load_data():
    """Load and preprocess the real-world dataset."""
    print("Loading dataset...")
    
    if not os.path.exists(DATASET_PATH):
        print(f"ERROR: Dataset not found at {DATASET_PATH}")
        print("Run collect_training_data.py first!")
        return None, None, None
    
    df = pd.read_csv(DATASET_PATH)
    print(f"Loaded {len(df)} samples")
    print(f"  - Malicious: {len(df[df['FLAG'] == 1])}")
    print(f"  - Safe: {len(df[df['FLAG'] == 0])}")
    
    # Check class balance
    mal_ratio = len(df[df['FLAG'] == 1]) / len(df)
    print(f"  - Malicious ratio: {mal_ratio:.1%}")
    
    # Get feature columns
    feature_cols = [col for col in df.columns if col not in EXCLUDE_COLUMNS]
    print(f"\nUsing {len(feature_cols)} features:")
    for col in feature_cols:
        print(f"  - {col}")
    
    # Handle missing values
    X = df[feature_cols].fillna(0)
    y = df['FLAG']
    
    return X, y, feature_cols

# ============================================================
# MODEL TRAINING
# ============================================================

def train_and_evaluate():
    """Train multiple models and select the best one."""
    
    X, y, feature_cols = load_data()
    if X is None:
        return
    
    print("\n" + "=" * 60)
    print("TRAINING MODELS")
    print("=" * 60)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Define models to try
    models = {
        'Random Forest': RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced',  # Handle imbalanced data
            random_state=42,
            n_jobs=-1
        ),
        'Gradient Boosting': GradientBoostingClassifier(
            n_estimators=150,
            max_depth=6,
            learning_rate=0.1,
            random_state=42
        ),
        'Logistic Regression': LogisticRegression(
            class_weight='balanced',
            max_iter=1000,
            random_state=42
        )
    }
    
    results = {}
    best_model = None
    best_score = 0
    best_name = ""
    
    for name, model in models.items():
        print(f"\n--- {name} ---")
        
        # Train
        model.fit(X_train_scaled, y_train)
        
        # Predict
        y_pred = model.predict(X_test_scaled)
        y_proba = model.predict_proba(X_test_scaled)[:, 1]
        
        # Metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        roc_auc = roc_auc_score(y_test, y_proba)
        
        print(f"Accuracy:  {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall:    {recall:.4f}")
        print(f"F1 Score:  {f1:.4f}")
        print(f"ROC-AUC:   {roc_auc:.4f}")
        
        # Cross-validation
        cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5, scoring='roc_auc')
        print(f"CV ROC-AUC: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")
        
        results[name] = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'roc_auc': roc_auc,
            'cv_mean': cv_scores.mean()
        }
        
        # Track best model (prioritize recall - we want to catch threats)
        score = (recall * 0.4) + (precision * 0.3) + (roc_auc * 0.3)
        if score > best_score:
            best_score = score
            best_model = model
            best_name = name
    
    print("\n" + "=" * 60)
    print(f"BEST MODEL: {best_name}")
    print("=" * 60)
    
    # Detailed evaluation of best model
    y_pred = best_model.predict(X_test_scaled)
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  TN={cm[0,0]:4d}  FP={cm[0,1]:4d}")
    print(f"  FN={cm[1,0]:4d}  TP={cm[1,1]:4d}")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Malicious']))
    
    # Feature importance (if Random Forest)
    if hasattr(best_model, 'feature_importances_'):
        print("\nTop 10 Most Important Features:")
        importances = pd.DataFrame({
            'feature': feature_cols,
            'importance': best_model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        for i, row in importances.head(10).iterrows():
            print(f"  {row['importance']:.4f} - {row['feature']}")
    
    # Save model
    print("\n" + "=" * 60)
    print("SAVING MODEL")
    print("=" * 60)
    
    with open(MODEL_OUTPUT, 'wb') as f:
        pickle.dump(best_model, f)
    print(f"✓ Model saved to {MODEL_OUTPUT}")
    
    with open(SCALER_OUTPUT, 'wb') as f:
        pickle.dump(scaler, f)
    print(f"✓ Scaler saved to {SCALER_OUTPUT}")
    
    with open(FEATURES_OUTPUT, 'w') as f:
        json.dump({'features': feature_cols}, f, indent=2)
    print(f"✓ Features saved to {FEATURES_OUTPUT}")
    
    print("\n" + "=" * 60)
    print("MODEL READY!")
    print("=" * 60)
    print(f"To use the new model, update api.py to load:")
    print(f"  - model_v2.pkl")
    print(f"  - scaler_v2.pkl")
    print(f"  - features_v2.json")
    
    return best_model, scaler, feature_cols, results

# ============================================================
# MAIN
# ============================================================

if __name__ == '__main__':
    train_and_evaluate()
