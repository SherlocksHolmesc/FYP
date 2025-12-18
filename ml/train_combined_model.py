"""
Train Model on Combined Dataset
================================
Uses both real-world GoPlus-verified fraud + Kaggle benign samples
for better balanced training.
"""

import os
import json
import pickle
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, classification_report

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
DATASET_FILE = os.path.join(DATA_DIR, 'combined_dataset.csv')
MODEL_DIR = os.path.dirname(__file__)

def main():
    print("Loading combined dataset...")
    df = pd.read_csv(DATASET_FILE)
    
    print(f"Loaded {len(df)} samples")
    print(f"  - Fraud (1): {(df['FLAG'] == 1).sum()}")
    print(f"  - Benign (0): {(df['FLAG'] == 0).sum()}")
    print(f"  - Fraud ratio: {(df['FLAG'] == 1).sum() / len(df) * 100:.1f}%")
    
    # Features to use (common between both datasets)
    feature_cols = [
        'Avg min between sent tnx',
        'Avg min between received tnx',
        'Time Diff between first and last (Mins)',
        'Sent tnx',
        'Received Tnx',
        'Number of Created Contracts',
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
    
    # Filter to available columns
    available_features = [f for f in feature_cols if f in df.columns]
    print(f"\nUsing {len(available_features)} features")
    
    # Prepare data
    X = df[available_features].fillna(0)
    y = df['FLAG']
    
    # Replace infinities
    X = X.replace([np.inf, -np.inf], 0)
    
    print("\n" + "=" * 60)
    print("TRAINING MODELS")
    print("=" * 60)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    print(f"\nTrain set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train models with class_weight='balanced' for better handling
    models = {
        'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced'),
        'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
        'Logistic Regression': LogisticRegression(random_state=42, max_iter=1000, class_weight='balanced'),
    }
    
    results = {}
    for name, model in models.items():
        print(f"\n--- {name} ---")
        model.fit(X_train_scaled, y_train)
        y_pred = model.predict(X_test_scaled)
        y_proba = model.predict_proba(X_test_scaled)[:, 1]
        
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        roc = roc_auc_score(y_test, y_proba)
        
        cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5, scoring='roc_auc')
        
        print(f"Accuracy:  {acc:.4f}")
        print(f"Precision: {prec:.4f}")
        print(f"Recall:    {rec:.4f}")
        print(f"F1 Score:  {f1:.4f}")
        print(f"ROC-AUC:   {roc:.4f}")
        print(f"CV ROC-AUC: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")
        
        results[name] = {
            'model': model,
            'accuracy': acc,
            'precision': prec,
            'recall': rec,
            'f1': f1,
            'roc_auc': roc,
            'cv_roc_auc': cv_scores.mean()
        }
    
    # Select best model (by F1 for balanced metric)
    best_name = max(results, key=lambda x: results[x]['f1'])
    best_model = results[best_name]['model']
    
    print("\n" + "=" * 60)
    print(f"BEST MODEL: {best_name}")
    print("=" * 60)
    
    # Final evaluation
    y_pred = best_model.predict(X_test_scaled)
    cm = confusion_matrix(y_test, y_pred)
    
    print(f"\nConfusion Matrix:")
    print(f"  TN={cm[0,0]:4d}  FP={cm[0,1]:4d}")
    print(f"  FN={cm[1,0]:4d}  TP={cm[1,1]:4d}")
    
    print(f"\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Fraud']))
    
    # Feature importance
    if hasattr(best_model, 'feature_importances_'):
        importances = list(zip(available_features, best_model.feature_importances_))
        importances.sort(key=lambda x: x[1], reverse=True)
        print("\nTop 10 Most Important Features:")
        for feat, imp in importances[:10]:
            print(f"  {imp:.4f} - {feat}")
    
    # Save model
    print("\n" + "=" * 60)
    print("SAVING MODEL")
    print("=" * 60)
    
    model_path = os.path.join(MODEL_DIR, 'model_v2.pkl')
    scaler_path = os.path.join(MODEL_DIR, 'scaler_v2.pkl')
    features_path = os.path.join(MODEL_DIR, 'features_v2.json')
    
    with open(model_path, 'wb') as f:
        pickle.dump(best_model, f)
    print(f"✓ Model saved to {model_path}")
    
    with open(scaler_path, 'wb') as f:
        pickle.dump(scaler, f)
    print(f"✓ Scaler saved to {scaler_path}")
    
    with open(features_path, 'w') as f:
        json.dump({'features': available_features}, f, indent=2)
    print(f"✓ Features saved to {features_path}")
    
    print("\n" + "=" * 60)
    print("MODEL READY!")
    print("=" * 60)
    print("Restart your API to use the new model.")

if __name__ == '__main__':
    main()
