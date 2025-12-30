"""
ML Model Visualization
=======================
Generates charts and visualizations for the trained fraud detection model.
"""

import os
import pickle
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, roc_curve, auc, precision_recall_curve
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Paths
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
DATASET_FILE = os.path.join(DATA_DIR, 'combined_dataset.csv')
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model_v2.pkl')
SCALER_PATH = os.path.join(os.path.dirname(__file__), 'scaler_v2.pkl')
FEATURES_PATH = os.path.join(os.path.dirname(__file__), 'features_v2.json')
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'visualizations')

# Create output directory
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Set style
plt.style.use('seaborn-v0_8-whitegrid')
sns.set_palette("husl")

def load_data_and_model():
    """Load dataset and trained model."""
    # Load data
    df = pd.read_csv(DATASET_FILE)
    
    # Load model
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    with open(SCALER_PATH, 'rb') as f:
        scaler = pickle.load(f)
    with open(FEATURES_PATH, 'r') as f:
        feature_names = json.load(f)['features']
    
    return df, model, scaler, feature_names

def plot_class_distribution(df):
    """Plot distribution of fraud vs safe addresses."""
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    
    # Pie chart
    counts = df['FLAG'].value_counts()
    labels = ['Safe (0)', 'Fraud (1)']
    colors = ['#2ecc71', '#e74c3c']
    axes[0].pie(counts, labels=labels, autopct='%1.1f%%', colors=colors, explode=(0, 0.05))
    axes[0].set_title('Dataset Class Distribution', fontsize=14, fontweight='bold')
    
    # Bar chart
    ax = sns.countplot(x='FLAG', data=df, ax=axes[1], palette=['#2ecc71', '#e74c3c'])
    axes[1].set_xlabel('Class', fontsize=12)
    axes[1].set_ylabel('Count', fontsize=12)
    axes[1].set_title('Number of Samples per Class', fontsize=14, fontweight='bold')
    axes[1].set_xticklabels(['Safe', 'Fraud'])
    
    for p in ax.patches:
        ax.annotate(f'{int(p.get_height())}', 
                    (p.get_x() + p.get_width() / 2., p.get_height()),
                    ha='center', va='bottom', fontsize=12, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, '1_class_distribution.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print("✓ Saved: 1_class_distribution.png")

def plot_feature_importance(model, feature_names):
    """Plot feature importance from Random Forest."""
    if not hasattr(model, 'feature_importances_'):
        print("Model doesn't have feature_importances_")
        return
    
    importance = model.feature_importances_
    indices = np.argsort(importance)[::-1]
    
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Top 15 features
    top_n = min(15, len(feature_names))
    colors = plt.cm.RdYlGn_r(np.linspace(0.2, 0.8, top_n))
    
    bars = ax.barh(range(top_n), importance[indices[:top_n]], color=colors)
    ax.set_yticks(range(top_n))
    ax.set_yticklabels([feature_names[i] for i in indices[:top_n]])
    ax.invert_yaxis()
    ax.set_xlabel('Importance Score', fontsize=12)
    ax.set_title('Top Feature Importance for Fraud Detection', fontsize=14, fontweight='bold')
    
    # Add value labels
    for bar, val in zip(bars, importance[indices[:top_n]]):
        ax.text(val + 0.005, bar.get_y() + bar.get_height()/2, f'{val:.3f}', 
                va='center', fontsize=10)
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, '2_feature_importance.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print("✓ Saved: 2_feature_importance.png")

def plot_confusion_matrix(model, X_test, y_test, scaler):
    """Plot confusion matrix."""
    X_test_scaled = scaler.transform(X_test)
    y_pred = model.predict(X_test_scaled)
    
    cm = confusion_matrix(y_test, y_pred)
    
    fig, ax = plt.subplots(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax,
                xticklabels=['Safe', 'Fraud'], yticklabels=['Safe', 'Fraud'],
                annot_kws={'size': 16})
    ax.set_xlabel('Predicted', fontsize=12)
    ax.set_ylabel('Actual', fontsize=12)
    ax.set_title('Confusion Matrix', fontsize=14, fontweight='bold')
    
    # Add accuracy text
    accuracy = (cm[0,0] + cm[1,1]) / cm.sum()
    ax.text(0.5, -0.15, f'Accuracy: {accuracy:.2%}', transform=ax.transAxes, 
            ha='center', fontsize=12, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, '3_confusion_matrix.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print("✓ Saved: 3_confusion_matrix.png")

def plot_roc_curve(model, X_test, y_test, scaler):
    """Plot ROC curve."""
    X_test_scaled = scaler.transform(X_test)
    y_proba = model.predict_proba(X_test_scaled)[:, 1]
    
    fpr, tpr, _ = roc_curve(y_test, y_proba)
    roc_auc = auc(fpr, tpr)
    
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot(fpr, tpr, color='#3498db', lw=2, label=f'ROC Curve (AUC = {roc_auc:.3f})')
    ax.plot([0, 1], [0, 1], color='gray', lw=1, linestyle='--', label='Random Classifier')
    ax.fill_between(fpr, tpr, alpha=0.3, color='#3498db')
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel('False Positive Rate', fontsize=12)
    ax.set_ylabel('True Positive Rate', fontsize=12)
    ax.set_title('ROC Curve - Fraud Detection Model', fontsize=14, fontweight='bold')
    ax.legend(loc='lower right', fontsize=11)
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, '4_roc_curve.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print("✓ Saved: 4_roc_curve.png")

def plot_precision_recall_curve(model, X_test, y_test, scaler):
    """Plot Precision-Recall curve."""
    X_test_scaled = scaler.transform(X_test)
    y_proba = model.predict_proba(X_test_scaled)[:, 1]
    
    precision, recall, _ = precision_recall_curve(y_test, y_proba)
    pr_auc = auc(recall, precision)
    
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot(recall, precision, color='#e74c3c', lw=2, label=f'PR Curve (AUC = {pr_auc:.3f})')
    ax.fill_between(recall, precision, alpha=0.3, color='#e74c3c')
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel('Recall', fontsize=12)
    ax.set_ylabel('Precision', fontsize=12)
    ax.set_title('Precision-Recall Curve', fontsize=14, fontweight='bold')
    ax.legend(loc='lower left', fontsize=11)
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, '5_precision_recall_curve.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print("✓ Saved: 5_precision_recall_curve.png")

def plot_score_distribution(model, X_test, y_test, scaler):
    """Plot distribution of fraud probability scores."""
    X_test_scaled = scaler.transform(X_test)
    y_proba = model.predict_proba(X_test_scaled)[:, 1]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Separate scores by class
    safe_scores = y_proba[y_test == 0] * 100
    fraud_scores = y_proba[y_test == 1] * 100
    
    ax.hist(safe_scores, bins=30, alpha=0.7, label='Safe Addresses', color='#2ecc71', edgecolor='white')
    ax.hist(fraud_scores, bins=30, alpha=0.7, label='Fraud Addresses', color='#e74c3c', edgecolor='white')
    
    ax.axvline(x=50, color='black', linestyle='--', lw=2, label='Threshold (50)')
    ax.set_xlabel('ML Risk Score', fontsize=12)
    ax.set_ylabel('Count', fontsize=12)
    ax.set_title('Distribution of ML Risk Scores by Class', fontsize=14, fontweight='bold')
    ax.legend(fontsize=11)
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, '6_score_distribution.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print("✓ Saved: 6_score_distribution.png")

def plot_feature_correlations(df, feature_names):
    """Plot feature correlation heatmap."""
    # Get features that exist in dataframe
    available_features = [f for f in feature_names if f in df.columns]
    
    corr_matrix = df[available_features + ['FLAG']].corr()
    
    fig, ax = plt.subplots(figsize=(14, 12))
    mask = np.triu(np.ones_like(corr_matrix, dtype=bool))
    sns.heatmap(corr_matrix, mask=mask, annot=True, fmt='.2f', cmap='RdYlBu_r',
                center=0, ax=ax, annot_kws={'size': 8})
    ax.set_title('Feature Correlation Matrix', fontsize=14, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, '7_feature_correlations.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print("✓ Saved: 7_feature_correlations.png")

def plot_model_metrics_summary():
    """Create a summary metrics chart."""
    # Metrics from training
    metrics = {
        'Accuracy': 0.9596,
        'Precision': 0.9462,
        'Recall': 0.9011,
        'F1 Score': 0.9231,
        'ROC-AUC': 0.9892
    }
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    colors = ['#3498db', '#2ecc71', '#f39c12', '#9b59b6', '#e74c3c']
    bars = ax.bar(metrics.keys(), metrics.values(), color=colors, edgecolor='white', linewidth=2)
    
    ax.set_ylim(0, 1.1)
    ax.set_ylabel('Score', fontsize=12)
    ax.set_title('Model Performance Metrics', fontsize=14, fontweight='bold')
    
    # Add value labels
    for bar, val in zip(bars, metrics.values()):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02, 
                f'{val:.2%}', ha='center', fontsize=12, fontweight='bold')
    
    ax.axhline(y=0.9, color='gray', linestyle='--', alpha=0.5, label='90% threshold')
    ax.legend()
    ax.grid(True, alpha=0.3, axis='y')
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, '8_model_metrics.png'), dpi=150, bbox_inches='tight')
    plt.close()
    print("✓ Saved: 8_model_metrics.png")

def main():
    print("=" * 60)
    print("GENERATING ML MODEL VISUALIZATIONS")
    print("=" * 60)
    
    # Load data and model
    print("\nLoading data and model...")
    df, model, scaler, feature_names = load_data_and_model()
    print(f"Dataset: {len(df)} samples")
    print(f"Features: {len(feature_names)}")
    
    # Prepare test data
    available_features = [f for f in feature_names if f in df.columns]
    X = df[available_features].fillna(0).replace([np.inf, -np.inf], 0)
    y = df['FLAG']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print(f"\nGenerating visualizations in: {OUTPUT_DIR}")
    print("-" * 60)
    
    # Generate all plots
    plot_class_distribution(df)
    plot_feature_importance(model, available_features)
    plot_confusion_matrix(model, X_test, y_test, scaler)
    plot_roc_curve(model, X_test, y_test, scaler)
    plot_precision_recall_curve(model, X_test, y_test, scaler)
    plot_score_distribution(model, X_test, y_test, scaler)
    plot_feature_correlations(df, feature_names)
    plot_model_metrics_summary()
    
    print("-" * 60)
    print(f"\n✓ All visualizations saved to: {OUTPUT_DIR}")
    print("\nGenerated files:")
    for f in sorted(os.listdir(OUTPUT_DIR)):
        if f.endswith('.png'):
            print(f"  - {f}")

if __name__ == '__main__':
    main()
