"""
Merge Kaggle Benign Data with Real-World Dataset
=================================================
The Kaggle dataset has 7,662 benign addresses.
We'll add these to our real-world dataset to balance it.
"""

import pandas as pd
import numpy as np
import os

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
KAGGLE_FILE = os.path.join(DATA_DIR, 'transaction_dataset.csv')
REALWORLD_FILE = os.path.join(DATA_DIR, 'real_world_dataset.csv')
OUTPUT_FILE = os.path.join(DATA_DIR, 'combined_dataset.csv')

def main():
    print("=" * 60)
    print("MERGING KAGGLE BENIGN DATA WITH REAL-WORLD DATA")
    print("=" * 60)
    
    # Load datasets
    kaggle_df = pd.read_csv(KAGGLE_FILE)
    realworld_df = pd.read_csv(REALWORLD_FILE)
    
    print(f"\nKaggle dataset: {len(kaggle_df)} samples")
    print(f"  - Fraud (1): {(kaggle_df['FLAG'] == 1).sum()}")
    print(f"  - Benign (0): {(kaggle_df['FLAG'] == 0).sum()}")
    
    print(f"\nReal-world dataset: {len(realworld_df)} samples")
    print(f"  - Fraud (1): {(realworld_df['FLAG'] == 1).sum()}")
    print(f"  - Benign (0): {(realworld_df['FLAG'] == 0).sum()}")
    
    # Get common features between datasets
    kaggle_cols = set(kaggle_df.columns)
    realworld_cols = set(realworld_df.columns)
    common_cols = kaggle_cols & realworld_cols
    
    print(f"\nCommon features: {len(common_cols)}")
    
    # Features we need for training (from real-world model)
    required_features = [
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
        'FLAG'
    ]
    
    # Check which features exist in Kaggle
    kaggle_features = [f for f in required_features if f in kaggle_df.columns]
    print(f"Matching features in Kaggle: {len(kaggle_features)}")
    
    # Get benign samples from Kaggle (only those with FLAG=0)
    kaggle_benign = kaggle_df[kaggle_df['FLAG'] == 0].copy()
    print(f"\nKaggle benign samples: {len(kaggle_benign)}")
    
    # Use ALL Kaggle data (both fraud and benign)
    # This gives us massive training set: 2179 + 652 fraud, 7662 + 37 benign
    kaggle_sample = kaggle_df  # Use ALL samples, not just benign
    
    # Select only common features
    features_to_use = [f for f in kaggle_features if f in realworld_df.columns]
    
    # Add missing features to kaggle sample with zeros
    for col in realworld_df.columns:
        if col not in kaggle_sample.columns:
            kaggle_sample[col] = 0
    
    # Add source column
    realworld_df['source'] = 'real_world'
    kaggle_sample['source'] = 'kaggle'
    
    # Combine datasets
    combined = pd.concat([realworld_df, kaggle_sample[realworld_df.columns]], ignore_index=True)
    
    print(f"\n✓ Combined dataset: {len(combined)} samples")
    print(f"  - Fraud (1): {(combined['FLAG'] == 1).sum()}")
    print(f"  - Benign (0): {(combined['FLAG'] == 0).sum()}")
    print(f"  - Fraud ratio: {(combined['FLAG'] == 1).sum() / len(combined) * 100:.1f}%")
    
    # Save
    combined.to_csv(OUTPUT_FILE, index=False)
    print(f"\n✓ Saved to: {OUTPUT_FILE}")
    print(f"\nNow run: python train_combined_model.py")

if __name__ == '__main__':
    main()
