# Web3 Risk Guard - ML Component

## Hybrid Scoring Model

This folder contains the machine learning component for the Web3 Risk Guard extension.

### Architecture

```
Final Score = 0.4 × ML_model_score + 0.3 × darklist_match + 0.3 × heuristic_score
```

### Components

1. **ML Model** - Trained on Kaggle Ethereum Fraud Detection dataset
2. **Darklist Lookup** - MyEtherWallet address blacklist
3. **Heuristics** - Rule-based detection (approve, permit, setApprovalForAll)

---

## Setup Instructions

### Step 1: Download Dataset

1. Go to: https://www.kaggle.com/datasets/vagifa/ethereum-frauddetection-dataset
2. Download `transaction_dataset.csv`
3. Place it in this folder: `ml/data/transaction_dataset.csv`

### Step 2: Download Darklist

```bash
curl -o data/darklist.json https://raw.githubusercontent.com/MyEtherWallet/ethereum-lists/master/src/addresses/addresses-darklist.json
```

### Step 3: Train Model

```bash
python train_model.py
```

### Step 4: Export for Browser

The trained model will be exported to ONNX format for browser inference.

---

## File Structure

```
ml/
├── data/
│   ├── transaction_dataset.csv  (from Kaggle)
│   └── darklist.json            (from MyEtherWallet)
├── train_model.py               (training script)
├── model.onnx                   (exported model)
└── README.md
```
