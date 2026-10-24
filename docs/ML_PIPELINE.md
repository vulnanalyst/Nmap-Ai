# Machine Learning Pipeline & Threat Classification

## 1. Dataset Origin & Description

The intrusion detection pipeline is trained on network telemetry from the **CIC-IDS2017 Benchmark Dataset** (Canadian Institute for Cybersecurity), specifically the `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` capture.

- **Raw Capture**: 286,467 network flows generated using CICFlowMeter.
- **Classes**: `BENIGN` (127,537 flows) and `PortScan` (158,930 flows).
- **Curated Lab Subset (`final_dataset.csv`)**: 2,000 stratified, balanced rows for reproducible, fast, and resource-efficient lab training.

---

## 2. Feature Schema & Preprocessing

The model uses a strict 10-feature schema:

| Index | Feature Name | Unit / Description |
|:-----:|:-------------|:-------------------|
| 0 | `Destination Port` | Target TCP/UDP port (0 - 65535) |
| 1 | `Flow Duration` | Total flow lifetime in microseconds ($\mu s$) |
| 2 | `Total Fwd Packets` | Count of packets sent in the forward direction |
| 3 | `Total Backward Packets` | Count of packets sent in the backward direction |
| 4 | `Total Length of Fwd Packets` | Total bytes in forward packet payloads |
| 5 | `Fwd Packet Length Max` | Maximum forward packet payload size in bytes |
| 6 | `Bwd Packet Length Max` | Maximum backward packet payload size in bytes |
| 7 | `Flow Bytes/s` | Aggregate byte transmission rate per second |
| 8 | `Flow Packets/s` | Aggregate packet rate per second |
| 9 | `Average Packet Size` | Mean byte length across all packets in the flow |

### Preprocessing & Data Hygiene
- **Infinite & NaN Handling**: Infinite values (`np.inf`, `-np.inf`) and nulls are cleaned.
- **Label Encoding**: Binary mapping `{'BENIGN': 0, 'PortScan': 1}`.
- **Leakage Prevention**: Stratified 80/20 train/test split is applied after deduplication.
- **Input Validation**: Inference requests are verified against `FEATURE_NAMES`. Missing features raise `FeatureSchemaError` (HTTP 400). Reordered dictionaries are safely aligned to the training schema order.

---

## 3. Training & Evaluation Results

### Model Specifications
- **Classifier**: `RandomForestClassifier` (Scikit-Learn)
- **Estimators**: 200 trees
- **Class Weighting**: `balanced_subsample`
- **Reproducibility Seed**: 42

### Test Set Performance (400 Stratified Samples)

| Metric | Score |
|:-------|:-----:|
| **Macro F1-Score** | **99.75%** |
| **Balanced Accuracy** | **99.75%** |
| **Macro Precision** | **99.75%** |
| **Macro Recall** | **99.75%** |

### Confusion Matrix

```text
                  Predicted BENIGN    Predicted ATTACK
Actual BENIGN            200                 0
Actual ATTACK              1               199
```

- **True Negatives**: 200 (100.0% specificity)
- **False Positives**: 0 (0.0% false positive rate on test set)
- **False Negatives**: 1
- **True Positives**: 199 (99.5% sensitivity)

### Feature Importance Ranking (Gini Impurity Reduction)

```text
1. Fwd Packet Length Max       [24.55%]  ████████████
2. Total Length of Fwd Packets [23.41%]  ███████████▌
3. Average Packet Size         [19.26%]  █████████▌
4. Flow Duration               [ 7.78%]  ████
5. Flow Packets/s              [ 6.17%]  ███
6. Flow Bytes/s                [ 5.54%]  ██▌
7. Bwd Packet Length Max       [ 4.74%]  ██
8. Total Fwd Packets           [ 4.64%]  ██
9. Destination Port            [ 3.33%]  █▌
10. Total Backward Packets     [ 0.58%]  ▎
```

---

## 4. Reproducing Training

To retrain the model and generate versioned artifacts:

```bash
# Activate virtual environment
source .venv/bin/activate

# Execute training pipeline
python -m ml.training.train
```

This generates three versioned files in `ml/artifacts/`:
1. `<version>.joblib`: Serialized Scikit-Learn model.
2. `<version>.schema.json`: Frozen feature names and class ordering metadata.
3. `<version>.metrics.json`: Full evaluation results and confusion matrix.
4. Updates `latest.json` pointer.

---

## 5. Live Inference & Operational Limitations

### Explicit Disclaimer
Offline benchmark evaluation (CIC-IDS2017) does not guarantee identical accuracy on live lab traffic. Network topologies, MTU sizes, and application traffic profiles vary between environments.

### Incomplete Flow Protection
Packet sniffers often capture single SYN packets before a full connection flow develops. In the Nmap-AI platform:
- If a flow has fewer than 2 packets or missing metrics, inference is **skipped** with status `skipped_insufficient`.
- The platform never fabricates constants (such as inserting `1000.0` or `1.0`) to force an inference result.
