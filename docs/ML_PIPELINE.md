# Flow classification pipeline

The optional flow classifier provides a PortScan-vs-benign signal for sufficiently complete flow telemetry. It does not replace Nmap, establish that a host is compromised, or prove malicious intent.

## Dataset and training

The training pipeline reads the prepared CIC-IDS2017-derived dataset at `dataset/final_dataset.csv`. The raw source file and preparation tool are retained in `dataset/`. Run training locally with:

```bash
source .venv/bin/activate
python -m ml.training.train
```

Training evaluates the selected model on a stratified holdout split and writes versioned model, schema, and metrics files under `ml/artifacts/`, plus a `latest.json` pointer. Metrics depend on the data and run; the saved evaluation is an offline benchmark, not expected production performance.

## Feature contract

Inference accepts exactly these features in the order defined by `ml/preprocessing/schema.py`:

| Feature | Meaning |
|---|---|
| `Destination Port` | Flow destination port |
| `Flow Duration` | Flow duration in microseconds |
| `Total Fwd Packets` | Forward packet count |
| `Total Backward Packets` | Reverse packet count |
| `Total Length of Fwd Packets` | Forward packet bytes |
| `Fwd Packet Length Max` | Largest forward packet |
| `Bwd Packet Length Max` | Largest reverse packet |
| `Flow Bytes/s` | Bytes per second |
| `Flow Packets/s` | Packets per second |
| `Average Packet Size` | Mean packet length |

The API validates feature names, order, count, and finite numeric values. Flow aggregation marks insufficient inputs as skipped; it does not fill missing features with constants.

## Limitations

- CIC-IDS2017 was collected in a benchmark environment; live lab traffic can differ substantially.
- This model classifies feature vectors, not Nmap banners or CVEs.
- The current TCP telemetry receiver requires an external authorized capture source and optional Scapy parsing.
- Prediction confidence is a model output, not the probability that an attack occurred.
