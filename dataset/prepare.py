
import pandas as pd

df = pd.read_csv("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")

FEATURES = [
    'Destination Port', 'Flow Duration',
    'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Fwd Packet Length Max',
    'Bwd Packet Length Max', 'Flow Bytes/s',
    'Flow Packets/s', 'Average Packet Size'
]

df.columns = df.columns.str.strip()
df = df[FEATURES + ['Label']].copy()
df.replace([float('inf'), float('-inf')], pd.NA, inplace=True)
df.dropna(inplace=True)

df['Label'] = df['Label'].apply(lambda x: 0 if 'BENIGN' in str(x) else 1)

normal = df[df['Label'] == 0].sample(1000, random_state=42)
attack = df[df['Label'] == 1].sample(1000, random_state=42)

final = pd.concat([normal, attack]).sample(frac=1, random_state=42)
final.to_csv("final_dataset.csv", index=False)
print(f"✅ Dataset ready: {len(final)} rows")
print(final['Label'].value_counts())