FEATURE_NAMES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Fwd Packet Length Max",
    "Bwd Packet Length Max",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Average Packet Size",
]

LABEL_COLUMN = "Label"

# CIC-IDS2017 PortScan day labels observed in this repository.
LABEL_MAPPING = {
    "BENIGN": 0,
    "PortScan": 1,
}

CLASS_NAMES = {
    0: "BENIGN",
    1: "ATTACK",
}
