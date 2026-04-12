from datetime import datetime

LOG_FILE = "alerts/alerts.log"

def send_alert(message, source="SYSTEM"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert = f"[{timestamp}] [{source}] {message}"
    print(alert)
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(alert + "\n")