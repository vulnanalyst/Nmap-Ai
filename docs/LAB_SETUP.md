# Lab Setup Guide — Kali Linux & Windows 10 Target

This guide details how to build an authorized cybersecurity testing lab to run live scans, capture network traffic, and evaluate the Nmap-AI Security Intelligence Platform.

---

## 1. Lab Architecture & Network Topology

```text
+------------------------------+             +------------------------------+
|     Kali Linux (Scanner)     |             |    Windows 10 Lab Target     |
|  - Nmap Scanner              |             |  - SMB Service (Port 445)    |
|  - Nmap-AI Backend & UI      |  Host-Only  |  - RDP Service (Port 3389)   |
|  - ML Inference Engine       |<----------->|  - Local Lab Services        |
|  IP: [Configurable]          |   Network   |  IP: [Configurable]          |
|  e.g., 192.168.56.10/24      |             |  e.g., 192.168.56.20/24      |
+------------------------------+             +------------------------------+
```

> [!IMPORTANT]
> **Safety Notice**: This lab must be operated exclusively in an isolated virtual network (Host-Only or Internal Network in VirtualBox/VMware/Proxmox). Never scan public or unauthorized IP addresses.

---

## 2. Windows 10 Target Configuration

### A. Network Setup
1. Configure the network adapter to **Host-Only** or **Internal Network**.
2. Set a static IP or observe assigned DHCP IP (e.g., `192.168.56.20`).
3. Verify connectivity by pinging between Kali and Windows.

### B. Enable Target Services for Scanning
1. **Enable SMBv2/v3**:
   - Open PowerShell as Administrator:
     ```powershell
     Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
     ```
2. **Enable Remote Desktop (RDP)**:
   - In Windows Settings -> **System** -> **Remote Desktop** -> Toggle **Enable Remote Desktop**.
3. **Firewall Rules for Testing**:
   - In PowerShell (Administrator), allow incoming TCP on ports 445 and 3389 from the lab subnet:
     ```powershell
     New-NetFirewallRule -DisplayName "Lab-SMB-In" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow
     New-NetFirewallRule -DisplayName "Lab-RDP-In" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow
     ```

---

## 3. Kali Linux Scanner & Platform Configuration

### A. Install Dependencies
```bash
# Update package lists and install Nmap
sudo apt update
sudo apt install -y nmap libpcap-dev

# Verify Nmap installation
nmap -V
```

### B. Configure Platform Allowlist
1. Start the Nmap-AI backend:
   ```bash
   python3 main.py
   ```
2. Navigate to `http://localhost:5173/settings`.
3. Under **Authorized Lab Machine Identities**:
   - Set **Scanner Display Name**: `Kali Linux Lab`
   - Set **Scanner Interface IP**: (e.g. `192.168.56.10`)
   - Set **Target Display Name**: `Windows 10 Victim`
   - Set **Target Host IP**: (e.g. `192.168.56.20`)
4. Under **Authorized Target CIDR Allowlist**:
   - Add your lab subnet (e.g. `192.168.56.0/24`).

---

## 4. Running Authorized Scans

### Profile 1: Host Discovery
```bash
# Checks reachability without port probing
nmap -sn 192.168.56.20 -oX data/scans/discovery.xml
```

### Profile 2: Service Version Detection
```bash
# Full version detection with structured output
nmap -sT -sV -p 1-1024,3389 192.168.56.20 -oX data/scans/services.xml
```

### Profile 3: Cautious Non-Destructive Script Checks
```bash
# Evaluates SMB signing and RDP security without disruption
nmap -sT -sV --script smb2-security-mode,rdp-ntlm-info -p 445,3389 192.168.56.20 -oX data/scans/checks.xml
```

You can execute these directly within the **Scan Management** page or import the resulting `.xml` files via the upload button.

---

## 5. Live Telemetry & Traffic Ingestion

To monitor live packet flows between Kali and Windows:

```bash
# Start the telemetry listener on port 9999
python3 capture/live_monitor.py
```

### Streaming Telemetry from Windows or Remote Probe:
If sending telemetry over TCP:
```python
import socket, struct

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("192.168.56.10", 9999))

# Send length-prefixed raw ethernet frame
frame_bytes = b"..." # raw captured ethernet bytes
header = struct.pack("!I", len(frame_bytes))
sock.sendall(header + frame_bytes)
```

---

## 6. Troubleshooting

| Symptom | Cause | Solution |
|---------|-------|----------|
| `Target is down / 0 hosts up` | Windows Firewall dropping ICMP echo requests | Use `-Pn` flag or allow ICMP echo in Windows Firewall. |
| `Scan rejected: Unauthorized target` | Target IP is not in the allowlist | Add the subnet in `Lab Settings -> Authorized Targets`. |
| `Nmap executable not found` | Nmap is not installed or not in PATH | Run `sudo apt install nmap` or configure `NMAP_AI_NMAP_PATH` in `.env`. |
| `Permission denied for Scapy sniffing` | Raw socket capture requires root/admin | Run capture script with `sudo` or configure Linux capability: `sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)`. |
