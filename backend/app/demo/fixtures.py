from __future__ import annotations

from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session

from backend.app.models import Alert, Finding, Host, ScanJob, Service, TrafficEvent


def seed_demo_data(db: Session) -> dict:
    # Check if demo data already seeded
    existing = db.query(Host).filter_by(data_source="demo").first()
    if existing:
        return {"status": "already_seeded", "message": "Demo data is already present"}

    now = datetime.now(timezone.utc)
    one_hour_ago = now - timedelta(hours=1)
    two_hours_ago = now - timedelta(hours=2)

    # 1. Demo Scan Job
    scan = ScanJob(
        id="demo-scan-001",
        profile="service_version",
        targets="10.0.0.0/24",
        status="completed",
        argv=["nmap", "-sT", "-sV", "--stats-every", "5s", "-oX", "demo.xml", "10.0.0.0/24"],
        dry_run=False,
        data_source="demo",
        progress_pct=100.0,
        nmap_version="7.94",
        created_at=two_hours_ago,
        started_at=two_hours_ago,
        finished_at=two_hours_ago + timedelta(seconds=45),
        duration_seconds=45.2,
        authorized_by="lab-operator (demo)",
        hosts_up=3,
        hosts_down=251,
        ports_open=6,
        ports_closed=120,
        ports_filtered=4,
    )
    db.add(scan)
    db.flush()

    # 2. Demo Hosts
    # Host 1: Windows 10 Target Lab
    win_host = Host(
        scan_id=scan.id,
        ip="10.0.0.45",
        hostname="win10-lab-victim.local",
        mac="00:0C:29:4F:8E:1A",
        mac_vendor="VMware, Inc.",
        state="up",
        os_guess="Microsoft Windows 10 (1909-20H2)",
        os_accuracy=94,
        reason="syn-ack",
        first_seen=two_hours_ago,
        last_seen=now,
        provenance="nmap_xml",
        data_source="demo",
    )
    # Host 2: Linux Lab Server
    lin_host = Host(
        scan_id=scan.id,
        ip="10.0.0.88",
        hostname="ubuntu-lab-srv.local",
        mac="00:0C:29:3B:11:5C",
        mac_vendor="VMware, Inc.",
        state="up",
        os_guess="Linux 5.4 - 5.15",
        os_accuracy=98,
        reason="syn-ack",
        first_seen=two_hours_ago,
        last_seen=now,
        provenance="nmap_xml",
        data_source="demo",
    )
    # Host 3: Lab Gateway
    gw_host = Host(
        scan_id=scan.id,
        ip="10.0.0.1",
        hostname="gateway.lab",
        mac="00:50:56:FE:00:01",
        mac_vendor="VMware, Inc.",
        state="up",
        os_guess="Embedded Linux",
        os_accuracy=82,
        reason="syn-ack",
        first_seen=two_hours_ago,
        last_seen=now,
        provenance="nmap_xml",
        data_source="demo",
    )
    db.add_all([win_host, lin_host, gw_host])
    db.flush()

    # 3. Services for Windows 10
    svc_win_smb = Service(
        host_id=win_host.id,
        protocol="tcp",
        port=445,
        state="open",
        reason="syn-ack",
        name="microsoft-ds",
        product="Windows 10 Enterprise 19041",
        version="microsoft-ds",
        detection_source="nmap-sV",
        data_source="demo",
        scripts=[{"id": "smb2-security-mode", "output": "Message signing enabled but not required"}],
    )
    svc_win_rdp = Service(
        host_id=win_host.id,
        protocol="tcp",
        port=3389,
        state="open",
        reason="syn-ack",
        name="ms-wbt-server",
        product="Microsoft Terminal Services",
        version="10.0.19041",
        detection_source="nmap-sV",
        data_source="demo",
        scripts=[{"id": "rdp-ntlm-info", "output": "NetBIOS computer name: WIN10-LAB"}],
    )
    svc_win_rpc = Service(
        host_id=win_host.id,
        protocol="tcp",
        port=135,
        state="open",
        reason="syn-ack",
        name="msrpc",
        product="Microsoft Windows RPC",
        version=None,
        detection_source="nmap-sV",
        data_source="demo",
    )

    # Services for Linux
    svc_lin_ssh = Service(
        host_id=lin_host.id,
        protocol="tcp",
        port=22,
        state="open",
        reason="syn-ack",
        name="ssh",
        product="OpenSSH",
        version="8.2p1 Ubuntu 4ubuntu0.5",
        detection_source="nmap-sV",
        data_source="demo",
    )
    svc_lin_http = Service(
        host_id=lin_host.id,
        protocol="tcp",
        port=80,
        state="open",
        reason="syn-ack",
        name="http",
        product="Apache httpd",
        version="2.4.41",
        detection_source="nmap-sV",
        data_source="demo",
    )

    # Service for Gateway
    svc_gw_dns = Service(
        host_id=gw_host.id,
        protocol="udp",
        port=53,
        state="open",
        reason="udp-response",
        name="domain",
        product="dnsmasq",
        version="2.80",
        detection_source="nmap-sU",
        data_source="demo",
    )

    db.add_all([svc_win_smb, svc_win_rdp, svc_win_rpc, svc_lin_ssh, svc_lin_http, svc_gw_dns])
    db.flush()

    # 4. Findings
    f1 = Finding(
        id="demo-finding-smb-signing",
        scan_id=scan.id,
        host_ip="10.0.0.45",
        port=445,
        protocol="tcp",
        service_name="microsoft-ds",
        product="Windows 10 Enterprise",
        version="19041",
        title="SMB Signing Disabled or Not Required",
        cve="CVE-2016-2115",
        cvss=5.9,
        severity="medium",
        evidence={
            "script": "smb2-security-mode",
            "output": "Message signing enabled but not required. Allows NTLM relay attacks in lab environments.",
            "port": 445,
            "provenance": "nmap-safe-scripts",
        },
        detection_source="nmap_script",
        confidence=0.95,
        validation_status="confirmed_by_check",
        impact="An attacker situated on the local segment could relay NTLM authentication to execute unauthorized actions.",
        remediation="Enforce SMB message signing via Windows Group Policy (GPO): 'Digitally sign communications (always)'.",
        reference_url="https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing",
        first_observed=two_hours_ago,
        last_observed=now,
        workflow_status="investigating",
        risk_score=6.2,
        risk_breakdown={
            "cvss_component": 2.65,
            "exposure_component": 1.5,
            "confidence_component": 0.95,
            "ml_anomaly_signal": 0.5,
            "freshness_factor": 1.0,
        },
        data_source="demo",
        fingerprint="demo:10.0.0.45:445:smb-signing",
    )

    f2 = Finding(
        id="demo-finding-rdp-exposure",
        scan_id=scan.id,
        host_ip="10.0.0.45",
        port=3389,
        protocol="tcp",
        service_name="ms-wbt-server",
        product="Microsoft Terminal Services",
        version="10.0.19041",
        title="Exposed Remote Desktop Protocol (RDP) Service",
        cve=None,
        cvss=4.3,
        severity="low",
        evidence={
            "port": 3389,
            "state": "open",
            "note": "RDP observed reachable. Service banner verified without credential exposure.",
        },
        detection_source="nmap_port_observation",
        confidence=0.90,
        validation_status="suspected",
        impact="Direct RDP exposure increases risk of brute-force and credential spraying against lab accounts.",
        remediation="Restrict RDP port 3389 to authorized administrator management IP via Windows Defender Firewall.",
        reference_url="https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final",
        first_observed=two_hours_ago,
        last_observed=now,
        workflow_status="new",
        risk_score=4.1,
        risk_breakdown={
            "cvss_component": 1.9,
            "exposure_component": 1.2,
            "confidence_component": 0.9,
            "ml_anomaly_signal": 0.1,
            "freshness_factor": 1.0,
        },
        data_source="demo",
        fingerprint="demo:10.0.0.45:3389:rdp-exposure",
    )

    f3 = Finding(
        id="demo-finding-apache-version",
        scan_id=scan.id,
        host_ip="10.0.0.88",
        port=80,
        protocol="tcp",
        service_name="http",
        product="Apache httpd",
        version="2.4.41",
        title="Apache HTTP Server 2.4.41 Version Disclosure",
        cve="CVE-2021-40438",
        cvss=7.5,
        severity="high",
        evidence={
            "port": 80,
            "banner": "Apache/2.4.41 (Ubuntu)",
            "catalog_match": "Affects Apache httpd <= 2.4.48 (mod_proxy SSRF). Configuration not confirmed without check.",
        },
        detection_source="cve_catalog_match",
        confidence=0.75,
        validation_status="potential_issue",
        impact="Potential Server-Side Request Forgery (SSRF) if mod_proxy is active and configured.",
        remediation="Upgrade Apache package to 2.4.49+ or ensure mod_proxy is not loaded unnecessarily (`a2dismod proxy`).",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2021-40438",
        first_observed=two_hours_ago,
        last_observed=now,
        workflow_status="confirmed",
        risk_score=7.1,
        risk_breakdown={
            "cvss_component": 3.38,
            "exposure_component": 2.0,
            "confidence_component": 0.75,
            "ml_anomaly_signal": 0.6,
            "freshness_factor": 1.0,
        },
        data_source="demo",
        fingerprint="demo:10.0.0.88:80:apache-ssrf",
    )

    db.add_all([f1, f2, f3])

    # 5. Alerts
    a1 = Alert(
        timestamp=now - timedelta(minutes=15),
        src_addr="10.0.0.12",
        dst_addr="10.0.0.45",
        src_port=54210,
        dst_port=445,
        protocol="TCP",
        detection_method="ml_classification",
        rule_or_model="rf-model-v1",
        evidence_ref="flow-2026-demo-01",
        severity="high",
        confidence=0.984,
        title="ML-IDS: PortScan Flow Pattern Detected",
        message="Classified network flow as PortScan attack with 98.4% model probability (RandomForest).",
        status="open",
        fingerprint="demo:ml:10.0.0.12:10.0.0.45",
        data_source="demo",
        extra={"features": {"Destination Port": 445, "Flow Packets/s": 420.5, "Flow Bytes/s": 24500.0}},
    )
    a2 = Alert(
        timestamp=now - timedelta(minutes=32),
        src_addr="10.0.0.12",
        dst_addr="10.0.0.45",
        src_port=53102,
        dst_port=3389,
        protocol="TCP",
        detection_method="signature",
        rule_or_model="RULE-SENSITIVE-SERVICE",
        evidence_ref="event-demo-02",
        severity="medium",
        confidence=0.90,
        title="Signature-IDS: Sensitive Service Connection",
        message="Observed TCP SYN to RDP service port 3389 from unlisted scanner endpoint.",
        status="acknowledged",
        fingerprint="demo:sig:10.0.0.12:3389",
        data_source="demo",
    )
    a3 = Alert(
        timestamp=now - timedelta(minutes=45),
        src_addr="10.0.0.12",
        dst_addr="10.0.0.88",
        src_port=48920,
        dst_port=80,
        protocol="TCP",
        detection_method="rate_anomaly",
        rule_or_model="RATE-BURST-CHECK",
        evidence_ref="flow-rate-03",
        severity="low",
        confidence=0.80,
        title="Rate Anomaly: Rapid Sequential Port Probes",
        message="Observed 12 SYN connection attempts within a 2-second sliding window.",
        status="resolved",
        fingerprint="demo:rate:10.0.0.12:10.0.0.88",
        data_source="demo",
    )
    db.add_all([a1, a2, a3])

    # 6. Traffic Events
    e1 = TrafficEvent(
        timestamp=now - timedelta(minutes=15),
        adapter="tcp-framed",
        src_addr="10.0.0.12",
        dst_addr="10.0.0.45",
        src_port=54210,
        dst_port=445,
        protocol="TCP",
        packet_length=64,
        features={
            "Destination Port": 445,
            "Flow Duration": 120500,
            "Total Fwd Packets": 15,
            "Total Backward Packets": 12,
            "Flow Bytes/s": 24500.0,
            "Flow Packets/s": 420.5,
        },
        feature_complete=True,
        ml_status="classified",
        ml_label="ATTACK",
        ml_confidence=0.984,
        model_version="rf-20261024T183348Z",
        signatures=["SENSITIVE_PORT_445"],
        data_source="demo",
    )
    e2 = TrafficEvent(
        timestamp=now - timedelta(minutes=18),
        adapter="tcp-framed",
        src_addr="10.0.0.88",
        dst_addr="10.0.0.1",
        src_port=45122,
        dst_port=53,
        protocol="UDP",
        packet_length=72,
        features={"Destination Port": 53, "Flow Duration": 2400},
        feature_complete=False,
        ml_status="skipped_insufficient",
        data_source="demo",
    )
    db.add_all([e1, e2])

    db.commit()
    return {"status": "seeded", "message": "Demo lab data successfully populated"}


def clear_demo_data(db: Session) -> dict:
    db.query(Alert).filter_by(data_source="demo").delete()
    db.query(TrafficEvent).filter_by(data_source="demo").delete()
    db.query(Finding).filter_by(data_source="demo").delete()
    db.query(Service).filter_by(data_source="demo").delete()
    db.query(Host).filter_by(data_source="demo").delete()
    db.query(ScanJob).filter_by(data_source="demo").delete()
    db.commit()
    return {"status": "cleared", "message": "Demo lab data removed"}
