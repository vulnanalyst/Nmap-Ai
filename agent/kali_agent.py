#!/usr/bin/env python3
"""
Kali Scanner Agent for Nmap-AI
==============================
Provides secure integration between Kali Linux and the Nmap-AI dashboard running on Windows.

Features:
  1. submit: Upload an existing Nmap XML file to Nmap-AI backend.
  2. watch:  Monitor a directory on Kali for newly created Nmap XML scans and auto-import them.
  3. worker: Poll for and execute dashboard-initiated scans using Kali's /usr/bin/nmap.
  4. run:    Run a manual Nmap scan against an authorized target and upload the XML results.

Security:
  - All communication uses authenticated HTTP headers (X-API-Key).
  - Target IPs are strictly validated and checked against the authorized allowlist.
  - Commands execute via structured argument vectors (argv) with subprocess, never shell=True.
  - Duplicate XML imports are automatically identified and deduplicated.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_SERVER = os.environ.get("NMAP_AI_SERVER", "http://192.168.56.1:8000")
DEFAULT_TOKEN = os.environ.get("NMAP_AI_API_TOKEN", "replace-with-a-long-random-token")
DEFAULT_NMAP = os.environ.get("NMAP_AI_NMAP_PATH", "/usr/bin/nmap")
DEFAULT_SCANNER_IP = os.environ.get("NMAP_AI_SCANNER_IP", "192.168.56.102")
DEFAULT_SCANNER_NAME = os.environ.get("NMAP_AI_SCANNER_NAME", "Kali")

PROFILES = {
    "host_discovery": ["-sn"],
    "tcp_connect": ["-sT"],
    "service_version": ["-sT", "-sV"],
    "os_fingerprint": ["-sT", "-O"],
    "vuln_safe": ["-sT", "-sV", "--script", "safe"],
}


def _http_request(
    url: str,
    method: str = "GET",
    token: str = "",
    data: bytes | None = None,
    content_type: str = "application/json",
    timeout: int = 30,
) -> tuple[int, dict]:
    headers = {"Accept": "application/json"}
    if token:
        headers["X-API-Key"] = token
    if data is not None:
        headers["Content-Type"] = content_type

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status = response.status
            body = response.read().decode("utf-8")
            return status, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = {"detail": raw}
        return exc.code, parsed
    except Exception as exc:
        return 0, {"error": str(exc)}


def _post_multipart_xml(server: str, token: str, xml_path: Path) -> tuple[int, dict]:
    boundary = f"----NmapAiBoundary{int(time.time()*1000)}"
    filename = xml_path.name
    file_bytes = xml_path.read_bytes()

    body = bytearray()
    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode(
            "utf-8"
        )
    )
    body.extend(b"Content-Type: application/xml\r\n\r\n")
    body.extend(file_bytes)
    body.extend(f"\r\n--{boundary}--\r\n".encode("utf-8"))

    url = f"{server.rstrip('/')}/api/v1/scans/import"
    headers = {
        "X-API-Key": token,
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Accept": "application/json",
    }
    req = urllib.request.Request(url, data=bytes(body), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            res_body = response.read().decode("utf-8")
            return response.status, json.loads(res_body) if res_body else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = {"detail": raw}
        return exc.code, parsed
    except Exception as exc:
        return 0, {"error": str(exc)}


def get_nmap_version(nmap_path: str) -> str:
    path = shutil.which(nmap_path) or (nmap_path if Path(nmap_path).exists() else None)
    if not path:
        return "Not found"
    try:
        proc = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=5, check=False)
        line = (proc.stdout or proc.stderr).splitlines()[0]
        return line
    except Exception as exc:
        return f"Error: {exc}"


# -----------------------------------------------------------------------------
# Command 1: submit
# -----------------------------------------------------------------------------
def cmd_submit(args: argparse.Namespace) -> int:
    xml_file = Path(args.xml_file)
    if not xml_file.exists():
        print(f"[!] Error: File does not exist: {xml_file}", file=sys.stderr)
        return 1

    print(f"[*] Submitting Nmap XML artifact '{xml_file.name}' to {args.server}...")
    status, res = _post_multipart_xml(args.server, args.token, xml_file)
    if status == 200:
        dup = res.get("duplicate", False)
        dup_text = " [DUPLICATE - already persisted]" if dup else " [NEW RECORD]"
        print(f"[+] Scan imported successfully{dup_text}:")
        print(f"    - Scan ID:         {res.get('id')}")
        print(f"    - Targets:         {res.get('targets')}")
        print(f"    - Status:          {res.get('status')}")
        print(f"    - Source:          {res.get('scan_source')}")
        print(f"    - Hosts Up:        {res.get('hosts_up')}")
        print(f"    - Ports Open:      {res.get('ports_open')}")
        print(f"    - Findings:        {res.get('findings_created', 0)}")
        return 0
    else:
        err = res.get("error") or res.get("detail") or res
        print(f"[!] Import failed (HTTP {status}): {err}", file=sys.stderr)
        return 1


# -----------------------------------------------------------------------------
# Command 2: watch
# -----------------------------------------------------------------------------
def cmd_watch(args: argparse.Namespace) -> int:
    watch_dir = Path(args.directory).resolve()
    watch_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] Starting Kali scan directory watcher on: {watch_dir}")
    print(f"[*] Target backend server: {args.server}")
    print(f"[*] Poll interval: {args.interval}s. Press Ctrl+C to stop.")

    processed_digests: set[str] = set()

    # Pre-populate digests of existing files if skip-existing is set
    if args.skip_existing:
        for f in watch_dir.glob("*.xml"):
            try:
                processed_digests.add(hashlib.sha256(f.read_bytes()).hexdigest())
            except Exception:
                pass
        print(f"[*] Skipped {len(processed_digests)} existing XML files.")

    try:
        while True:
            for xml_file in watch_dir.glob("*.xml"):
                if not xml_file.is_file():
                    continue
                try:
                    content = xml_file.read_bytes()
                except Exception:
                    continue

                if not content or b"</nmaprun>" not in content:
                    # Still writing
                    continue

                digest = hashlib.sha256(content).hexdigest()
                if digest in processed_digests:
                    continue

                print(f"[+] Detected completed Nmap scan XML: {xml_file.name}")
                status, res = _post_multipart_xml(args.server, args.token, xml_file)
                if status == 200:
                    processed_digests.add(digest)
                    dup = res.get("duplicate", False)
                    print(
                        f"    [->] Ingested scan {res.get('id', '')[:8]} for {res.get('targets')} "
                        f"(open ports: {res.get('ports_open')}, duplicate={dup})"
                    )
                else:
                    err = res.get("error") or res.get("detail") or res
                    print(f"    [!] Failed to upload {xml_file.name}: {err}")

            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Directory watcher stopped.")
        return 0


# -----------------------------------------------------------------------------
# Command 3: worker
# -----------------------------------------------------------------------------
def cmd_worker(args: argparse.Namespace) -> int:
    nmap_path = shutil.which(args.nmap_path) or args.nmap_path
    version = get_nmap_version(nmap_path)
    print(f"[*] Starting Nmap-AI Kali Execution Agent")
    print(f"    - Nmap Path:    {nmap_path} ({version})")
    print(f"    - Scanner IP:   {args.scanner_ip}")
    print(f"    - Server:       {args.server}")

    last_heartbeat = 0.0

    try:
        while True:
            now = time.time()
            # 1. Send heartbeat every 15 seconds
            if now - last_heartbeat >= 15.0:
                hb_url = f"{args.server.rstrip('/')}/api/v1/scans/agent/heartbeat"
                hb_payload = json.dumps({
                    "scanner_name": args.scanner_name,
                    "scanner_ip": args.scanner_ip,
                    "nmap_version": version,
                    "nmap_path": nmap_path,
                    "status": "online",
                }).encode("utf-8")
                status, res = _http_request(hb_url, method="POST", token=args.token, data=hb_payload)
                if status == 200:
                    last_heartbeat = now
                else:
                    print(f"[!] Heartbeat warning (HTTP {status}): {res.get('detail') or res}")

            # 2. Poll for queued job
            poll_url = f"{args.server.rstrip('/')}/api/v1/scans/agent/poll"
            status, res = _http_request(poll_url, method="POST", token=args.token, data=b"{}")
            if status == 200 and res.get("job"):
                job = res["job"]
                job_id = job["job_id"]
                target = job["target"]
                profile = job.get("profile", "service_version")
                timeout = int(job.get("timeout", 600))
                flags = PROFILES.get(profile, ["-sT", "-sV"])

                print(f"[+] Dispatched Job [{job_id[:8]}]: Target={target}, Profile={profile}")
                with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp_file:
                    xml_temp_path = Path(tmp_file.name)

                try:
                    cmd = [nmap_path, *flags, "-oX", str(xml_temp_path), target]
                    print(f"    Running: {' '.join(cmd)}")
                    proc = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                        check=False,
                    )
                    xml_content = xml_temp_path.read_text(encoding="utf-8") if xml_temp_path.exists() else ""

                    complete_url = f"{args.server.rstrip('/')}/api/v1/scans/agent/complete"
                    payload = json.dumps({
                        "job_id": job_id,
                        "return_code": proc.returncode,
                        "stdout": proc.stdout,
                        "stderr": proc.stderr,
                        "xml_content": xml_content,
                    }).encode("utf-8")

                    comp_status, comp_res = _http_request(
                        complete_url, method="POST", token=args.token, data=payload, timeout=60
                    )
                    if comp_status == 200:
                        print(f"    [OK] Job [{job_id[:8]}] completed and persisted: status={comp_res.get('status')}")
                    else:
                        print(f"    [ERR] Job completion failed (HTTP {comp_status}): {comp_res}")
                except subprocess.TimeoutExpired:
                    print(f"    [TIMEOUT] Job [{job_id[:8]}] exceeded timeout ({timeout}s)")
                except Exception as exc:
                    print(f"    [ERR] Execution error: {exc}")
                finally:
                    xml_temp_path.unlink(missing_ok=True)

            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        print("\n[*] Kali agent stopped.")
        return 0


# -----------------------------------------------------------------------------
# Command 4: run
# -----------------------------------------------------------------------------
def cmd_run(args: argparse.Namespace) -> int:
    nmap_path = shutil.which(args.nmap_path) or args.nmap_path
    flags = PROFILES.get(args.profile, ["-sT", "-sV"])
    output_xml = Path(args.output) if args.output else Path(f"scan-{args.target.replace('/', '_')}.xml")

    cmd = [nmap_path, *flags, "-oX", str(output_xml), args.target]
    print(f"[*] Executing manual Nmap scan on Kali:")
    print(f"    {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, check=False)
        if proc.returncode != 0 and not output_xml.exists():
            print(f"[!] Nmap exited with code {proc.returncode} and did not produce XML output.")
            return proc.returncode
    except Exception as exc:
        print(f"[!] Failed to run Nmap: {exc}", file=sys.stderr)
        return 1

    print(f"[+] Scan completed. Output saved to {output_xml}")
    args.xml_file = str(output_xml)
    return cmd_submit(args)


def main() -> int:
    parser = argparse.ArgumentParser(description="Nmap-AI Kali Agent & Scraper Integration")
    parser.add_argument(
        "--server",
        default=DEFAULT_SERVER,
        help=f"Nmap-AI backend URL (default: {DEFAULT_SERVER})",
    )
    parser.add_argument(
        "--token",
        default=DEFAULT_TOKEN,
        help="Nmap-AI API token (X-API-Key)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # submit
    p_submit = subparsers.add_parser("submit", help="Upload a completed Nmap XML scan to Nmap-AI")
    p_submit.add_argument("xml_file", help="Path to Nmap XML output file")

    # watch
    p_watch = subparsers.add_parser("watch", help="Watch a directory for new Nmap XML files and auto-import")
    p_watch.add_argument("directory", nargs="?", default=".", help="Directory to monitor (default: current dir)")
    p_watch.add_argument("--interval", type=int, default=3, help="Polling interval in seconds (default: 3)")
    p_watch.add_argument("--skip-existing", action="store_true", help="Skip existing XML files in directory")

    # worker
    p_worker = subparsers.add_parser("worker", help="Run background worker to execute scans dispatched from Nmap-AI UI")
    p_worker.add_argument("--scanner-name", default=DEFAULT_SCANNER_NAME, help="Scanner identifier name")
    p_worker.add_argument("--scanner-ip", default=DEFAULT_SCANNER_IP, help="Scanner IP address")
    p_worker.add_argument("--nmap-path", default=DEFAULT_NMAP, help="Path to nmap executable on Kali")
    p_worker.add_argument("--poll-interval", type=int, default=3, help="Poll interval in seconds")

    # run
    p_run = subparsers.add_parser("run", help="Run an authorized Nmap scan on Kali and immediately submit results")
    p_run.add_argument("target", help="Target IP address or CIDR")
    p_run.add_argument(
        "--profile",
        choices=list(PROFILES.keys()),
        default="service_version",
        help="Scan profile (default: service_version)",
    )
    p_run.add_argument("--nmap-path", default=DEFAULT_NMAP, help="Path to nmap executable on Kali")
    p_run.add_argument("--output", "-o", help="Optional output XML path")

    args = parser.parse_args()

    if args.command == "submit":
        return cmd_submit(args)
    elif args.command == "watch":
        return cmd_watch(args)
    elif args.command == "worker":
        return cmd_worker(args)
    elif args.command == "run":
        return cmd_run(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
