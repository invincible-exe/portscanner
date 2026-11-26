import argparse
import json
import os
import time
from datetime import datetime, timezone

import nmap
import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def normalize_cpe_23(cpe_raw) -> str | None:
    """Convert Nmap's CPE 2.2 string (cpe:/a:vendor:product:version) to CPE 2.3."""
    if isinstance(cpe_raw, list):
        cpe_raw = cpe_raw[0] if cpe_raw else ""
    if not cpe_raw or not str(cpe_raw).startswith("cpe:/"):
        return None

    parts = str(cpe_raw)[5:].split(":")
    # Require at least part, vendor, product, and version to avoid noisy matches
    if len(parts) < 4 or not parts[3]:
        return None

    padded = (parts + ["*"] * 11)[:11]
    return "cpe:2.3:" + ":".join(padded)


def clean_version(version: str) -> str:
    """Strip distro-specific suffixes (e.g., '6.6.1p1 Ubuntu ...' -> '6.6.1p1')."""
    return version.strip().split()[0] if version and version.strip() else ""


def severity_label(score) -> str:
    """Map numeric CVSS score to a severity tier."""
    if not isinstance(score, (int, float)):
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


def extract_cvss_score(metrics: dict):
    """Extract the highest available CVSS base score (v4.0 -> v3.1 -> v3.0 -> v2.0)."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            score = metrics[key][0].get("cvssData", {}).get("baseScore")
            if score is not None:
                return score
    return "N/A"


def _request_nvd(params: dict, headers: dict) -> list[dict]:
    """Execute a single NVD API v2.0 request and parse CVE entries."""
    response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=15)
    if response.status_code == 404:
        return []
    response.raise_for_status()
    data = response.json()

    vulns = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "Unknown ID")

        descriptions = cve.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available.",
        )

        score = extract_cvss_score(cve.get("metrics", {}))
        vulns.append(
            {
                "id": cve_id,
                "score": score,
                "severity": severity_label(score),
                "description": desc[:140] + "..." if len(desc) > 140 else desc,
            }
        )

    vulns.sort(
        key=lambda v: v["score"] if isinstance(v["score"], (int, float)) else -1.0,
        reverse=True,
    )
    return vulns


def query_nvd(product: str, version: str, cpe: str = "", api_key: str | None = None, limit: int = 5) -> list[dict]:
    """Query NIST NVD v2.0 using CPE 2.3 first, then fall back to cleaned keyword search."""
    if not product:
        return []

    headers = {"apiKey": api_key} if api_key else {}
    cpe_23 = normalize_cpe_23(cpe)

    try:
        if cpe_23:
            vulns = _request_nvd({"cpeName": cpe_23, "resultsPerPage": limit}, headers)
            if vulns:
                return vulns
            if not api_key:
                time.sleep(6)

        short_ver = clean_version(version)
        query = f"{product} {short_ver}".strip()
        return _request_nvd({"keywordSearch": query, "resultsPerPage": limit}, headers)

    except requests.RequestException as e:
        print(f"   [!] Error querying NVD API: {e}")
        return []


def scan_target(
    target: str,
    port_range: str = "1-1024",
    nvd_api_key: str | None = None,
    output_file: str | None = None,
):
    """Scan an authorized target for open TCP services and check NVD for known CVEs."""
    scanner = nmap.PortScanner()
    print(f"[*] Scanning target: {target} on TCP ports {port_range}...")

    try:
        scanner.scan(hosts=target, ports=port_range, arguments="-sV -T4")
    except nmap.PortScannerError as e:
        print(f"   [!] Nmap scan error: {e}")
        return

    hosts = scanner.all_hosts()
    if not hosts:
        print(f"   [!] No hosts responded. Stats: {scanner.scanstats()}")
        return

    report = {
        "scan_time_utc": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "port_range": port_range,
        "hosts": [],
    }

    for host in hosts:
        hostname = scanner[host].hostname() or "no reverse DNS"
        state = scanner[host].state()
        print(f"\n[+] Host: {host} ({hostname})")
        print(f"    State: {state}")

        host_entry = {"ip": host, "hostname": hostname, "state": state, "services": []}

        for proto in scanner[host].all_protocols():
            print(f"    Protocol: {proto.upper()}")
            ports = sorted(scanner[host][proto].keys())

            for port in ports:
                service = scanner[host][proto][port]
                if service.get("state") != "open":
                    continue

                name = service.get("name", "unknown")
                product = service.get("product", "")
                version = service.get("version", "")
                cpe = service.get("cpe", "")

                service_str = f"{product} {version}".strip() or "Version Unknown"
                print(f"    [+] Port {port:<5} | Service: {name:<12} | Product: {service_str}")

                vulns = []
                if product and version:
                    vulns = query_nvd(product, version, cpe=cpe, api_key=nvd_api_key)
                    if vulns:
                        for v in vulns:
                            print(
                                f"        - {v['id']} | {v['severity']:<8} ({v['score']}) | {v['description']}"
                            )
                    else:
                        print("        [-] No matching CVEs returned by NVD.")

                    if not nvd_api_key:
                        time.sleep(6)
                else:
                    print("        [-] Version banner not exposed; skipping NVD lookup.")

                host_entry["services"].append(
                    {
                        "protocol": proto,
                        "port": port,
                        "service": name,
                        "product": product,
                        "version": version,
                        "cpe": cpe,
                        "cves": vulns,
                    }
                )

        report["hosts"].append(host_entry)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\n[*] Audit report saved to: {output_file}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="TCP service version & NIST NVD CVE auditor (use only on authorized hosts)."
    )
    parser.add_argument("target", nargs="?", help="Target IP or hostname (e.g., 127.0.0.1)")
    parser.add_argument(
        "-p", "--ports", default="1-1024", help="Port range or list (default: 1-1024)"
    )
    parser.add_argument(
        "-o", "--output", default=None, help="Optional JSON file path to save scan results"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    target_ip = args.target or input("Enter target IP address: ").strip()
    if not target_ip:
        print("[!] No target specified.")
        raise SystemExit(1)

    api_key = os.getenv("NVD_API_KEY")
    scan_target(target_ip, port_range=args.ports, nvd_api_key=api_key, output_file=args.output)