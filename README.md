# Network Scanner

A Python-based **Network Scanner** designed for host discovery, service fingerprinting, vulnerability assessment, SSL/TLS analysis, and network security reporting.

The scanner combines an **offline Local CVE Engine** with an **external vulnerability intelligence module (Vulne)** to provide accurate vulnerability detection using service versions and banner grabbing.

---

# Features

## Host Discovery

* Detects live hosts using ARP scanning
* Identifies IP and MAC addresses

---

## Port Scanning

Supports three scan modes:

* Top 5000 Ports
* All 65535 Ports
* Custom Port Selection

---

## Service Detection

Uses Nmap service fingerprinting to identify:

* Open services
* Service versions
* Protocol information

---

## Banner Grabbing

Performs banner grabbing to improve service identification.

Extracts:

* Service banner
* Product information
* Version information

This significantly improves vulnerability detection accuracy.

---

## Product Normalization

Normalizes different service names into a common product format before vulnerability matching.

Examples:

* OpenSSH → openssh
* ISC BIND → bind
* Apache HTTPD → apache http server
* dnsmasq → dnsmasq

This improves Local CVE matching accuracy.

---

## Operating System Detection

Detects operating systems using Nmap OS fingerprinting.

Normalized OS families:

* Windows
* Linux
* Android
* Unknown

---

## Hostname Detection

Performs reverse DNS lookups for discovered hosts.

---

## Firewall Detection

Detects filtered hosts and identifies possible firewall or gateway devices.

---

## SSL/TLS Detection

Collects SSL/TLS information including:

* TLS 1.2 Support
* TLS 1.3 Support
* Certificate Subject
* Certificate Validity
* Certificate Expiration Status

---

# Vulnerability Assessment

## Local Offline CVE Engine

The scanner includes a completely offline CVE engine built using the MITRE CVE List V5 database.

Features:

* Offline vulnerability lookup
* Version-aware matching
* CVSS extraction
* Severity classification
* Product normalization

Generated Output:

```text
results/cves.json
```

---

## Version-Aware CVE Matching

Detected services are matched using:

* Product Name
* Product Version

Supported version comparisons:

* before x.x.x
* <= x.x.x
* Exact Version Matching

---

## External Vulnerability Intelligence (Vulne Integration)

The scanner integrates the **Vulne** project to retrieve additional vulnerability information from online sources.

Features:

* Live CVE lookup
* National Vulnerability Database (NVD)
* CISA Known Exploited Vulnerabilities (KEV)
* CVSS Scores
* Vulnerability Descriptions

Generated Output:

```text
results/vulne_cves.json
```

---

## Third-Party Integration

The external vulnerability lookup module is based on the **Vulne** project developed by **Joel S Joseph**.

Original Repository:

https://github.com/joell007/vulne

The project has been integrated and modified to work with this Network Scanner.

---

## Risk Mapping

Assigns:

* Low
* Medium
* High
* Critical

risk levels based on detected services and vulnerabilities.

---

## Network Topology

Builds a topology containing:

* Gateway
* Connected Devices
* Operating Systems

---

## Master Security Report

Generates a consolidated report including:

* Host Information
* Open Ports
* Services
* Fingerprints
* Local CVEs
* External CVEs
* Risks
* Network Topology

Generated Output:

```text
results/master_scan.json
```

---

# Project Structure

```text
network_scanner/

├── app.py
├── host_discovery.py
├── port_scanner.py
├── service_detection.py
├── banner_grabber.py
├── service_fingerprint.py
├── product_normalizer.py
├── version_normalizer.py
├── version_utils.py
├── build_cve_index.py
├── cve_mapping.py
├── vulne_mapping.py
├── vulnerability_mapping.py
├── os_detection.py
├── os_normalizer.py
├── hostname_detection.py
├── firewall_detection.py
├── ssl_detection.py
├── network_topology.py
├── export_results.py
├── master_export.py
├── utils.py

├── results/

├── vulnerability_db/

└── vulne/
```

---

# Requirements

Install required packages:

```bash
sudo apt update

sudo apt install \
nmap \
arp-scan \
sslscan \
python3 -y
```

Python dependency:

```bash
pip install requests
```

---

# Local CVE Database Setup

Clone the MITRE CVE List V5 database:

```bash
mkdir vulnerability_db

cd vulnerability_db

git clone https://github.com/CVEProject/cvelistV5.git
```

Build the local CVE index:

```bash
cd ..

python3 build_cve_index.py
```

This generates:

```text
vulnerability_db/cve_index.json
```

**Note:** `cve_index.json` is **not included** in this repository because it exceeds GitHub's file size limit. Generate it locally using the command above.

---

# Running the Scanner

Run:

```bash
python3 app.py
```

Choose scan mode:

```text
1. Top 5000 Ports

2. All 65535 Ports

3. Custom Ports
```

---

# Running the Vulne Module Separately

The Vulne engine runs automatically as part of the scan.

To execute it manually:

```bash
cd vulne

python3 cve_retriever.py
```

Results are generated in:

```text
vulnerability_results.json
```

The scanner automatically copies them to:

```text
results/vulne_cves.json
```

---

# Output Files

Generated inside:

```text
results/
```

Files:

```text
hosts.json
ports.json
services.json
fingerprints.json
ssl.json
risks.json
topology.json

cves.json
vulne_cves.json

master_scan.json
```

---

# Scan Workflow

```text
Host Discovery
        ↓
Port Scan
        ↓
Service Detection
        ↓
Banner Grabbing
        ↓
Product Normalization
        ↓
Operating System Detection
        ↓
Hostname Detection
        ↓
Firewall Detection
        ↓
SSL/TLS Detection
        ↓
Service Fingerprinting
        ↓
Local CVE Engine
        ↓
External Vulne Engine
        ↓
Risk Mapping
        ↓
Network Topology
        ↓
Master Security Report
```

---

# Future Enhancements

* Vendor Detection (MAC → Vendor)
* React Dashboard Integration
* AI-Based Mitigation Recommendations
* AI Report Generation
* PDF Report Export
* HTML Dashboard
* CPE-Based Vulnerability Matching
* Automated Patch Recommendations

