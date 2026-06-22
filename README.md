# Network Scanner

## Overview

A multi-tool network scanner that discovers hosts, identifies open ports, detects services, fingerprints assets, detects SSL/TLS information, identifies firewalls, and exports structured data for LLM-based analysis and report generation.

## Workflow

Host Discovery
↓
Port Scanning
↓
Service Detection
↓
OS Detection
↓
OS Normalization
↓
Hostname Detection
↓
Firewall Detection
↓
SSL Detection
↓
Risk Mapping
↓
Topology Mapping
↓
Fingerprint Generation
↓
Export Results

## Tools Used

- arp-scan
- netdiscover
- nmap
- nbtscan
- sslscan

## Output Files

- hosts.json
- ports.json
- services.json
- os.json
- firewall.json
- ssl.json
- risks.json
- topology.json
- fingerprints.json
- master_scan.json
