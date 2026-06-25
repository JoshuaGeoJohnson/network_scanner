from host_discovery import discover_hosts
from port_scanner import scan_ports
from service_detection import detect_services
from os_detection import detect_os
from os_normalizer import normalize_os
from hostname_detection import detect_hostnames
from firewall_detection import detect_firewall
from ssl_detection import detect_ssl
from service_fingerprint import build_fingerprints
from vulnerability_mapping import map_risks
from network_topology import build_topology
from export_results import export_results
from master_export import create_master_scan
from cve_mapping import map_cves
from banner_grabber import grab_banners
from vulne_mapping import (
    map_vulne_cves
)
print("=" * 50)
print("Network Scanner Started")
print("=" * 50)

print("\nPort Scan Options")
print("1. Top 5000 Ports")
print("2. All 65535 Ports")
print("3. Custom Ports")

choice = input(
    "\nEnter choice (1/2/3): "
)

scan_mode = ""
custom_ports = None

if choice == "1":

    scan_mode = "top5000"

elif choice == "2":

    scan_mode = "all"

elif choice == "3":

    scan_mode = "custom"

    custom_ports = input(
        "Enter ports (example: 80,443,8080): "
    )

else:

    print("Invalid choice")
    exit()

# Step 1 - Discover Hosts
discover_hosts()

# Step 2 - Port Scan
scan_ports(
    scan_mode,
    custom_ports
)

# Step 3 - Service Detection
detect_services()

# Banner Grabbing
grab_banners()

# Step 4 - OS Detection
detect_os()

# Step 5 - OS Normalization
normalize_os()

# Step 6 - Hostname Detection
detect_hostnames()

# Step 7 - Firewall Detection
detect_firewall()

# Step 8 - SSL Detection
detect_ssl()

# Step 9 - Fingerprinting
build_fingerprints()

# Step 10 - Local CVE Engine
map_cves()

# Step 11 - Vulne API Engine
try:

    map_vulne_cves()

except Exception as e:

    print(
        f"[!] Vulne Engine Failed: {e}"
    )

# Step 12 - Risk Mapping
map_risks()
# Step 11 - Topology
build_topology()

# Step 12 - Export
export_results()

# Step 13 - Master Scan
create_master_scan()

print("=" * 50)
print("Network Scan Completed")
print("=" * 50)
