from host_discovery import discover_hosts
from port_scanner import scan_ports
from service_detection import detect_services
from os_detection import detect_os
from hostname_detection import detect_hostnames
from firewall_detection import detect_firewall
#from web_detection import detect_web
from ssl_detection import detect_ssl
from export_results import export_results
from vulnerability_mapping import map_risks
from network_topology import build_topology
from master_export import create_master_scan
from os_normalizer import normalize_os
#from banner_grabber import grab_banners
from service_fingerprint import build_fingerprints

print("=" * 50)
print("Network Scanner Started")
print("=" * 50)

# Step 1 - Discover Hosts
hosts = discover_hosts()

if not hosts:
    print("[!] No hosts discovered")
    exit()
# Step 2 - Find Open Ports
scan_ports()

# Step 3 - Service & Version Detection
detect_services()

#grab_banners()

# Step 4 - OS Detection
detect_os()

normalize_os()

# Step 5 - Hostname Detection
detect_hostnames()

# Step 6 - Firewall Detection
detect_firewall()

# Step 8 - SSL Detection
detect_ssl()

build_fingerprints()

map_risks()

build_topology()

export_results()

create_master_scan()

print("=" * 50)
print("Network Scan Completed")
print("=" * 50)
