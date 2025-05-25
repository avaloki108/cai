"""
Advanced Network Reconnaissance Toolkit for CAI

This module provides comprehensive network reconnaissance tools including
advanced port scanning, service enumeration, vulnerability detection, and target profiling.
"""

import socket
import threading
import subprocess
import re
import json
import time
import ipaddress
from typing import Dict, List, Tuple, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from cai.tools.common import run_command


def comprehensive_network_scan(target: str, scan_type: str = "aggressive", ctf=None, **kwargs) -> str:
    """
    Perform comprehensive network reconnaissance on target
    
    Args:
        target: Target IP, hostname, or network range
        scan_type: Type of scan (quick, normal, aggressive, stealth)
        
    Returns:
        str: Detailed reconnaissance results
    """
    results = []
    results.append("=== Comprehensive Network Reconnaissance ===")
    results.append(f"Target: {target}")
    results.append(f"Scan Type: {scan_type}")
    results.append(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    results.append("")

    try:
        # 1. Host Discovery
        results.append("=== Host Discovery ===")
        host_discovery = discover_hosts(target, ctf=ctf)
        results.append(host_discovery)
        results.append("")

        # 2. Port Scanning
        results.append("=== Port Scanning ===")
        port_scan = advanced_port_scan(target, scan_type, ctf=ctf)
        results.append(port_scan)
        results.append("")

        # 3. Service Enumeration
        results.append("=== Service Enumeration ===")
        service_enum = enumerate_services(target, ctf=ctf)
        results.append(service_enum)
        results.append("")

        # 4. OS Detection
        results.append("=== Operating System Detection ===")
        os_detection = detect_operating_system(target, ctf=ctf)
        results.append(os_detection)
        results.append("")

        # 5. Vulnerability Scanning
        results.append("=== Vulnerability Assessment ===")
        vuln_scan = vulnerability_scan(target, ctf=ctf)
        results.append(vuln_scan)
        results.append("")

        # 6. DNS Enumeration
        results.append("=== DNS Enumeration ===")
        dns_enum = dns_enumeration(target, ctf=ctf)
        results.append(dns_enum)
        results.append("")

        return "\n".join(results)

    except Exception as e:
        return f"Error during comprehensive scan: {str(e)}"


def discover_hosts(target: str, ctf=None, **kwargs) -> str:
    """Discover live hosts in the target network"""
    results = []

    try:
        # Check if target is a single host or network range
        if '/' in target:
            # Network range - use nmap for host discovery
            discovery_cmd = f"nmap -sn {target}"
            nmap_output = run_command(discovery_cmd, ctf=ctf)
            results.append(f"Network sweep results:\n{nmap_output}")

            # Extract live hosts
            live_hosts = re.findall(r'Nmap scan report for ([^\s]+)', nmap_output)
            if live_hosts:
                results.append(f"\nLive hosts discovered: {len(live_hosts)}")
                for host in live_hosts:
                    results.append(f"  - {host}")
        else:
            # Single host - check if it's alive
            ping_result = run_command(f"ping -c 3 {target}", ctf=ctf)
            if "3 received" in ping_result:
                results.append(f"Host {target} is alive")
                results.append(f"Ping results:\n{ping_result}")
            else:
                results.append(f"Host {target} may be down or filtering ICMP")

        # Try traceroute for network path analysis
        traceroute = run_command(f"traceroute -m 10 {target} 2>/dev/null || tracert -h 10 {target}", ctf=ctf)
        if traceroute.strip():
            results.append(f"\nNetwork path to target:\n{traceroute}")

    except Exception as e:
        results.append(f"Error during host discovery: {str(e)}")

    return "\n".join(results)


def advanced_port_scan(target: str, scan_type: str = "normal", ctf=None, **kwargs) -> str:
    """Perform advanced port scanning with different techniques"""
    results = []

    try:
        # Define scan parameters based on scan type
        scan_configs = {
            "quick": "-T4 -F",  # Fast scan, common ports only
            "normal": "-T4 -A -p1-1000",  # Aggressive scan, top 1000 ports
            "aggressive": "-T4 -A -p-",  # Full port range scan
            "stealth": "-sS -T2 -f -p1-1000"  # Stealth SYN scan
        }

        scan_params = scan_configs.get(scan_type, scan_configs["normal"])

        # Primary nmap scan
        nmap_cmd = f"nmap {scan_params} {target}"
        results.append(f"Running: {nmap_cmd}")
        nmap_output = run_command(nmap_cmd, ctf=ctf)
        results.append(f"\nNmap scan results:\n{nmap_output}")

        # Extract open ports for further analysis
        open_ports = re.findall(r'(\d+)/tcp\s+open\s+([^\s]+)', nmap_output)
        if open_ports:
            results.append(f"\nOpen ports summary:")
            for port, service in open_ports:
                results.append(f"  - {port}/tcp: {service}")

        # UDP scan for common UDP services
        if scan_type in ["aggressive", "normal"]:
            udp_ports = "53,67,68,69,123,135,137,138,139,161,162,500,514,1434"
            udp_cmd = f"nmap -sU -p{udp_ports} {target}"
            results.append(f"\nUDP scan: {udp_cmd}")
            udp_output = run_command(udp_cmd, ctf=ctf)
            results.append(f"UDP scan results:\n{udp_output}")

        # Service version detection for open ports
        if open_ports and scan_type != "quick":
            port_list = ",".join([port for port, _ in open_ports])
            version_cmd = f"nmap -sV -p{port_list} {target}"
            results.append(f"\nService version detection: {version_cmd}")
            version_output = run_command(version_cmd, ctf=ctf)
            results.append(f"Version detection results:\n{version_output}")

    except Exception as e:
        results.append(f"Error during port scanning: {str(e)}")

    return "\n".join(results)


def enumerate_services(target: str, ctf=None, **kwargs) -> str:
    """Enumerate specific services with detailed probing"""
    results = []

    try:
        # Get open ports first
        nmap_output = run_command(f"nmap -p1-1000 {target}", ctf=ctf)
        open_ports = re.findall(r'(\d+)/tcp\s+open\s+([^\s]+)', nmap_output)

        if not open_ports:
            return "No open ports found for service enumeration"

        results.append("Service-specific enumeration:")

        for port, service in open_ports:
            results.append(f"\n--- Port {port}/{service} ---")

            # HTTP/HTTPS enumeration
            if service.lower() in ['http', 'https', 'http-proxy']:
                http_enum = enumerate_http_service(target, port, ctf=ctf)
                results.append(http_enum)

            # SSH enumeration
            elif service.lower() == 'ssh':
                ssh_enum = enumerate_ssh_service(target, port, ctf=ctf)
                results.append(ssh_enum)

            # FTP enumeration
            elif service.lower() == 'ftp':
                ftp_enum = enumerate_ftp_service(target, port, ctf=ctf)
                results.append(ftp_enum)

            # SMB enumeration
            elif service.lower() in ['microsoft-ds', 'netbios-ssn', 'smb']:
                smb_enum = enumerate_smb_service(target, port, ctf=ctf)
                results.append(smb_enum)

            # SNMP enumeration
            elif service.lower() == 'snmp':
                snmp_enum = enumerate_snmp_service(target, port, ctf=ctf)
                results.append(snmp_enum)

            # Generic banner grabbing
            else:
                banner = grab_service_banner(target, int(port))
                if banner:
                    results.append(f"Banner: {banner}")

    except Exception as e:
        results.append(f"Error during service enumeration: {str(e)}")

    return "\n".join(results)


def enumerate_http_service(target: str, port: str, ctf=None) -> str:
    """Enumerate HTTP/HTTPS services"""
    results = []

    try:
        protocol = "https" if port == "443" else "http"
        base_url = f"{protocol}://{target}:{port}"

        # Basic HTTP enumeration
        curl_cmd = f"curl -I -k -m 10 {base_url}"
        http_headers = run_command(curl_cmd, ctf=ctf)
        results.append(f"HTTP headers:\n{http_headers}")

        # Directory enumeration
        common_dirs = [
            'admin', 'administrator', 'wp-admin', 'phpmyadmin', 'login',
            'robots.txt', 'sitemap.xml', '.htaccess', 'backup', 'config',
            'api', 'test', 'dev', 'staging'
        ]

        results.append("\nDirectory enumeration:")
        for directory in common_dirs[:5]:  # Test first 5 to avoid timeout
            test_url = f"{base_url}/{directory}"
            dir_check = run_command(f"curl -s -o /dev/null -w '%{{http_code}}' -k -m 5 {test_url}", ctf=ctf)
            if dir_check.strip() in ['200', '301', '302', '403']:
                results.append(f"  Found: {directory} (Status: {dir_check.strip()})")

        # Check for common web technologies
        tech_check = run_command(f"curl -s -k -m 10 {base_url}", ctf=ctf)
        technologies = []
        if 'wordpress' in tech_check.lower() or 'wp-content' in tech_check.lower():
            technologies.append('WordPress')
        if 'joomla' in tech_check.lower():
            technologies.append('Joomla')
        if 'drupal' in tech_check.lower():
            technologies.append('Drupal')

        if technologies:
            results.append(f"\nDetected technologies: {', '.join(technologies)}")

    except Exception as e:
        results.append(f"HTTP enumeration error: {str(e)}")

    return "\n".join(results)


def enumerate_ssh_service(target: str, port: str, ctf=None) -> str:
    """Enumerate SSH service"""
    results = []

    try:
        # SSH version and algorithm enumeration
        ssh_scan = run_command(f"nmap -p{port} --script ssh2-enum-algos,ssh-hostkey {target}", ctf=ctf)
        results.append(f"SSH enumeration:\n{ssh_scan}")

        # Check for weak authentication
        auth_methods = run_command(f"nmap -p{port} --script ssh-auth-methods {target}", ctf=ctf)
        if auth_methods.strip():
            results.append(f"\nSSH authentication methods:\n{auth_methods}")

    except Exception as e:
        results.append(f"SSH enumeration error: {str(e)}")

    return "\n".join(results)


def enumerate_ftp_service(target: str, port: str, ctf=None) -> str:
    """Enumerate FTP service"""
    results = []

    try:
        # FTP banner and anonymous access
        ftp_enum = run_command(f"nmap -p{port} --script ftp-anon,ftp-bounce,ftp-syst {target}", ctf=ctf)
        results.append(f"FTP enumeration:\n{ftp_enum}")

        # Try anonymous login
        anon_test = run_command(f"echo 'quit' | ftp -n {target} {port}", ctf=ctf)
        if "230" in anon_test:  # Successful login
            results.append("🔥 Anonymous FTP access allowed!")

    except Exception as e:
        results.append(f"FTP enumeration error: {str(e)}")

    return "\n".join(results)


def enumerate_smb_service(target: str, port: str, ctf=None) -> str:
    """Enumerate SMB service"""
    results = []

    try:
        # SMB enumeration with nmap scripts
        smb_enum = run_command(f"nmap -p{port} --script smb-enum-shares,smb-enum-users,smb-os-discovery {target}",
                               ctf=ctf)
        results.append(f"SMB enumeration:\n{smb_enum}")

        # Try null session
        null_session = run_command(f"smbclient -N -L //{target}", ctf=ctf)
        if "Sharename" in null_session:
            results.append(f"\n🔥 SMB null session successful:\n{null_session}")

        # Check for SMB vulnerabilities
        smb_vulns = run_command(f"nmap -p{port} --script smb-vuln-* {target}", ctf=ctf)
        if "VULNERABLE" in smb_vulns:
            results.append(f"\n🚨 SMB vulnerabilities found:\n{smb_vulns}")

    except Exception as e:
        results.append(f"SMB enumeration error: {str(e)}")

    return "\n".join(results)


def enumerate_snmp_service(target: str, port: str, ctf=None) -> str:
    """Enumerate SNMP service"""
    results = []

    try:
        # SNMP enumeration with common community strings
        community_strings = ['public', 'private', 'community', 'manager']

        for community in community_strings:
            snmp_test = run_command(f"snmpwalk -v2c -c {community} {target} 2>/dev/null | head -5", ctf=ctf)
            if snmp_test.strip():
                results.append(f"🔥 SNMP community '{community}' works:")
                results.append(snmp_test)
                break

        # SNMP system information
        sys_info = run_command(f"nmap -p{port} --script snmp-sysdescr,snmp-info {target}", ctf=ctf)
        if sys_info.strip():
            results.append(f"\nSNMP system information:\n{sys_info}")

    except Exception as e:
        results.append(f"SNMP enumeration error: {str(e)}")

    return "\n".join(results)


def grab_service_banner(target: str, port: int) -> str:
    """Grab service banner using socket connection"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))

        # Send HTTP request for web services
        if port in [80, 443, 8080, 8443]:
            sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")

        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        return banner.strip()[:200]  # Limit banner length

    except Exception:
        return ""


def detect_operating_system(target: str, ctf=None, **kwargs) -> str:
    """Detect operating system using various techniques"""
    results = []

    try:
        # Nmap OS detection
        os_detection = run_command(f"nmap -O {target}", ctf=ctf)
        results.append(f"Nmap OS detection:\n{os_detection}")

        # TTL-based OS detection
        ping_output = run_command(f"ping -c 1 {target}", ctf=ctf)
        ttl_match = re.search(r'ttl=(\d+)', ping_output.lower())
        if ttl_match:
            ttl = int(ttl_match.group(1))
            if ttl <= 64:
                os_guess = "Linux/Unix (TTL ≤ 64)"
            elif ttl <= 128:
                os_guess = "Windows (TTL ≤ 128)"
            else:
                os_guess = "Unknown (TTL > 128)"
            results.append(f"\nTTL-based OS guess: {os_guess} (TTL: {ttl})")

        # Service-based OS fingerprinting
        service_os = run_command(f"nmap -sV -O --version-intensity 9 {target}", ctf=ctf)
        os_matches = re.findall(r'OS details: ([^\n]+)', service_os)
        if os_matches:
            results.append(f"\nDetailed OS information: {os_matches[0]}")

    except Exception as e:
        results.append(f"Error during OS detection: {str(e)}")

    return "\n".join(results)


def vulnerability_scan(target: str, ctf=None, **kwargs) -> str:
    """Perform vulnerability scanning"""
    results = []

    try:
        # Nmap vulnerability scripts
        vuln_scan = run_command(f"nmap --script vuln {target}", ctf=ctf)
        results.append(f"Vulnerability scan results:\n{vuln_scan}")

        # Check for specific high-risk vulnerabilities
        high_risk_vulns = [
            "ms17-010",  # EternalBlue
            "ms08-067",  # Conficker
            "cve-2014-6271",  # Shellshock
            "cve-2017-7494"  # SambaCry
        ]

        for vuln in high_risk_vulns:
            vuln_check = run_command(f"nmap --script {vuln} {target}", ctf=ctf)
            if "VULNERABLE" in vuln_check:
                results.append(f"\n🚨 HIGH RISK: {vuln.upper()} vulnerability detected!")
                results.append(vuln_check)

        # SSL/TLS vulnerability checks
        ssl_check = run_command(f"nmap --script ssl-enum-ciphers,ssl-heartbleed {target}", ctf=ctf)
        if "VULNERABLE" in ssl_check or "weak" in ssl_check.lower():
            results.append(f"\n⚠️ SSL/TLS vulnerabilities:\n{ssl_check}")

    except Exception as e:
        results.append(f"Error during vulnerability scan: {str(e)}")

    return "\n".join(results)


def dns_enumeration(target: str, ctf=None, **kwargs) -> str:
    """Perform comprehensive DNS enumeration"""
    results = []

    try:
        # Basic DNS lookups
        dns_info = run_command(f"nslookup {target}", ctf=ctf)
        results.append(f"DNS lookup:\n{dns_info}")

        # DNS record enumeration
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        for record_type in record_types:
            record_query = run_command(f"dig {target} {record_type} +short", ctf=ctf)
            if record_query.strip():
                results.append(f"\n{record_type} records:")
                results.append(record_query)

        # Reverse DNS lookup
        try:
            # Get IP address first
            ip_result = run_command(f"dig {target} A +short", ctf=ctf)
            if ip_result.strip():
                ip_addr = ip_result.strip().split('\n')[0]
                reverse_dns = run_command(f"dig -x {ip_addr} +short", ctf=ctf)
                if reverse_dns.strip():
                    results.append(f"\nReverse DNS: {reverse_dns}")
        except Exception:
            pass

        # DNS zone transfer attempt
        ns_servers = run_command(f"dig {target} NS +short", ctf=ctf)
        if ns_servers.strip():
            results.append(f"\nAttempting zone transfer:")
            for ns in ns_servers.strip().split('\n')[:2]:  # Try first 2 NS servers
                if ns.strip():
                    zone_transfer = run_command(f"dig @{ns.strip()} {target} AXFR", ctf=ctf)
                    if "Transfer failed" not in zone_transfer and len(zone_transfer) > 100:
                        results.append(f"🔥 Zone transfer successful from {ns}:")
                        results.append(zone_transfer[:500])  # Limit output
                        break

        # Subdomain enumeration
        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api']
        results.append(f"\nSubdomain enumeration:")
        for subdomain in common_subdomains:
            subdomain_check = run_command(f"dig {subdomain}.{target} +short", ctf=ctf)
            if subdomain_check.strip():
                results.append(f"  Found: {subdomain}.{target} -> {subdomain_check.strip()}")

    except Exception as e:
        results.append(f"Error during DNS enumeration: {str(e)}")

    return "\n".join(results)


def network_topology_mapping(target_network: str, ctf=None, **kwargs) -> str:
    """Map network topology and identify key infrastructure"""
    results = []

    try:
        results.append(f"=== Network Topology Mapping ===")
        results.append(f"Target Network: {target_network}")

        # Network discovery scan
        discovery_scan = run_command(f"nmap -sn {target_network}", ctf=ctf)
        results.append(f"\nNetwork discovery:\n{discovery_scan}")

        # Extract live hosts
        live_hosts = re.findall(r'Nmap scan report for ([^\s]+)', discovery_scan)

        if live_hosts:
            results.append(f"\nLive hosts analysis:")
            for host in live_hosts[:10]:  # Analyze first 10 hosts
                results.append(f"\n--- Analyzing {host} ---")

                # Quick port scan to identify role
                quick_scan = run_command(f"nmap -T4 -F {host}", ctf=ctf)
                open_ports = re.findall(r'(\d+)/tcp\s+open\s+([^\s]+)', quick_scan)

                # Categorize host based on open ports
                host_role = categorize_host_role(open_ports)
                results.append(f"Likely role: {host_role}")

                if open_ports:
                    results.append(f"Open ports: {', '.join([p for p, s in open_ports])}")

        # Gateway identification
        gateway_info = run_command("ip route | grep default", ctf=ctf)
        if gateway_info.strip():
            results.append(f"\nGateway information:\n{gateway_info}")

    except Exception as e:
        results.append(f"Error during topology mapping: {str(e)}")

    return "\n".join(results)


def categorize_host_role(open_ports: List[Tuple[str, str]]) -> str:
    """Categorize host role based on open ports"""
    port_services = {port: service for port, service in open_ports}

    # Check for specific roles
    if '80' in port_services or '443' in port_services:
        return "Web Server"
    elif '22' in port_services:
        return "SSH Server / Linux Host"
    elif '3389' in port_services:
        return "Windows Host (RDP)"
    elif '139' in port_services or '445' in port_services:
        return "File Server (SMB)"
    elif '53' in port_services:
        return "DNS Server"
    elif '25' in port_services or '587' in port_services:
        return "Mail Server"
    elif '3306' in port_services or '5432' in port_services:
        return "Database Server"
    elif '21' in port_services:
        return "FTP Server"
    elif len(open_ports) > 10:
        return "Multi-service Host"
    else:
        return "General Purpose Host"
