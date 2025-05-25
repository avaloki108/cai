"""Bug Bounty Agent with comprehensive toolset"""
import os
from dotenv import load_dotenv
from cai.types import Agent  # pylint: disable=import-error
from cai.util import load_prompt_template  # Add this import

# Initialize the bug bounty functions list and debug info
bug_bounty_functions = []
import_debug = {"successful": [], "failed": []}


def safe_import(module_path, function_names, description=""):
    """Safely import functions and track success/failure"""
    global bug_bounty_functions, import_debug

    if isinstance(function_names, str):
        function_names = [function_names]

    try:
        module = __import__(module_path, fromlist=function_names)
        imported_functions = []

        for func_name in function_names:
            try:
                func = getattr(module, func_name)
                if callable(func):
                    bug_bounty_functions.append(func)
                    imported_functions.append(func_name)
                else:
                    import_debug["failed"].append(f"{module_path}.{func_name} (not callable)")
            except AttributeError:
                import_debug["failed"].append(f"{module_path}.{func_name} (not found)")

        if imported_functions:
            import_debug["successful"].append(f"{description}: {', '.join(imported_functions)}")

    except ImportError as e:
        import_debug["failed"].append(f"{module_path}: {str(e)}")
    except Exception as e:
        import_debug["failed"].append(f"{module_path}: Unexpected error - {str(e)}")


# Basic tools
safe_import("cai.tools.reconnaissance.generic_linux_command", "generic_linux_command", "Basic Linux Commands")
safe_import("cai.tools.reconnaissance.exec_code", "execute_code", "Code Execution")
safe_import("cai.tools.misc.reasoning", "think", "Reasoning")

# Reconnaissance tools
recon_functions = [
    "comprehensive_network_scan", "discover_hosts", "advanced_port_scan",
    "enumerate_services", "enumerate_http_service", "enumerate_ssh_service",
    "enumerate_ftp_service", "enumerate_smb_service", "enumerate_snmp_service",
    "detect_operating_system", "vulnerability_scan", "dns_enumeration",
    "network_topology_mapping", "categorize_host_role"
]
safe_import("cai.tools.reconnaissance", recon_functions, "Reconnaissance Tools")

# Web exploitation tools  
web_exploit_functions = [
    "automated_web_scan", "gather_web_info", "directory_bruteforce",
    "test_xss_vulnerabilities", "test_sql_injection", "test_command_injection",
    "test_lfi_vulnerabilities", "test_authentication_bypass",
    "generate_reverse_shell_payload", "exploit_file_upload_vulnerability"
]
safe_import("cai.tools.exploitation", web_exploit_functions, "Web Exploitation")

# Advanced exploitation tools
advanced_exploit_functions = [
    "advanced_vulnerability_scanner", "automated_exploit_chaining",
    "intelligent_payload_generator", "steganography_toolkit",
    "advanced_post_exploitation"
]
safe_import("cai.tools.advanced_exploitation", advanced_exploit_functions, "Advanced Exploitation")

# Automated exploitation engine
auto_exploit_functions = [
    "automated_exploit_discovery", "intelligent_payload_delivery",
    "advanced_session_management", "exploit_automation_framework",
    "adaptive_evasion_engine"
]
safe_import("cai.tools.automated_exploitation_engine", auto_exploit_functions, "Automated Exploitation Engine")

# Network intelligence tools
network_intel_functions = [
    "advanced_network_mapping", "osint_target_profiling",
    "intelligent_port_scanner", "network_vulnerability_hunter",
    "dns_intelligence_gathering"
]
safe_import("cai.tools.network_intelligence", network_intel_functions, "Network Intelligence")

# Privilege escalation tools
privesc_functions = [
    "automated_privesc_scan", "enumerate_system_info", "enumerate_user_info",
    "find_suid_sgid_files", "find_writable_directories", "find_interesting_files",
    "enumerate_network_info", "enumerate_processes", "enumerate_services_cron",
    "suggest_kernel_exploits", "exploit_sudo_misconfiguration", "exploit_cron_jobs"
]
safe_import("cai.tools.privilege_scalation", privesc_functions, "Privilege Escalation")

# Lateral movement tools
lateral_movement_functions = [
    "automated_lateral_movement", "harvest_local_credentials",
    "discover_internal_network", "enumerate_network_shares",
    "assess_remote_access", "assess_pivoting_opportunities",
    "setup_ssh_tunnel", "setup_socat_relay", "credential_spray_attack",
    "dump_network_configuration"
]
safe_import("cai.tools.lateral_movement", lateral_movement_functions, "Lateral Movement")

# Data exfiltration tools
data_exfil_functions = [
    "automated_data_collection", "discover_credential_files",
    "discover_database_files", "analyze_configuration_files",
    "collect_documents", "analyze_source_code", "gather_system_information",
    "analyze_file_for_credentials", "create_data_archive",
    "exfiltrate_via_http", "exfiltrate_via_dns", "cleanup_evidence"
]
safe_import("cai.tools.data_exfiltration", data_exfil_functions, "Data Exfiltration")

# Web and search tools
safe_import("cai.tools.web.search_web", "make_google_search", "Google Search")
safe_import("cai.tools.web.headers", "web_request_framework", "Web Headers")

# Command and control tools
safe_import("cai.tools.command_and_control.sshpass", "run_ssh_command_with_credentials", "SSH Commands")

# Shodan integration
safe_import("cai.tools.reconnaissance.shodan", ["shodan_search", "shodan_host_info"], "Shodan Integration")

# Add conditional tools based on API keys
if os.getenv('GOOGLE_SEARCH_API_KEY') and os.getenv('GOOGLE_SEARCH_CX'):
    # Google search was already imported above, so just note it's available
    import_debug["successful"].append("Google Search: Available (API keys found)")
else:
    import_debug["failed"].append("Google Search: Skipped (API keys not found)")

load_dotenv()

# Prompts
try:
    bug_bounter_system_prompt = load_prompt_template("prompts/system_bug_bounter.md")
except Exception as e:
    print(f"Warning: Failed to load system prompt: {e}")
    bug_bounter_system_prompt = "You are a comprehensive bug bounty hunting agent."

bug_bounter_agent = Agent(
    name="Bug Bounty Hunter",
    instructions=bug_bounter_system_prompt,
    description=f"""Comprehensive bug bounty hunting agent with {len(bug_bounty_functions)} tools loaded.
                   Expert in reconnaissance, web security, vulnerability discovery,
                   exploitation, privilege escalation, lateral movement, and responsible disclosure.
                   
                   Capabilities include:
                   - Advanced network reconnaissance and OSINT
                   - Web application security testing
                   - Automated vulnerability scanning and exploitation
                   - Privilege escalation and persistence
                   - Lateral movement and network pivoting
                   - Data collection and exfiltration techniques
                   - Steganography and advanced analysis
                   - Session management and evasion techniques
                   
                   Successfully loaded {len(import_debug['successful'])} tool categories with {len(bug_bounty_functions)} individual functions.""",
    model=os.getenv('CAI_MODEL', "qwen2.5:14b"),
    functions=bug_bounty_functions,
    parallel_tool_calls=False,
)
