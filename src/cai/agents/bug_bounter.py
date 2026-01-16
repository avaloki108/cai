"""Red Team Base Agent"""
import os
from dotenv import load_dotenv
from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
from openai import AsyncOpenAI
from cai.util import load_prompt_template, create_system_prompt_renderer
from cai.tools.command_and_control.sshpass import (  # pylint: disable=import-error # noqa: E501
    run_ssh_command_with_credentials
)

from cai.tools.reconnaissance.generic_linux_command import (  # pylint: disable=import-error # noqa: E501
    generic_linux_command
)
from cai.tools.web.search_web import (  # pylint: disable=import-error # noqa: E501
    make_google_search
)

from cai.tools.reconnaissance.exec_code import (  # pylint: disable=import-error # noqa: E501
    execute_code
)

from cai.tools.reconnaissance.shodan import (  # pylint: disable=import-error # noqa: E501
    shodan_search,
    shodan_host_info
)

from cai.tools.web3_security import (  # pylint: disable=import-error # noqa: E501
    slither_analyze,
    slither_check_upgradeability,
    mythril_analyze,
    mythril_disassemble,
    mythril_read_storage,
    securify_analyze,
    securify_compliance_check,
    echidna_fuzz,
    echidna_assertion_mode,
    echidna_coverage,
    medusa_fuzz,
    medusa_init,
    medusa_test,
    fuzz_utils_run,
    generate_fuzz_seeds,
    minimize_fuzz_corpus,
    analyze_fuzz_coverage,
    gambit_analyze,
    gambit_verify_property,
    gambit_explore_paths,
    clorgetizer_analyze,
    clorgetizer_compare_versions,
    clorgetizer_optimize,
    certora_verify,
    certora_run_tests,
    certora_check_invariants,
    oyente_analyze,
    oyente_check_vulnerability,
    oyente_compare_contracts,
    auditor_run_audit,
    auditor_check_compliance,
    auditor_generate_report,
    auditor_scan_dependencies,
    validate_finding,
    filter_false_positives,
    scribble_run,
)

from cai.agents.guardrails import get_security_guardrails

load_dotenv()

# Determine API key
api_key = os.getenv("ALIAS_API_KEY", os.getenv("OPENAI_API_KEY", "sk-alias-1234567890"))
# Prompts
bug_bounter_system_prompt = load_prompt_template("prompts/system_bug_bounter.md")
# Define tools list based on available API keys
tools = [
    generic_linux_command,
    execute_code,
    shodan_search,
    shodan_host_info,
    # Web3 Security Tools
    slither_analyze,
    slither_check_upgradeability,
    mythril_analyze,
    mythril_disassemble,
    mythril_read_storage,
    securify_analyze,
    securify_compliance_check,
    echidna_fuzz,
    echidna_assertion_mode,
    echidna_coverage,
    medusa_fuzz,
    medusa_init,
    medusa_test,
    fuzz_utils_run,
    generate_fuzz_seeds,
    minimize_fuzz_corpus,
    analyze_fuzz_coverage,
    gambit_analyze,
    gambit_verify_property,
    gambit_explore_paths,
    clorgetizer_analyze,
    clorgetizer_compare_versions,
    clorgetizer_optimize,
    certora_verify,
    certora_run_tests,
    certora_check_invariants,
    oyente_analyze,
    oyente_check_vulnerability,
    oyente_compare_contracts,
    auditor_run_audit,
    auditor_check_compliance,
    auditor_generate_report,
    auditor_scan_dependencies,
    # Validation Tools
    validate_finding,
    filter_false_positives,
    # Instrumentation
    scribble_run,
]

if os.getenv('GOOGLE_SEARCH_API_KEY') and os.getenv('GOOGLE_SEARCH_CX'):
    tools.append(make_google_search)

# Get security guardrails
input_guardrails, output_guardrails = get_security_guardrails()

bug_bounter_agent = Agent(
    name="Bug Bounter",
    instructions=create_system_prompt_renderer(bug_bounter_system_prompt),
    description="""Agent that specializes in bug bounty hunting and vulnerability discovery.
                   Expert in web security, API testing, and responsible disclosure.""",
    tools=tools,
    input_guardrails=input_guardrails,
    output_guardrails=output_guardrails,
    model=OpenAIChatCompletionsModel(
        model=os.getenv('CAI_MODEL', "alias1"),
        openai_client=AsyncOpenAI(api_key=api_key),
    )
   
)
