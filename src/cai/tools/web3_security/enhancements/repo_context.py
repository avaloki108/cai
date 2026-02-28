import json
import os
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
from cai.sdk.agents import function_tool


def _exists(repo: Path, rel: str) -> bool:
    return (repo / rel).exists()


def _read_text(p: Path, max_bytes: int = 200_000) -> str:
    try:
        data = p.read_bytes()
        return data[:max_bytes].decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _glob_read(repo: Path, patterns: List[str], limit_files: int = 80) -> List[str]:
    out = []
    count = 0
    for pat in patterns:
        for p in repo.rglob(pat):
            if p.is_file():
                out.append(_read_text(p))
                count += 1
                if count >= limit_files:
                    return out
    return out


def _detect_framework(repo: Path) -> str:
    # Foundry
    if _exists(repo, "foundry.toml") or _exists(repo, "forge.toml"):
        return "foundry"
    # Hardhat
    if _exists(repo, "hardhat.config.js") or _exists(repo, "hardhat.config.ts"):
        return "hardhat"
    # Truffle
    if _exists(repo, "truffle-config.js") or _exists(repo, "truffle.js"):
        return "truffle"
    # Brownie
    if _exists(repo, "brownie-config.yaml") or _exists(repo, "brownie-config.yml"):
        return "brownie"
    # Generic node project
    if _exists(repo, "package.json"):
        return "node"
    return "unknown"


def _detect_tests(repo: Path) -> Dict[str, Any]:
    return {
        "has_foundry_tests": (repo / "test").exists() and any(repo.joinpath("test").rglob("*.t.sol")),
        "has_hardhat_tests": (repo / "test").exists() and any(repo.joinpath("test").rglob("*.js")) or any(repo.joinpath("test").rglob("*.ts")),
        "has_scripts": (repo / "script").exists() or (repo / "scripts").exists(),
    }


def _detect_solidity_versions(repo: Path) -> List[str]:
    versions = set()
    for p in list(repo.rglob("*.sol"))[:300]:
        txt = _read_text(p, 50_000)
        # pragma solidity ^0.8.19;
        m = re.findall(r"pragma\s+solidity\s+([^;]+);", txt)
        for v in m:
            versions.add(v.strip())
    return sorted(versions)[:10]


def _detect_upgradeability(repo: Path, corpus: List[str]) -> Dict[str, Any]:
    patterns = {
        "transparent_proxy": r"TransparentUpgradeableProxy|ProxyAdmin",
        "uups": r"UUPSUpgradeable|upgradeTo\(|_authorizeUpgrade",
        "beacon": r"UpgradeableBeacon|BeaconProxy",
        "initializer": r"\binitialize\(|\binitializer\b|\breinitializer\b",
        "delegatecall": r"\.delegatecall\s*\(",
        "diamond": r"DiamondCutFacet|IDiamondCut|EIP-2535",
    }
    hits = {k: False for k in patterns}
    for txt in corpus:
        for k, rx in patterns.items():
            if re.search(rx, txt):
                hits[k] = True
    uses_proxy = hits["transparent_proxy"] or hits["uups"] or hits["beacon"] or hits["diamond"]
    return {"uses_proxy": uses_proxy, "signals": hits}


def _detect_oracle_and_defi(repo: Path, corpus: List[str]) -> Dict[str, Any]:
    rx = {
        "chainlink": r"AggregatorV3Interface|latestRoundData|latestAnswer",
        "uniswap_v2": r"IUniswapV2|UniswapV2Pair|swapExactTokensForTokens",
        "uniswap_v3": r"IUniswapV3|uniswapV3SwapCallback|exactInputSingle",
        "aave": r"IPool|flashLoan|IFlashLoanReceiver",
        "compound": r"Comptroller|cToken|liquidateBorrow",
        "curve": r"ICurve|CurvePool",
        "pendle": r"IPMarket|Pendle",
        "lending": r"collateral|healthFactor|liquidat",
        "vault": r"convertToShares|convertToAssets|totalAssets|ERC4626",
        "bridge": r"bridge|messag|relayer|L1|L2|deposit|withdraw",
        "permit": r"\bpermit\(|EIP712|DOMAIN_SEPARATOR",
    }
    hits = {k: False for k in rx}
    for txt in corpus:
        for k, rxx in rx.items():
            if re.search(rxx, txt, flags=re.IGNORECASE):
                hits[k] = True
    # Rough protocol type inference
    protocol_type = "unknown"
    if hits["vault"]:
        protocol_type = "vault"
    elif hits["lending"]:
        protocol_type = "lending"
    elif hits["bridge"]:
        protocol_type = "bridge"
    elif hits["uniswap_v2"] or hits["uniswap_v3"] or hits["curve"]:
        protocol_type = "amm/dex"
    elif hits["pendle"]:
        protocol_type = "yield/derivative"
    return {"protocol_type": protocol_type, "signals": hits}


def _detect_roles(corpus: List[str]) -> Dict[str, Any]:
    rx = {
        "owner": r"\bonlyOwner\b|\bOwnable\b|owner\(\)|transferOwnership|_setOwner",
        "governance": r"onlyGovernance|governance\(\)|DAO|propose\(|vote\(|quorum|GovernorAlpha|GovernorBravo",
        "relayer": r"relayer|isRelayer|onlyRelayer|trustedRelayer|GSN|MetaTransaction",
        "admin": r"onlyAdmin|DEFAULT_ADMIN_ROLE|AccessControl",
        "pauser": r"onlyPauser|Pausable",
    }
    hits = {k: False for k in rx}
    for txt in corpus:
        for k, rxx in rx.items():
            if re.search(rxx, txt, flags=re.IGNORECASE):
                hits[k] = True
    
    roles_mapped = [k for k, v in hits.items() if v]
    return {"roles": roles_mapped, "signals": hits}


@function_tool
def detect_web3_repo_context(repo_path: str, ctf=None) -> str:
    """
    Repo auto-detection for cloned Web3 repos.
    Returns a context JSON suitable to feed into scoring/orchestration.

    Safe defaults:
    - mode=repo
    - assumed_live=false
    - tvl=null
    - validation=static_only
    """
    repo = Path(repo_path).expanduser().resolve()
    if not repo.exists() or not repo.is_dir():
        return json.dumps({"error": f"Repo path not found or not a directory: {repo}"}, indent=2)

    framework = _detect_framework(repo)
    tests = _detect_tests(repo)
    solidity_versions = _detect_solidity_versions(repo)

    # Build a small corpus for regex-based detection (fast, no AST)
    corpus = _glob_read(repo, ["*.sol", "foundry.toml", "hardhat.config.*", "package.json", "*.md"], limit_files=120)
    upgradeability = _detect_upgradeability(repo, corpus)
    defi = _detect_oracle_and_defi(repo, corpus)
    roles = _detect_roles(corpus)

    context: Dict[str, Any] = {
        "mode": "repo",
        "repo_path": str(repo),
        "framework": framework,
        "has_tests": bool(tests["has_foundry_tests"] or tests["has_hardhat_tests"]),
        "tests": tests,
        "solidity_versions": solidity_versions,
        "protocol_type": defi["protocol_type"],
        "roles": roles["roles"],
        "signals": {
            "upgradeability": upgradeability["signals"],
            "defi": defi["signals"],
            "roles": roles["signals"],
        },
        # Scoring defaults (don’t over-hype local-only results)
        "assumed_live": False,
        "tvl": None,
        "validation": "static_only",
        # Optional flags the exploit scorer can consume
        "requires_privileged_role": False,
        "already_initialized": None,
        "paused": None,
        "mitigated": None,
        "attacker_model": "EOA",
    }

    return json.dumps(context, indent=2)
