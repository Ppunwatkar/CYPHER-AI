"""
CIPHER AI - Authoritative Security Observable Normalization Engine
Provides safe, offline normalization and canonical validation for security indicators.
Strictly zero-execution: never resolves DNS, executes URLs, or performs network connections.
"""

from dataclasses import dataclass
import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlsplit, urlunsplit


# Regex patterns for fast pre-validation
CVE_PATTERN = re.compile(r"^CVE-(\d{4})-(\d{4,7})$", re.IGNORECASE)
MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
DOMAIN_LABEL_PATTERN = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


@dataclass(frozen=True)
class NormalizedResult:
    """Immutable result object from normalization operation."""
    is_valid: bool
    normalized_value: str
    original_value: str
    detected_type: str
    error_message: Optional[str] = None


def defang_input(raw: str) -> str:
    """
    Safely neutralizes defensive defanging notation into canonical format:
    - Strips surrounding quotes or whitespace
    - Normalizes bracket dots: `185[.]220[.]101[.]5` -> `185.220.101.5`
    - Normalizes bracket colons: `http[:]//` -> `http://`
    - Normalizes bracket at: `user[@]domain.com` -> `user@domain.com`
    - Normalizes defanged schemes: `hxxp://` -> `http://`, `hxxps://` -> `https://`
    """
    cleaned = raw.strip()
    # Strip enclosing single/double quotes
    cleaned = re.sub(r"^['\"]+|['\"]+$", "", cleaned)

    # Defang bracket notations
    cleaned = re.sub(r"\[\.\]|\(\.\)", ".", cleaned)
    cleaned = re.sub(r"\[:\]|\(:\)", ":", cleaned)
    cleaned = re.sub(r"\[@\]|\(@\)", "@", cleaned)

    # Defang scheme prefixes
    cleaned = re.sub(r"^hxxps://", "https://", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^hxxp://", "http://", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^hXXps://", "https://", cleaned)
    cleaned = re.sub(r"^hXXp://", "http://", cleaned)

    return cleaned.strip()


def normalize_ipv4(val: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validates and normalizes an IPv4 address.
    Strips trailing port if present (e.g. '1.2.3.4:8080' -> '1.2.3.4').
    """
    cleaned = defang_input(val)
    # Strip port if present in IP:port format
    if ":" in cleaned:
        parts = cleaned.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            cleaned = parts[0]

    try:
        ip = ipaddress.IPv4Address(cleaned)
        return True, str(ip), None
    except (ipaddress.AddressValueError, ValueError) as exc:
        return False, val, f"Invalid IPv4 address format: {exc}"


def normalize_ipv6(val: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validates and normalizes an IPv6 address.
    Strips bracket notation and optional port suffix (e.g. '[2001:db8::1]:8080' -> '2001:db8::1').
    """
    cleaned = defang_input(val)
    # Handle bracket notation [ipv6]:port or [ipv6]
    if cleaned.startswith("["):
        bracket_match = re.match(r"^\[([a-fA-F0-9:]+)\](?::\d+)?$", cleaned)
        if bracket_match:
            cleaned = bracket_match.group(1)

    try:
        ip = ipaddress.IPv6Address(cleaned)
        # Canonical lowercase compressed IPv6 representation
        return True, str(ip).lower(), None
    except (ipaddress.AddressValueError, ValueError) as exc:
        return False, val, f"Invalid IPv6 address format: {exc}"


def normalize_cidr(val: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validates and normalizes an IPv4 or IPv6 CIDR block.
    """
    cleaned = defang_input(val)
    if "/" not in cleaned:
        return False, val, "CIDR notation must contain a subnet prefix delimiter ('/')"

    try:
        network = ipaddress.ip_network(cleaned, strict=False)
        return True, str(network), None
    except (ipaddress.NetmaskValueError, ValueError) as exc:
        return False, val, f"Invalid CIDR network specification: {exc}"


def normalize_domain(val: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validates and normalizes a domain name (FQDN).
    Normalizes to lowercase, strips protocols/ports if mistakenly included.
    """
    cleaned = defang_input(val).lower()
    # Strip scheme if present
    cleaned = re.sub(r"^https?://", "", cleaned)
    # Strip path or query string
    cleaned = cleaned.split("/")[0].split("?")[0]
    # Strip port if present
    if ":" in cleaned:
        cleaned = cleaned.split(":")[0]
    # Strip trailing dot
    cleaned = cleaned.rstrip(".")

    if not cleaned or len(cleaned) > 253:
        return False, val, "Domain name length must be between 1 and 253 characters."

    labels = cleaned.split(".")
    if len(labels) < 2:
        return False, val, "Domain must contain at least two labels separated by a dot."

    for label in labels:
        if not label or len(label) > 63:
            return False, val, f"Domain label '{label}' must be between 1 and 63 characters."
        if not DOMAIN_LABEL_PATTERN.match(label):
            return False, val, f"Domain label '{label}' contains invalid characters or formatting."

    # Verify TLD is not numeric
    if labels[-1].isdigit():
        return False, val, "Top-level domain (TLD) cannot be purely numeric."

    return True, cleaned, None


def normalize_url(val: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validates and normalizes a URL.
    Ensures safe parsing without making any network connection or DNS resolution.
    Normalizes scheme and host to lowercase.
    """
    cleaned = defang_input(val)

    if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
        return False, val, "URL must start with a valid 'http://' or 'https://' scheme."

    try:
        parsed = urlsplit(cleaned)
    except Exception as exc:
        return False, val, f"Failed to parse URL structure: {exc}"

    if not parsed.netloc:
        return False, val, "URL must contain a valid host/authority component."

    # Normalize scheme and host to lowercase
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"

    normalized = urlunsplit((scheme, netloc, path, parsed.query, parsed.fragment))
    return True, normalized, None


def normalize_hash(val: str, expected_type: Optional[str] = None) -> Tuple[bool, str, Optional[str], str]:
    """
    Validates and normalizes cryptographic hashes (MD5, SHA-1, SHA-256).
    Returns (is_valid, normalized_value, error_message, detected_hash_type).
    """
    cleaned = defang_input(val).strip().lower()

    if SHA256_PATTERN.match(cleaned):
        if expected_type and expected_type.lower() not in ("hash", "sha256"):
            return False, val, f"Expected {expected_type}, but provided value matches SHA-256.", "sha256"
        return True, cleaned, None, "sha256"

    if SHA1_PATTERN.match(cleaned):
        if expected_type and expected_type.lower() not in ("hash", "sha1"):
            return False, val, f"Expected {expected_type}, but provided value matches SHA-1.", "sha1"
        return True, cleaned, None, "sha1"

    if MD5_PATTERN.match(cleaned):
        if expected_type and expected_type.lower() not in ("hash", "md5"):
            return False, val, f"Expected {expected_type}, but provided value matches MD5.", "md5"
        return True, cleaned, None, "md5"

    return False, val, "Value does not match valid hex length for MD5 (32), SHA-1 (40), or SHA-256 (64).", "hash"


def normalize_cve(val: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validates and normalizes Common Vulnerabilities and Exposures (CVE) identifier.
    Canonical format: 'CVE-YYYY-NNNN+' in uppercase.
    """
    cleaned = defang_input(val).strip().upper()
    match = CVE_PATTERN.match(cleaned)
    if not match:
        return False, val, "Value must follow standard format: CVE-YYYY-NNNN (e.g. CVE-2024-38077)."

    year = int(match.group(1))
    if year < 1999 or year > 2099:
        return False, val, f"CVE year '{year}' is outside valid range (1999-2099)."

    return True, cleaned, None


def auto_detect_type(val: str) -> str:
    """
    Infers the observable/target type from raw value structure.
    """
    cleaned = defang_input(val)

    # 1. CVE
    if CVE_PATTERN.match(cleaned):
        return "cve"

    # 2. Hash
    if SHA256_PATTERN.match(cleaned):
        return "sha256"
    if SHA1_PATTERN.match(cleaned):
        return "sha1"
    if MD5_PATTERN.match(cleaned):
        return "md5"

    # 3. URL
    if cleaned.lower().startswith("http://") or cleaned.lower().startswith("https://"):
        return "url"

    # 4. CIDR
    if "/" in cleaned:
        ok, _, _ = normalize_cidr(cleaned)
        if ok:
            return "cidr"

    # 5. IPv4
    ok, _, _ = normalize_ipv4(cleaned)
    if ok:
        return "ipv4"

    # 6. IPv6
    ok, _, _ = normalize_ipv6(cleaned)
    if ok:
        return "ipv6"

    # 7. Domain
    ok, _, _ = normalize_domain(cleaned)
    if ok:
        return "domain"

    # Fallback to hostname if valid single label or alphanumeric
    if re.match(r"^[a-zA-Z0-9_-]+$", cleaned):
        return "hostname"

    return "unknown"


def normalize_indicator(raw_value: str, indicator_type: Optional[str] = None) -> NormalizedResult:
    """
    Master authoritative normalization gateway for all indicators and security targets.
    """
    if not raw_value or not raw_value.strip():
        return NormalizedResult(
            is_valid=False,
            normalized_value="",
            original_value=raw_value or "",
            detected_type=indicator_type or "unknown",
            error_message="Indicator value cannot be empty.",
        )

    target_type = (indicator_type or "").strip().lower()
    if not target_type or target_type == "unknown":
        target_type = auto_detect_type(raw_value)

    # Normalize based on determined type
    if target_type in ("ipv4", "ip"):
        is_valid, norm_val, err = normalize_ipv4(raw_value)
        # If expected type was general 'ip', try IPv6 if IPv4 failed
        if not is_valid and indicator_type in ("ip", None):
            is_v6, norm_v6, err_v6 = normalize_ipv6(raw_value)
            if is_v6:
                return NormalizedResult(True, norm_v6, raw_value, "ipv6", None)
        return NormalizedResult(is_valid, norm_val, raw_value, "ipv4", err)

    if target_type == "ipv6":
        is_valid, norm_val, err = normalize_ipv6(raw_value)
        return NormalizedResult(is_valid, norm_val, raw_value, "ipv6", err)

    if target_type == "cidr":
        is_valid, norm_val, err = normalize_cidr(raw_value)
        return NormalizedResult(is_valid, norm_val, raw_value, "cidr", err)

    if target_type == "domain":
        is_valid, norm_val, err = normalize_domain(raw_value)
        return NormalizedResult(is_valid, norm_val, raw_value, "domain", err)

    if target_type == "url":
        is_valid, norm_val, err = normalize_url(raw_value)
        return NormalizedResult(is_valid, norm_val, raw_value, "url", err)

    if target_type in ("hash", "sha256", "sha1", "md5"):
        is_valid, norm_val, err, detected_sub = normalize_hash(raw_value, target_type)
        return NormalizedResult(is_valid, norm_val, raw_value, detected_sub, err)

    if target_type == "cve":
        is_valid, norm_val, err = normalize_cve(raw_value)
        return NormalizedResult(is_valid, norm_val, raw_value, "cve", err)

    if target_type in ("hostname", "cloud_asset"):
        cleaned = defang_input(raw_value).strip()
        if cleaned:
            return NormalizedResult(True, cleaned, raw_value, target_type, None)
        return NormalizedResult(False, raw_value, raw_value, target_type, "Value cannot be empty.")

    return NormalizedResult(
        is_valid=False,
        normalized_value=raw_value,
        original_value=raw_value,
        detected_type=target_type,
        error_message=f"Unsupported indicator type: '{target_type}'.",
    )
