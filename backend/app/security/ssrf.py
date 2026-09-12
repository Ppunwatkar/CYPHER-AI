"""
CIPHER AI - Outbound Network Security & SSRF Protection Gateway
Enforces centralized outbound request policy against SSRF, internal network scanning,
cloud metadata exfiltration (AWS/GCP/Azure), loopback traversal, and IPv6 remapping.
"""

import ipaddress
import socket
from typing import List, Optional, Tuple
from urllib.parse import urlsplit


# Cloud provider metadata endpoints & internal naming services
BLOCKED_HOSTNAMES = frozenset([
    "localhost",
    "metadata.google.internal",
    "metadata",
    "instance-data",
    "host.docker.internal",
    "gateway.docker.internal",
    "kubernetes.default",
    "kubernetes.default.svc",
])

# Prohibited destination networks and special-purpose prefixes
BLOCKED_NETWORKS = [
    # IPv4 RFC 1918 Private
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # IPv4 Loopback & Local
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    # IPv4 Link-Local & Cloud Metadata (RFC 3927)
    ipaddress.ip_network("169.254.0.0/16"),
    # IPv4 Documentation & Benchmark
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    # IPv4 Multicast & Future use
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    # IPv4 Broadcast
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6 Loopback & Unspecified
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    # IPv6 Unique Local Address (ULA - RFC 4193)
    ipaddress.ip_network("fc00::/7"),
    # IPv6 Link-Local
    ipaddress.ip_network("fe80::/10"),
    # IPv6 Documentation
    ipaddress.ip_network("2001:db8::/32"),
]


def is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, Optional[str]]:
    """
    Evaluates whether an IPv4 or IPv6 address belongs to a prohibited or private network.
    Unwraps IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1) for inspection.
    """
    # Unpack IPv4-mapped IPv6 (::ffff:192.0.2.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if ip.is_loopback:
        return True, "Loopback addresses (127.0.0.0/8, ::1) are strictly prohibited."

    if ip.is_private:
        return True, "Private RFC1918 / ULA internal network addresses are strictly prohibited."

    if ip.is_link_local:
        return True, "Link-local / cloud metadata network addresses (169.254.0.0/16) are strictly prohibited."

    if ip.is_multicast:
        return True, "Multicast addresses are prohibited."

    if ip.is_reserved:
        return True, "IETF reserved addresses are prohibited."

    if ip.is_unspecified:
        return True, "Unspecified wildcard addresses (0.0.0.0, ::) are prohibited."

    # Direct network block matching
    for network in BLOCKED_NETWORKS:
        if ip in network:
            return True, f"Address falls within prohibited network block: {network}"

    return False, None


def resolve_all_ips(hostname: str) -> List[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """
    Resolves hostname to all corresponding IPv4 and IPv6 addresses.
    Handles numeric/hex/octal representations via ipaddress.ip_address parsing.
    """
    # Check if hostname is directly a numeric or encoded IP string
    try:
        parsed_ip = ipaddress.ip_address(hostname)
        return [parsed_ip]
    except ValueError:
        pass

    # Resolve via system DNS
    try:
        addr_info = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )
    except socket.gaierror as err:
        raise ValueError(f"DNS resolution failure for host '{hostname}': {err}") from err

    ips = []
    seen = set()
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        if ip_str not in seen:
            seen.add(ip_str)
            try:
                ips.append(ipaddress.ip_address(ip_str))
            except ValueError:
                continue

    if not ips:
        raise ValueError(f"No IP addresses could be resolved for host '{hostname}'.")

    return ips


def validate_outbound_url(url: str) -> Tuple[bool, Optional[str]]:
    """
    Validates that a URL is safe for server-side outbound requests.
    Enforces scheme allowlist, hostname restrictions, DNS resolution, and IP boundary checks.

    Returns (True, None) if safe, or (False, "Reason") if prohibited.
    """
    if not url or not isinstance(url, str):
        return False, "URL must be a non-empty string."

    url_clean = url.strip()
    if len(url_clean) > 2048:
        return False, "URL length exceeds safety threshold (2048 characters)."

    try:
        parsed = urlsplit(url_clean)
    except Exception as err:
        return False, f"Malformed URL: {err}"

    # 1. Scheme Validation
    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Unsupported URL scheme '{parsed.scheme}'. Only http and https are allowed."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL does not specify a valid hostname."

    hostname_clean = hostname.strip().lower()

    # 2. Blocked Hostnames & Internal Domains
    if hostname_clean in BLOCKED_HOSTNAMES:
        return False, f"Destination hostname '{hostname_clean}' is prohibited (internal / metadata service)."

    if hostname_clean.endswith(".internal") or hostname_clean.endswith(".local"):
        return False, f"Internal domain suffix in '{hostname_clean}' is prohibited."

    # 3. Resolve and inspect all target IPs
    try:
        resolved_ips = resolve_all_ips(hostname_clean)
    except ValueError as val_err:
        return False, str(val_err)

    for ip in resolved_ips:
        blocked, reason = is_ip_blocked(ip)
        if blocked:
            return False, f"Resolved address '{ip}' is blocked: {reason}"

    return True, None
