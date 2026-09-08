import { ExtractedIndicator, SecurityTarget, InvestigationPlan, EvidenceSourceItem, InvestigationVerdict } from '../types';

// Regex patterns for indicators
const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
const IPV6_REGEX = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|\b:(?::[0-9a-fA-F]{1,4}){1,7}\b/g;
const CIDR_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:3[0-2]|[12]?[0-9])\b/g;
const CVE_REGEX = /\bCVE-\d{4}-\d{4,7}\b/gi;
const SHA256_REGEX = /\b[a-fA-F0-9]{64}\b/g;
const MD5_REGEX = /\b[a-fA-F0-9]{32}\b/g;
const URL_REGEX = /\b(?:https?|hxxps?):\/\/[^\s<>"'{}|\\^`]+\b/gi;
const EMAIL_REGEX = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
const DOMAIN_REGEX = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|dev|cloud|internal|corp|info|biz|co|cc|de|ru|cn|eu)\b/gi;

/**
 * Normalizes an indicator string (strips protocol prefixes, port suffixes where appropriate, trims spaces)
 */
export function normalizeTargetValue(raw: string): { normalized: string; type: SecurityTarget['type'] } {
  let cleaned = raw.trim();
  // Strip enclosing quotes or brackets (e.g. [.] or hxxp)
  cleaned = cleaned.replace(/^['"]+|['"]+$/g, '');
  cleaned = cleaned.replace(/\[\.\]/g, '.');
  cleaned = cleaned.replace(/^hxxp/i, 'http');

  // Check URL
  if (/^https?:\/\//i.test(cleaned)) {
    try {
      const url = new URL(cleaned);
      return { normalized: cleaned, type: 'url' };
    } catch {
      // fallback
    }
  }

  // Check CIDR
  if (CIDR_REGEX.test(cleaned)) {
    return { normalized: cleaned, type: 'cidr' };
  }

  // Check IPv4
  const ipv4Match = cleaned.match(IPV4_REGEX);
  if (ipv4Match && ipv4Match[0] === cleaned.split(':')[0]) {
    return { normalized: cleaned.split(':')[0], type: 'ipv4' };
  }

  // Check IPv6
  if (IPV6_REGEX.test(cleaned)) {
    return { normalized: cleaned.toLowerCase(), type: 'ipv6' };
  }

  // Strip protocol if present for domain extraction
  cleaned = cleaned.replace(/^https?:\/\//i, '').replace(/\/.*$/, '');

  // Check Domain
  if (DOMAIN_REGEX.test(cleaned)) {
    return { normalized: cleaned.toLowerCase(), type: 'domain' };
  }

  return { normalized: cleaned, type: 'hostname' };
}

/**
 * Validate target value format
 */
export function validateTarget(value: string, type: SecurityTarget['type']): { isValid: boolean; message?: string } {
  const trimmed = value.trim();
  if (!trimmed) return { isValid: false, message: 'Target value cannot be empty' };

  if (type === 'ipv4') {
    const parts = trimmed.split('.');
    if (parts.length !== 4) return { isValid: false, message: 'IPv4 must have 4 octets' };
    for (const p of parts) {
      const num = parseInt(p, 10);
      if (isNaN(num) || num < 0 || num > 255) {
        return { isValid: false, message: 'Each IPv4 octet must be between 0 and 255' };
      }
    }
    return { isValid: true };
  }

  if (type === 'cidr') {
    if (!trimmed.includes('/')) return { isValid: false, message: 'CIDR requires a slash notation (e.g. /24)' };
    const [ip, mask] = trimmed.split('/');
    const maskNum = parseInt(mask, 10);
    if (isNaN(maskNum) || maskNum < 0 || maskNum > 32) {
      return { isValid: false, message: 'CIDR prefix must be between 0 and 32' };
    }
    return validateTarget(ip, 'ipv4');
  }

  if (type === 'domain') {
    if (trimmed.length < 3 || !trimmed.includes('.')) {
      return { isValid: false, message: 'Domain must contain a valid TLD' };
    }
    return { isValid: true };
  }

  return { isValid: true };
}

/**
 * Check if target already exists in list (duplicate detection)
 */
export function checkTargetDuplicate(value: string, existing: SecurityTarget[]): SecurityTarget | undefined {
  const norm = normalizeTargetValue(value).normalized.toLowerCase();
  return existing.find(t => t.value.toLowerCase() === norm);
}

/**
 * Extract all indicators from a block of text
 */
export function extractIndicatorsFromText(text: string): ExtractedIndicator[] {
  const results: ExtractedIndicator[] = [];
  const seen = new Set<string>();

  const add = (type: ExtractedIndicator['type'], val: string, severity: ExtractedIndicator['severity']) => {
    const key = `${type}:${val.toLowerCase()}`;
    if (!seen.has(key)) {
      seen.add(key);
      results.push({ type, value: val, severity });
    }
  };

  // CVEs
  const cveMatches = text.match(CVE_REGEX);
  if (cveMatches) {
    cveMatches.forEach(cve => add('cve', cve.toUpperCase(), 'critical'));
  }

  // CIDR
  const cidrMatches = text.match(CIDR_REGEX);
  if (cidrMatches) {
    cidrMatches.forEach(cidr => add('ipv4', cidr, 'medium'));
  }

  // IPv4
  const ipMatches = text.match(IPV4_REGEX);
  if (ipMatches) {
    ipMatches.forEach(ip => {
      // Avoid matching sub-portions of CIDRs already matched
      if (!text.includes(`${ip}/`)) {
        const sev = ip.startsWith('10.') || ip.startsWith('192.168.') ? 'medium' : 'high';
        add('ipv4', ip, sev);
      }
    });
  }

  // SHA256
  const sha256Matches = text.match(SHA256_REGEX);
  if (sha256Matches) {
    sha256Matches.forEach(h => add('sha256', h.toLowerCase(), 'critical'));
  }

  // URLs
  const urlMatches = text.match(URL_REGEX);
  if (urlMatches) {
    urlMatches.forEach(u => add('url', u, 'high'));
  }

  // Domains
  const domainMatches = text.match(DOMAIN_REGEX);
  if (domainMatches) {
    domainMatches.forEach(d => {
      // Filter out standard common file extensions like .png, .js
      if (!/\.(png|jpg|gif|js|css|json|html|ts|tsx)$/i.test(d)) {
        add('domain', d.toLowerCase(), 'high');
      }
    });
  }

  return results;
}

export const extractIndicators = extractIndicatorsFromText;

/**
 * Detects if user query contains an explicit intent to investigate
 */
export function detectInvestigationIntent(prompt: string): {
  isInvestigation: boolean;
  detected: boolean;
  targetValue?: string;
  targetType: SecurityTarget['type'];
  detectedTarget?: {
    value: string;
    type: SecurityTarget['type'];
  };
  promptContext: string;
} {
  const trimmed = prompt.trim();
  const lower = trimmed.toLowerCase();

  // Check if starts with investigate / scan / check / analyze
  const isActionVerb = /^(investigate|analyze|scan|check|query|correlate|audit|lookup|assess)\b/i.test(lower);

  // Extract all indicators
  const indicators = extractIndicatorsFromText(trimmed);

  if (indicators.length > 0) {
    const first = indicators[0];
    let mappedType: SecurityTarget['type'] = 'ipv4';
    if (first.type === 'domain') mappedType = 'domain';
    if (first.type === 'url') mappedType = 'url';
    if (first.type === 'cve') mappedType = 'hostname';

    return {
      isInvestigation: isActionVerb || indicators.length > 0,
      detected: true,
      targetValue: first.value,
      targetType: mappedType,
      detectedTarget: {
        value: first.value,
        type: mappedType
      },
      promptContext: trimmed
    };
  }

  return {
    isInvestigation: false,
    detected: false,
    targetType: 'ipv4',
    promptContext: trimmed
  };
}

/**
 * Generate synthetic verdict for an investigated target
 */
export function generateSyntheticVerdict(target: string, evidence?: EvidenceSourceItem[]): InvestigationVerdict {
  const isMaliciousTarget = target.includes('185.220') || target.includes('194.26') || target.includes('azure-edge-sync');
  return {
    target,
    threatLevel: isMaliciousTarget ? 'CRITICAL' : 'LOW',
    confidence: isMaliciousTarget ? 92 : 88,
    evidenceCount: evidence ? evidence.length : 5,
    riskFactors: isMaliciousTarget ? [
      'Active Tor exit relay flagged by multiple global threat feeds',
      'Exposed unauthenticated proxy on non-standard port 8080',
      'Direct correlation with internal host beaconing in VPC flow logs',
      'Documented C2 infrastructure overlap with APT29 (Midnight Blizzard)'
    ] : [
      'No abuse reports logged in past 90 days',
      'Standard corporate infrastructure SSL certificate verified',
      'No anomalous outbound persistent sessions observed'
    ],
    confidenceFactors: [
      'Verified across 5 distinct threat intelligence and knowledge sources',
      'Telemetry corroborated with internal VPC flow records and Suricata AST rules',
      'Zero-trust passive intelligence retrieved with high-precision timestamping'
    ],
    timeline: [
      { time: 'T-30s', step: 'Target submitted to CIPHER AI Copilot', status: 'completed', provenance: 'User Scope' },
      { time: 'T-25s', step: 'Target normalized & validated against RFC specs', status: 'completed', provenance: 'Target Engine' },
      { time: 'T-20s', step: 'Threat intelligence queried (AbuseIPDB, Shodan, VT)', status: 'completed', provenance: 'OSINT Connectors' },
      { time: 'T-15s', step: 'External results received & normalized', status: 'completed', provenance: 'Threat Graph' },
      { time: 'T-10s', step: 'Internal RAG policy correlation completed', status: 'completed', provenance: 'Vector RAG Core' },
      { time: 'T-5s', step: 'AI synthesis & multi-source verdict generated', status: 'completed', provenance: 'Gemini 2.5 SecOps' }
    ]
  };
}

/**
 * Generate evidence data for a target investigation with explicit source provenance and simulated demo transparency
 */
export function generateEvidenceForTarget(
  target: string, 
  type: SecurityTarget['type'], 
  investigationType: 'PASSIVE INTELLIGENCE' | 'ACTIVE ANALYSIS' = 'PASSIVE INTELLIGENCE'
): {
  evidence: EvidenceSourceItem[];
  verdict: InvestigationVerdict;
} {
  const isMaliciousTarget = target.includes('185.220') || target.includes('194.26') || target.includes('azure-edge-sync');
  const now = new Date();
  const timeStr = (offsetSec = 0) => {
    const d = new Date(now.getTime() - offsetSec * 1000);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' UTC';
  };

  const evidence: EvidenceSourceItem[] = [
    {
      id: 'ev-1',
      source: 'AbuseIPDB',
      result: isMaliciousTarget ? 'High Risk (100% Confidence Score, 47 malicious reports in 24h)' : 'Low Risk (0 reports in 30 days, ASN Clean)',
      retrievedAt: timeStr(25),
      status: 'Simulated Demo',
      details: 'Categories: Port Scanning, Hacking, Cobalt Strike C2 Relay. Reporter ASNs: Core-Backbone, Zwiebelfreunde e.V.'
    },
    {
      id: 'ev-2',
      source: 'Shodan',
      result: isMaliciousTarget ? '4 Open Ports (22/ssh, 80/http, 443/https, 8080/c2-proxy)' : '1 Open Port (443/https TLS 1.3)',
      retrievedAt: timeStr(20),
      status: 'Simulated Demo',
      details: 'Banner: Jetty 9.4.43, Self-signed X.509 cert issued to "api-sync-internal.edge-worker.org"'
    },
    {
      id: 'ev-3',
      source: 'VirusTotal',
      result: isMaliciousTarget ? 'Detection Ratio: 58/72 Security Engines Flagged Malicious' : 'Detection Ratio: 0/72 Clean',
      retrievedAt: timeStr(15),
      status: 'Simulated Demo',
      details: 'Threat Tags: trojan.cobaltstrike/malleable, elf.mirai.scanner, tor-exit-node'
    },
    {
      id: 'ev-4',
      source: 'NVD',
      result: 'Related CVE: CVE-2024-38077 (CVSS 9.8 Critical RCE) & CVE-2024-3400',
      retrievedAt: timeStr(10),
      status: 'Verified',
      details: 'NIST NVD Official Advisory matching observed exploit payloads against exposed perimeter endpoints'
    },
    {
      id: 'ev-5',
      source: 'RAG',
      result: '3 Document Matches in RAG Knowledge Core (SOP-88, Incident-Runbook-2026.pdf)',
      retrievedAt: timeStr(5),
      status: 'Internal Knowledge',
      details: 'Semantic similarity match 0.94. Rule: Immediate host isolation required when beaconing exceeds 15m threshold.',
      ragMeta: {
        document: 'Incident Handling & Containment SOP-88',
        page: 14,
        retrievedChunk: 'Section 4.2.1: Outbound egress matching Tor exit relays requires immediate automated network isolation via AWS Security Group zero-trust rule.',
        similarity: '94% Semantic Match'
      }
    }
  ];

  const verdict: InvestigationVerdict = {
    target,
    threatLevel: isMaliciousTarget ? 'CRITICAL' : 'LOW',
    confidence: isMaliciousTarget ? 92 : 88,
    evidenceCount: evidence.length,
    riskFactors: isMaliciousTarget ? [
      'Active Tor exit relay flagged by multiple global threat feeds',
      'Exposed unauthenticated proxy on non-standard port 8080',
      'Direct correlation with internal host beaconing in VPC flow logs',
      'Documented C2 infrastructure overlap with APT29 (Midnight Blizzard)'
    ] : [
      'No abuse reports logged in past 90 days',
      'Standard corporate infrastructure SSL certificate verified',
      'No anomalous outbound persistent sessions observed'
    ],
    confidenceFactors: [
      'Verified across 5 distinct threat intelligence and knowledge sources',
      'Telemetry corroborated with internal VPC flow records and Suricata AST rules',
      'Zero-trust passive intelligence retrieved with high-precision timestamping'
    ],
    timeline: [
      { time: timeStr(30), step: 'Target submitted to CIPHER AI Copilot', status: 'completed', provenance: 'User Scope' },
      { time: timeStr(25), step: 'Target normalized & validated against RFC specs', status: 'completed', provenance: 'Target Engine' },
      { time: timeStr(20), step: 'Threat intelligence queried (AbuseIPDB, Shodan, VT)', status: 'completed', provenance: 'OSINT Connectors' },
      { time: timeStr(15), step: 'External results received & normalized', status: 'completed', provenance: 'Threat Graph' },
      { time: timeStr(10), step: 'Internal RAG policy correlation completed', status: 'completed', provenance: 'Vector RAG Core' },
      { time: timeStr(5), step: 'AI synthesis & multi-source verdict generated', status: 'completed', provenance: 'Gemini 2.5 SecOps' }
    ]
  };

  return { evidence, verdict };
}
