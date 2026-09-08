export type ScreenType = 
  | 'copilot' 
  | 'ioc-manager' 
  | 'security-intel'
  | 'threat-intel'
  | 'investigations'
  | 'agent-workflows'
  | 'rag-core'
  | 'target-inventory';


export interface IOCItem {
  id: string;
  value: string;
  type: 'ipv4' | 'ipv6' | 'domain' | 'sha256' | 'md5' | 'url' | 'cve';
  threatType: string;
  confidence: number; // 0 - 100
  severity: 'critical' | 'high' | 'medium' | 'low';
  firstSeen: string;
  lastSeen: string;
  source: string;
  asn?: string;
  country?: string;
  countryCode?: string;
  city?: string;
  tags: string[];
  status: 'active' | 'blocked' | 'investigating' | 'mitigated';
  maliciousHits: number;
  totalHits: number;
  threatActor?: string;
  associatedIncidents: string[];
  notes?: string;
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: string;
  model?: string;
  reasoningSteps?: {
    title: string;
    description: string;
    status: 'completed' | 'running' | 'pending';
    duration?: string;
    toolName?: string;
  }[];
  extractedArtifacts?: {
    type: 'ioc' | 'cve' | 'mitre' | 'command';
    label: string;
    value: string;
    severity?: string;
  }[];
  suggestedActions?: {
    label: string;
    action: string;
    type: 'primary' | 'destructive' | 'secondary';
  }[];
  investigationScope?: {
    target: string;
    targetType: SecurityTarget['type'];
    environment: SecurityTarget['environment'];
    status: 'pending_approval' | 'plan_ready' | 'executed' | 'cancelled';
  };
  investigationPlan?: InvestigationPlan;
  evidenceResult?: {
    evidence: EvidenceSourceItem[];
    verdict: InvestigationVerdict;
  };
  extractedIndicators?: ExtractedIndicator[];
  uploadedDocument?: {
    filename: string;
    sizeBytes: number;
    chunksCount: number;
    summary: string;
  };
}

export interface InvestigationCase {
  id: string;
  caseNumber: string;
  title: string;
  status: 'open' | 'contained' | 'investigating' | 'closed';
  severity: 'critical' | 'high' | 'medium' | 'low';
  leadAnalyst: string;
  createdAt: string;
  updatedAt: string;
  summary: string;
  targetAssets: string[];
  iocs: string[];
  mitreTactics: string[];
  assignedAiAgent: string;
  blastRadiusScore: number;
  timeline: {
    time: string;
    event: string;
    source: string;
    severity?: 'critical' | 'high' | 'medium' | 'low';
  }[];
}

export interface WorkflowNode {
  id: string;
  title: string;
  type: 'trigger' | 'enrichment' | 'ai_analysis' | 'hitl_approval' | 'remediation';
  status: 'completed' | 'in_progress' | 'pending' | 'waiting_approval' | 'failed';
  timestamp?: string;
  duration?: string;
  details?: string;
  toolUsed?: string;
}

export interface SecurityReport {
  id: string;
  title: string;
  type: 'post_mortem' | 'executive_brief' | 'threat_dossier' | 'compliance_audit';
  classification: 'TLP:AMBER' | 'TLP:RED' | 'TLP:GREEN' | 'TLP:CLEAR';
  createdDate: string;
  author: string;
  hashVerification: string;
  cvssScore: number;
  lateralExposure: string;
  affectedSystems: number;
  attackNarrative: string;
  mitreChain: {
    tactic: string;
    techniqueId: string;
    techniqueName: string;
    evidence: string;
  }[];
  remediationRoadmap: {
    phase: string;
    timeframe: string;
    actions: string[];
    status: 'completed' | 'in_progress' | 'planned';
  }[];
}

export interface UserProfile {
  id: string;
  name: string;
  email: string;
  role: string;
  organization: string;
  clearanceLevel: 'TLP:CLEAR' | 'TLP:GREEN' | 'TLP:AMBER' | 'TLP:RED' | 'TOP SECRET // TS-SCI';
  avatarInitials: string;
  sessionToken: string;
  createdAt: string;
}

export type TargetStatus = 
  | 'DISCOVERED' 
  | 'QUEUED' 
  | 'ANALYZING' 
  | 'ENRICHED' 
  | 'INVESTIGATED' 
  | 'MONITORED' 
  | 'RESOLVED';

export type InvestigationType = 'PASSIVE INTELLIGENCE' | 'ACTIVE ANALYSIS';

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export interface SecurityTarget {
  id: string;
  value: string;
  type: 'ipv4' | 'ipv6' | 'cidr' | 'domain' | 'hostname' | 'cloud_asset' | 'url';
  label: string;
  environment: 'production' | 'staging' | 'dmz' | 'external_threat' | 'internal_mesh';
  priority: 'critical' | 'high' | 'medium' | 'low';
  threatScore: number;
  verdict: 'malicious' | 'suspicious' | 'benign' | 'unknown' | 'under_scan';
  status: TargetStatus;
  owner: string;
  firstSeen: string;
  lastAnalyzed?: string;
  riskLevel: RiskLevel;
  confidence: number; // 0 - 100
  relatedIOCs?: string[];
  relatedCVEs?: string[];
  relatedInvestigations?: string[];
  investigationType?: InvestigationType;
  validationStatus?: 'valid' | 'invalid' | 'normalized';
  asn?: string;
  country?: string;
  city?: string;
  openPorts: number[];
  tags: string[];
  notes?: string;
  addedBy: string;
  addedAt: string;
  lastScannedAt: string;
  associatedIncidents?: string[];
}

export interface InvestigationPlan {
  id?: string;
  target: string;
  targetType: SecurityTarget['type'];
  environment: SecurityTarget['environment'];
  investigationType: InvestigationType;
  objective: string;
  plannedOperations: {
    name: string;
    description: string;
    tool: string;
    isPassive: boolean;
  }[];
  status?: 'pending_approval' | 'approved' | 'executing' | 'completed' | 'cancelled';
  createdAt?: string;
}

export interface EvidenceSourceItem {
  id: string;
  source: 'AbuseIPDB' | 'Shodan' | 'VirusTotal' | 'NVD' | 'RAG' | 'SIEM' | 'MITRE ATT&CK';
  result: string;
  retrievedAt: string;
  status: 'Verified' | 'Simulated Demo' | 'Mock Intelligence' | 'Live API' | 'Internal Knowledge';
  details?: string;
  ragMeta?: {
    document: string;
    page?: number;
    retrievedChunk?: string;
    similarity?: string;
  };
}

export interface InvestigationVerdict {
  target: string;
  threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: number; // 0 - 100
  evidenceCount: number;
  riskFactors: string[];
  confidenceFactors: string[];
  timeline: {
    time: string;
    step: string;
    status: 'completed' | 'running' | 'queued';
    provenance?: string;
  }[];
}

export interface ExtractedIndicator {
  type: 'ipv4' | 'ipv6' | 'domain' | 'url' | 'sha256' | 'md5' | 'cve' | 'email';
  value: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  event: 
    | 'LOGIN' 
    | 'LOGOUT' 
    | 'TARGET_ADDED' 
    | 'INVESTIGATION_STARTED' 
    | 'TOOL_EXECUTED' 
    | 'DOCUMENT_UPLOADED' 
    | 'IOC_SAVED' 
    | 'REPORT_GENERATED';
  actor: string;
  details: string;
  classification: 'TLP:CLEAR' | 'TLP:GREEN' | 'TLP:AMBER' | 'TLP:RED';
}

export interface ServiceHealthStatus {
  service: string;
  category: 'AI Model' | 'Threat Intel' | 'Vulnerability' | 'Identity' | 'Storage';
  status: 'Operational' | 'Degraded' | 'Unavailable' | 'Not Configured' | 'Rate Limited';
  latencyMs: number;
  notes: string;
  isSimulated?: boolean;
}

