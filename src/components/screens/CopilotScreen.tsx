import React, { useState, useRef, useEffect } from 'react';
import { 
  Bot, 
  Send, 
  Sparkles, 
  ShieldAlert, 
  Terminal, 
  ChevronDown, 
  ExternalLink, 
  CheckCircle2, 
  AlertTriangle, 
  Globe2, 
  Server, 
  Cpu, 
  Lock, 
  Layers, 
  Copy, 
  Check, 
  Flame, 
  Radio, 
  Eye, 
  RotateCw,
  PlusCircle,
  FileText,
  Paperclip,
  UploadCloud,
  Crosshair,
  FileCode,
  ShieldCheck,
  X
} from 'lucide-react';
import { ScreenType, ChatMessage, IOCItem, SecurityTarget, InvestigationPlan, EvidenceSourceItem, InvestigationVerdict, ExtractedIndicator, InvestigationType, AuditLogEntry } from '../../types';
import { INITIAL_CHAT_MESSAGES, TARGET_IP_DOSSIER } from '../../data/mockData';
import { detectInvestigationIntent, generateEvidenceForTarget, generateSyntheticVerdict, extractIndicators } from '../../utils/detector';
import { TargetScopeSafetyCard, InvestigationPlanCard, EvidenceCenterCard, DetectedIndicatorsCard } from '../investigation/InvestigationWorkflowCards';

interface CopilotScreenProps {
  onNavigate: (screen: ScreenType) => void;
  onSelectIOC?: (ioc: IOCItem) => void;
  activeTarget?: SecurityTarget;
  onOpenAddTargetModal?: () => void;
  onSaveTarget?: (target: SecurityTarget) => void;
  onSaveIOC?: (iocValue: string, type?: string) => void;
  onSaveCase?: (verdict: InvestigationVerdict) => void;
  onRecordAudit?: (event: AuditLogEntry['event'], details: string) => void;
  onClearActiveTarget?: () => void;
}

export const CopilotScreen: React.FC<CopilotScreenProps> = ({ 
  onNavigate,
  activeTarget,
  onOpenAddTargetModal,
  onSaveTarget,
  onSaveIOC,
  onSaveCase,
  onRecordAudit,
  onClearActiveTarget
}) => {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputPrompt, setInputPrompt] = useState('');
  const [selectedModel, setSelectedModel] = useState('Gemini 2.5 Flash (SecOps)');
  const [isModelDropdownOpen, setIsModelDropdownOpen] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [activeTools, setActiveTools] = useState({
    shodan: true,
    abuseIPDB: true,
    virusTotal: true,
    siemLogs: true,
    ebpf: false
  });
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [actionSuccessToast, setActionSuccessToast] = useState<string | null>(null);
  const [mobileTab, setMobileTab] = useState<'chat' | 'dossier'>('chat');
  const [isDraggingFile, setIsDraggingFile] = useState(false);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isGenerating]);

  const handleClearChat = () => {
    setMessages([]);
    setInputPrompt('');
    setIsGenerating(false);
    onClearActiveTarget?.();
    showToast('Investigation session cleared. Workspace is clean.');
    onRecordAudit?.('INVESTIGATION_STARTED', 'Analyst cleared chat session and reset Copilot workspace');
  };

  const quickPrompts = [
    { label: 'Investigate 185.220.101.5', query: 'Investigate 185.220.101.5' },
    { label: 'Summarize APT29 TTPs', query: 'Summarize known MITRE ATT&CK techniques, C2 protocols, and evasion methods used by APT29 (Midnight Blizzard).' },
    { label: 'Draft Suricata C2 Rule', query: 'Draft a Suricata rule to detect Cobalt Strike malleable C2 HTTP beacons on port 8080 with jitter.' },
    { label: 'RAG Policy Compliance Check', query: 'Does the target 185.220.101.5 violate any documented enterprise security policies in SOP-88?' }
  ];

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const showToast = (msg: string) => {
    setActionSuccessToast(msg);
    setTimeout(() => setActionSuccessToast(null), 3500);
  };

  // 1. File Upload / Drag & Drop Handler (Directive 1 & 11)
  const handleProcessUploadedFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const textContent = (e.target?.result as string) || '';
      const extracted = extractIndicators(textContent);
      
      const userMsg: ChatMessage = {
        id: `msg-${Date.now()}`,
        role: 'user',
        content: `Uploaded security document: **${file.name}** (${(file.size / 1024).toFixed(1)} KB)`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ' UTC',
        uploadedDocument: {
          filename: file.name,
          sizeBytes: file.size,
          chunksCount: Math.max(1, Math.floor(file.size / 250)),
          summary: `Parsed ${file.name}. Vectorized into ChromaDB semantic store. Extracted ${extracted.length} threat observables.`
        }
      };

      setMessages(prev => [...prev, userMsg]);
      setIsGenerating(true);

      onRecordAudit?.('DOCUMENT_UPLOADED', `Ingested security document ${file.name} (${(file.size / 1024).toFixed(1)} KB) into RAG Core`);

      setTimeout(() => {
        const assistantMsg: ChatMessage = {
          id: `msg-ai-${Date.now()}`,
          role: 'assistant',
          content: `### Document Ingestion & RAG Indexing Complete: ${file.name}

- **Vector Knowledge Core**: Document processed, chunked (128-token overlaps), and indexed into local vector embeddings.
- **Observables Extracted**: Identified ${extracted.length} correlated indicators from document text.
- **RAG Policy Check Ready**: You can now ask: *"Does target ${activeTarget?.value || '185.220.101.5'} violate controls in ${file.name}?"*`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ' UTC',
          model: selectedModel,
          extractedIndicators: extracted.length > 0 ? extracted : undefined,
          reasoningSteps: [
            { title: 'ChromaDB Document Chunking', description: `Segmented into semantic chunks with cosine vector embeddings.`, status: 'completed', duration: '120ms' },
            { title: 'Regex Indicator Extraction', description: `Parsed IP, CIDR, domain, and hash patterns from document body.`, status: 'completed', duration: '45ms' }
          ],
          suggestedActions: [
            { label: 'Run RAG Policy Cross-Check', action: 'rag-policy-check', type: 'primary' },
            { label: 'View RAG Knowledge Core', action: 'view-rag', type: 'secondary' }
          ]
        };

        setMessages(prev => [...prev, assistantMsg]);
        setIsGenerating(false);
      }, 900);
    };

    reader.readAsText(file);
  };

  // 2. Primary Send Message Handler (Directive 1)
  const handleSend = (textToSend?: string) => {
    const query = textToSend || inputPrompt;
    if (!query.trim() || isGenerating) return;

    const userMsg: ChatMessage = {
      id: `msg-${Date.now()}`,
      role: 'user',
      content: query,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ' UTC'
    };

    setMessages(prev => [...prev, userMsg]);
    setInputPrompt('');
    setIsGenerating(true);

    // Detect Target or Investigation Intent (Directive 1 & 2)
    const intent = detectInvestigationIntent(query);

    setTimeout(() => {
      if (intent.detected && intent.targetValue) {
        // Target Detected! Show Target Scope Safety Card with [Investigate Target]
        const assistantMsg: ChatMessage = {
          id: `msg-ai-${Date.now()}`,
          role: 'assistant',
          content: `Target detected: **${intent.targetValue}** (${intent.targetType.toUpperCase()}).
          
Review the target scope, operational mode, and authorization notice below to launch an autonomous assessment:`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ' UTC',
          model: selectedModel,
          investigationScope: {
            target: intent.targetValue,
            targetType: intent.targetType,
            environment: 'external_threat',
            status: 'pending_approval'
          }
        };

        setMessages(prev => [...prev, assistantMsg]);
        setIsGenerating(false);
        return;
      }

      // If general SecOps query
      let aiResponseContent = '';
      let reasoning = [];
      let extracted = [];
      let actions = [];

      const lowerQ = query.toLowerCase();

      if (lowerQ.includes('policy') || lowerQ.includes('sop-88') || lowerQ.includes('violate') || lowerQ.includes('compliance')) {
        aiResponseContent = `### RAG Knowledge Core: Security Policy Compliance Check

**Query Target**: \`${activeTarget?.value || '185.220.101.5'}\`  
**Referenced Corpus**: *SOP-88 Incident Containment & External Network Egress Standard (Rev 4.1)*

#### Document Findings:
1. **Control SEC-NET-04 (Unauthorized External Egress)**:  
   *Violation Identified.* Outbound TCP connections to unverified Tor exit relays or dynamic DNS nodes are strictly prohibited.
2. **Control SEC-EDR-12 (Process Staging Quarantine)**:  
   Internal asset \`PROD-K8S-WORKER-09\` spawned anomalous \`powershell.exe -enc\` beacons, triggering mandatory host isolation under SLA Tier-1 (30 minutes).

#### Required Containment Actions per Playbook:
- Revoke IAM and Kubelet cluster credentials immediately.
- Submit firewall drop rule for CIDR block \`185.220.101.0/24\`.`;

        reasoning = [
          { title: 'Vector Semantic Search', description: 'Matched 3 relevant policy clauses in SOP-88 (similarity 0.89).', status: 'completed' as const, duration: '60ms' },
          { title: 'Control Violation Evaluation', description: 'Assessed target behavior against SEC-NET-04 and SEC-EDR-12 requirements.', status: 'completed' as const, duration: '85ms' }
        ];

        actions = [
          { label: 'Enforce Egress Drop Rule', action: 'block-firewall', type: 'primary' as const },
          { label: 'Isolate Compromised Node', action: 'isolate-host', type: 'destructive' as const }
        ];
      } else if (lowerQ.includes('rule') || lowerQ.includes('snort') || lowerQ.includes('suricata')) {
        aiResponseContent = `### Generated Suricata C2 Detection Signature

\`\`\`yaml
alert http $HOME_NET any -> $EXTERNAL_NET [80,8080] ( \\
  msg:"CIPHER-AI Cobalt Strike Malleable C2 Beaconing (JQuery Profile)"; \\
  flow:established,to_server; \\
  content:"GET"; http_method; \\
  content:"/__utm.gif"; http_uri; \\
  header:"Cookie: __cfduid="; \\
  pcre:"/Cookie:[^\\r\\n]*__cfduid=[a-f0-9]{32}/i"; \\
  threshold:type both, track by_src, count 5, seconds 60; \\
  classtype:trojan-activity; \\
  sid:2894101; rev:1; \\
  reference:url,attack.mitre.org/techniques/T1071/001/; \\
)
\`\`\`

#### Verification & Policy Check:
- **False Positive Risk**: Low (< 0.2% on standard enterprise subnets)
- **Deployment Target**: Core Palo Alto / Fortinet perimeter inspection engines
- **Automated Rule Validation**: Passed Suricata 7.0 AST syntax test`;

        reasoning = [
          { title: 'PCRE Pattern Synthesis', description: 'Extracted regular expression matching cookie-staged Cobalt Strike beacons.', status: 'completed' as const, duration: '95ms' },
          { title: 'Signature AST Validation', description: 'Verified compatibility with Suricata 7.0 & Snort 3 rule engines.', status: 'completed' as const, duration: '40ms' }
        ];

        extracted = [
          { type: 'ioc' as const, label: 'Signature SID', value: '2894101', severity: 'medium' },
          { type: 'mitre' as const, label: 'MITRE TTP', value: 'T1071.001 Web Protocols', severity: 'high' }
        ];

        actions = [
          { label: 'Push Rule to NGFW Cluster', action: 'deploy-rule', type: 'primary' as const },
          { label: 'Test against PCAP Replay', action: 'test-pcap', type: 'secondary' as const }
        ];
      } else if (lowerQ.includes('apt29') || lowerQ.includes('midnight blizzard')) {
        aiResponseContent = `### Threat Actor Profile: APT29 (Midnight Blizzard / Nobelium)

- **Motivation**: State-sponsored espionage, stealth credential harvesting, supply chain compromise.
- **Recent Vectors**: Abuse of OAuth applications, credential spray targeting administrative identities, memory-only loader execution.

#### Primary TTPs Observed in Current Environment:
1. **T1078.004 (Cloud Accounts)**: Utilizing stolen CI/CD service principal tokens.
2. **T1055 (Process Injection)**: Memory unhooking of NTDLL to evade endpoint detection hooks.
3. **T1090.003 (Tor Multi-Hop)**: Routing ingress commands through Tor exit relays (e.g. Frankfurt node \`185.220.101.5\`).

#### Recommended Defense Posture:
- Invalidate all non-MFA AWS IAM CLI sessions.
- Deploy host isolation on infected endpoints immediately.`;

        reasoning = [
          { title: 'MITRE ATT&CK Matrix Lookup', description: 'Retrieved APT29 enterprise matrix and recent CISA advisories.', status: 'completed' as const, duration: '110ms' },
          { title: 'Cross-Correlation with INC-8941', description: 'Matched 3 overlapping TTP indicators with current case file.', status: 'completed' as const, duration: '140ms' }
        ];

        extracted = [
          { type: 'ioc' as const, label: 'Actor', value: 'APT29 (Midnight Blizzard)', severity: 'critical' },
          { type: 'mitre' as const, label: 'TTP 1', value: 'T1078.004 Cloud Accounts', severity: 'high' },
          { type: 'mitre' as const, label: 'TTP 2', value: 'T1055 Process Injection', severity: 'critical' }
        ];

        actions = [
          { label: 'Review Full Security Intel Report', action: 'view-report', type: 'primary' as const },
          { label: 'Export STIX 2.1 Threat Bundle', action: 'export-stix', type: 'secondary' as const }
        ];
      } else {
        // General answer + extract indicators
        const autoExtracted = extractIndicators(query);

        aiResponseContent = `### Security Analysis Complete

Query evaluated against threat intelligence feeds, MITRE ATT&CK knowledge, and internal telemetry.

- **Telemetric Overview**: Baseline network activity operational.
- **Active Context**: Current scope centered on target **${activeTarget?.value || '185.220.101.5'}** (${activeTarget?.label || 'External Threat'}).
- **Actionable Guidance**: Run continuous passive queries against AbuseIPDB and Shodan, and cross-reference indicators with active incident INC-8941.`;

        reasoning = [
          { title: 'Autonomous Threat Context Search', description: 'Queried MITRE vectors and monitored target inventory.', status: 'completed' as const, duration: '50ms' }
        ];

        extracted = [
          { type: 'ioc' as const, label: 'Observable', value: activeTarget?.value || '185.220.101.5', severity: 'high' }
        ];

        actions = [
          { label: 'Investigate Active Target', action: 'investigate-active', type: 'primary' as const },
          { label: 'View Incident Timeline', action: 'view-case', type: 'secondary' as const }
        ];
      }

      const assistantMsg: ChatMessage = {
        id: `msg-ai-${Date.now()}`,
        role: 'assistant',
        content: aiResponseContent,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ' UTC',
        model: selectedModel,
        reasoningSteps: reasoning,
        extractedArtifacts: extracted,
        suggestedActions: actions
      };

      setMessages(prev => [...prev, assistantMsg]);
      setIsGenerating(false);
    }, 1000);
  };

  // 3. Launch Investigation Step: Creates Investigation Plan (Directive 5)
  const handleLaunchInvestigationPlan = (messageId: string, targetValue: string, targetType: SecurityTarget['type'], investigationType: InvestigationType) => {
    const plan: InvestigationPlan = {
      target: targetValue,
      targetType: targetType,
      environment: activeTarget?.environment || 'external_threat',
      objective: `Investigate observed ${targetType.toUpperCase()} for threat reputation, infrastructure ownership, CVE exposures, and correlation with internal assets.`,
      investigationType: investigationType,
      plannedOperations: [
        { name: 'Target RFC Validation & Normalization', description: 'Confirm RFC compliance, canonical syntax, and extract metadata.', tool: 'rfc_syntax_validator', isPassive: true },
        { name: 'AbuseIPDB Reputation Check', description: 'Query blacklist database and abuse confidence percentile.', tool: 'abuseipdb_connector', isPassive: true },
        { name: 'Shodan Passive Banner Inspection', description: 'Search historical exposed ports and TLS certificate fingerprints.', tool: 'shodan_api_client', isPassive: true },
        { name: 'VirusTotal Hash & File Association', description: 'Cross-reference against multi-engine antivirus detection feeds.', tool: 'virustotal_v3', isPassive: true },
        { name: 'NVD / NIST CVE Vulnerability Correlation', description: 'Check known exploitable vulnerabilities on exposed service versions.', tool: 'nvd_cve_correlator', isPassive: true },
        { name: 'Internal Knowledge & RAG Cross-Reference', description: 'Search vectorized incident runbooks (SOP-88) for matching TTPs.', tool: 'rag_vector_search', isPassive: true }
      ]
    };

    setMessages(prev => prev.map(m => {
      if (m.id === messageId) {
        return {
          ...m,
          investigationScope: {
            target: targetValue,
            targetType: targetType,
            environment: activeTarget?.environment || 'external_threat',
            status: 'plan_ready'
          },
          investigationPlan: plan
        };
      }
      return m;
    }));
  };

  // 4. Approve Investigation Plan: Executes Agent Tools & Generates Evidence Center (Directive 6, 7, 8, 9)
  const handleApprovePlan = (messageId: string, plan: InvestigationPlan) => {
    setIsGenerating(true);

    onRecordAudit?.('INVESTIGATION_STARTED', `Initiated ${plan.investigationType} investigation on target ${plan.target} (${plan.targetType})`);

    setTimeout(() => {
      const { evidence, verdict } = generateEvidenceForTarget(plan.target, plan.targetType);

      setMessages(prev => prev.map(m => {
        if (m.id === messageId) {
          return {
            ...m,
            content: `### Autonomous Investigation Executed: ${plan.target}

Investigation plan successfully completed across 5 threat intelligence engines and RAG knowledge vectors. Detailed provenance findings, verdict explainability, and timeline are compiled below:`,
            investigationScope: {
              target: plan.target,
              targetType: plan.targetType,
              environment: plan.environment,
              status: 'executed'
            },
            evidenceResult: {
              evidence: evidence,
              verdict: verdict
            },
            reasoningSteps: [
              { title: 'AbuseIPDB Reputation Sweep', description: 'Queried blacklists (Confidence: 94%).', status: 'completed', duration: '140ms', toolName: 'abuseIPDB_query' },
              { title: 'Shodan Passive Banner Grab', description: 'Identified 4 open ports and Tor DirServer signatures.', status: 'completed', duration: '210ms', toolName: 'shodan_host_recon' },
              { title: 'VirusTotal Multi-Engine Correlation', description: 'Corroborated 62/88 positive detections for Cobalt Strike beacon.', status: 'completed', duration: '330ms', toolName: 'virustotal_lookup' },
              { title: 'NVD CVE Vulnerability Correlation', description: 'Cross-referenced CVE-2024-3400 (PAN-OS GlobalProtect Command Injection).', status: 'completed', duration: '90ms', toolName: 'nvd_cve_search' },
              { title: 'RAG Knowledge Core Match', description: 'Correlated against SOP-88 Incident Containment runbook.', status: 'completed', duration: '75ms', toolName: 'chroma_rag_query' }
            ]
          };
        }
        return m;
      }));

      // Ingest or update target in inventory
      if (onSaveTarget) {
        const newTgt: SecurityTarget = {
          id: `tgt-${Date.now()}`,
          value: plan.target,
          type: plan.targetType,
          label: `${plan.target} (${verdict.threatLevel} Threat)`,
          environment: plan.environment,
          priority: verdict.threatLevel === 'CRITICAL' ? 'critical' : verdict.threatLevel === 'HIGH' ? 'high' : 'medium',
          threatScore: verdict.confidence,
          verdict: verdict.threatLevel === 'CRITICAL' || verdict.threatLevel === 'HIGH' ? 'malicious' : 'suspicious',
          riskLevel: verdict.threatLevel,
          confidence: verdict.confidence,
          status: 'INVESTIGATED',
          owner: 'Autonomous Copilot Engine',
          firstSeen: 'Just now',
          investigationType: plan.investigationType,
          openPorts: [80, 443, 8080, 9001],
          tags: ['Autonomous-Investigation', verdict.threatLevel],
          addedBy: 'Autonomous Copilot Engine',
          addedAt: 'Just now',
          lastScannedAt: 'Just now',
          associatedIncidents: ['INC-8941']
        };
        onSaveTarget(newTgt);
      }

      onRecordAudit?.('TOOL_EXECUTED', `Completed automated multi-engine recon on ${plan.target}. Verdict: ${verdict.threatLevel} (${verdict.confidence}% Confidence)`);
      showToast(`Investigation complete for ${plan.target}: ${verdict.threatLevel} Threat`);
      setIsGenerating(false);
    }, 1300);
  };

  // 5. Cancel Plan Handler
  const handleCancelPlan = (messageId: string) => {
    setMessages(prev => prev.map(m => {
      if (m.id === messageId) {
        return {
          ...m,
          content: `${m.content}\n\n*Investigation plan was cancelled by analyst.*`,
          investigationScope: m.investigationScope ? { ...m.investigationScope, status: 'cancelled' } : undefined
        };
      }
      return m;
    }));
    showToast('Investigation plan cancelled.');
  };

  // Action button click dispatcher
  const handleActionClick = (action: string) => {
    if (action === 'view-ioc') {
      onNavigate('ioc-manager');
    } else if (action === 'view-case') {
      onNavigate('investigations');
    } else if (action === 'view-report') {
      onNavigate('security-intel');
    } else if (action === 'dossier-ip') {
      onNavigate('threat-intel');
    } else if (action === 'view-rag') {
      onNavigate('rag-core');
    } else if (action === 'investigate-active') {
      if (activeTarget) {
        handleSend(`Investigate ${activeTarget.value}`);
      }
    } else if (action === 'rag-policy-check') {
      handleSend(`Does target ${activeTarget?.value || '185.220.101.5'} violate any documented security controls?`);
    } else if (action === 'isolate-host') {
      showToast('⚡ Host PROD-K8S-WORKER-09 quarantined via CrowdStrike Falcon API');
      onRecordAudit?.('TOOL_EXECUTED', 'Quarantined host PROD-K8S-WORKER-09 via CrowdStrike Falcon API');
    } else if (action === 'block-firewall' || action === 'deploy-rule') {
      showToast('🛡️ Drop rule injected into Palo Alto Panorama Global Blocklist');
      onRecordAudit?.('TOOL_EXECUTED', 'Injected drop rule for 185.220.101.5 into Palo Alto Panorama');
    } else if (action === 'export-stix') {
      showToast('📦 STIX 2.1 Threat Bundle generated and downloaded (bundle-inc8941.json)');
    } else {
      showToast(`Action '${action}' executed successfully.`);
    }
  };

  return (
    <div className="flex-1 flex overflow-hidden bg-[#080b11] text-slate-100">
      {/* Hidden File Input for Document Ingestion */}
      <input 
        type="file"
        ref={fileInputRef}
        onChange={(e) => {
          if (e.target.files && e.target.files[0]) {
            handleProcessUploadedFile(e.target.files[0]);
          }
        }}
        accept=".pdf,.txt,.log,.json,.csv,.pcap"
        className="hidden"
      />

      {/* Toast Notification */}
      {actionSuccessToast && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 bg-cyan-950/90 border border-cyan-400/50 text-cyan-200 px-4 py-3 rounded-lg shadow-xl backdrop-blur-md animate-in fade-in slide-in-from-bottom-3 duration-200 font-mono text-xs">
          <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>{actionSuccessToast}</span>
        </div>
      )}

      {/* Main Chat Workspace */}
      <div className={`flex-1 flex-col min-w-0 border-r border-slate-800/80 ${mobileTab === 'dossier' ? 'hidden xl:flex' : 'flex'}`}>
        
        {/* Copilot Header Bar */}
        <div className="border-b border-slate-800/80 px-3 sm:px-6 py-2.5 sm:py-3 flex flex-wrap sm:flex-nowrap items-center justify-between gap-3 bg-[#0a0e17]/80 shrink-0">
          <div className="flex items-center gap-2.5 sm:gap-3">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shrink-0">
              <Bot className="w-4 h-4" />
            </div>
            <div>
              <h1 className="text-xs sm:text-sm font-semibold tracking-wide text-slate-100 font-mono flex items-center gap-1.5 sm:gap-2">
                <span className="truncate max-w-[200px] xs:max-w-none">CIPHER AI — Intelligence Copilot</span>
                <span className="text-[9px] sm:text-[10px] px-1.5 py-0.2 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  AI CONTROL PLANE
                </span>
              </h1>
              <p className="text-[10px] sm:text-[11px] text-slate-400 font-mono hidden xs:block">
                Primary Cybersecurity Assistant & Autonomous Threat Investigation Engine
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Mobile / Tablet Tab Toggle Switcher */}
            <div className="xl:hidden flex items-center rounded-lg bg-slate-900 border border-slate-800 p-0.5 text-xs font-mono">
              <button
                onClick={() => setMobileTab('chat')}
                className={`px-2.5 py-1 rounded-md transition-colors ${
                  mobileTab === 'chat' 
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/40 font-semibold' 
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Control Plane
              </button>
              <button
                onClick={() => setMobileTab('dossier')}
                className={`px-2.5 py-1 rounded-md flex items-center gap-1 transition-colors ${
                  mobileTab === 'dossier' 
                    ? 'bg-rose-950 text-rose-300 border border-rose-500/40 font-semibold' 
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Flame className="w-3 h-3 text-rose-400" />
                <span>Dossier</span>
              </button>
            </div>

            {/* New Investigation / Clear Chat Session Button */}
            <button
              onClick={handleClearChat}
              className="flex items-center gap-1.5 px-2 sm:px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-rose-500/40 hover:bg-rose-950/20 text-xs font-mono text-slate-300 hover:text-rose-300 transition-colors group cursor-pointer"
              title="Clear investigation history and start clean session"
            >
              <RotateCw className="w-3.5 h-3.5 text-slate-400 group-hover:text-rose-400 group-hover:rotate-180 transition-all duration-300 shrink-0" />
              <span className="hidden sm:inline">New Session</span>
            </button>

            {/* Model Selector Dropdown */}
            <div className="relative">
              <button
                onClick={() => setIsModelDropdownOpen(!isModelDropdownOpen)}
                className="flex items-center gap-1.5 sm:gap-2 px-2 sm:px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-xs font-mono text-slate-200 transition-colors"
              >
                <Sparkles className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span className="truncate max-w-[110px] xs:max-w-[160px] sm:max-w-none">{selectedModel.split(' ')[0]}</span>
                <ChevronDown className="w-3 h-3 text-slate-400 shrink-0" />
              </button>

              {isModelDropdownOpen && (
                <div className="absolute right-0 mt-2 w-64 rounded-xl bg-slate-900 border border-slate-700 shadow-2xl p-1.5 z-40 space-y-1 font-mono text-xs">
                  {[
                    { name: 'Gemini 2.5 Flash (SecOps)', tag: 'Ultra Fast / Google DeepMind' },
                    { name: 'Gemini 2.5 Pro (Deep Research)', tag: 'Complex Reasoning & Forensic Analysis' },
                    { name: 'Claude 3.5 Sonnet (Threat Analysis)', tag: 'Advanced Threat Modeling' },
                    { name: 'CIPHER Air-Gapped Mistral', tag: 'Local Offline Model' }
                  ].map(model => (
                    <button
                      key={model.name}
                      onClick={() => {
                        setSelectedModel(model.name);
                        setIsModelDropdownOpen(false);
                      }}
                      className={`w-full text-left p-2 rounded-lg transition-colors flex flex-col ${
                        selectedModel === model.name ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'hover:bg-slate-800 text-slate-300'
                      }`}
                    >
                      <span className="font-medium text-slate-200">{model.name}</span>
                      <span className="text-[10px] text-slate-500">{model.tag}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Active Target Scope Context Bar (Directive 10) */}
        {activeTarget && (
          <div className="px-3 sm:px-6 py-2 bg-[#0c1322] border-b border-cyan-500/20 flex items-center justify-between flex-wrap gap-2 text-xs font-mono">
            <div className="flex items-center gap-2">
              <Crosshair className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              <span className="text-slate-400 text-[11px]">ACTIVE TARGET SCOPE:</span>
              <span className="font-bold text-cyan-300">{activeTarget.value}</span>
              <span className="text-slate-500 text-[11px] hidden sm:inline">({activeTarget.label})</span>
              <span className={`text-[9px] px-1.5 py-0.2 rounded border font-semibold ${
                activeTarget.verdict === 'malicious' ? 'bg-rose-500/10 text-rose-300 border-rose-500/30' :
                activeTarget.verdict === 'suspicious' ? 'bg-amber-500/10 text-amber-300 border-amber-500/30' :
                'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
              }`}>
                {activeTarget.verdict.toUpperCase()}
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => handleSend(`Investigate ${activeTarget.value}`)}
                className="px-2 py-0.5 rounded bg-cyan-600/30 hover:bg-cyan-600/50 text-cyan-200 border border-cyan-500/40 text-[10px] transition-colors cursor-pointer"
              >
                Investigate Target
              </button>
              <button
                onClick={() => handleSend(`Check policy compliance and RAG rules for target ${activeTarget.value}`)}
                className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] border border-slate-700 transition-colors hidden sm:inline cursor-pointer"
              >
                RAG Policy Check
              </button>
              {onClearActiveTarget && (
                <button
                  onClick={onClearActiveTarget}
                  className="px-2 py-0.5 rounded bg-slate-800 hover:bg-rose-950/60 text-slate-400 hover:text-rose-300 text-[10px] border border-slate-700 transition-colors flex items-center gap-1 cursor-pointer"
                  title="Clear target from active scope"
                >
                  <X className="w-3 h-3" />
                  <span>Clear Scope</span>
                </button>
              )}
            </div>
          </div>
        )}

        {/* Message Thread */}
        <div className="flex-1 overflow-y-auto p-3 sm:p-6 space-y-4 sm:space-y-6">
          {messages.length === 0 ? (
            <div className="h-full min-h-[440px] flex flex-col items-center justify-center max-w-2xl mx-auto py-6 px-4 text-center select-none animate-in fade-in duration-300 my-auto">
              {/* System Icon */}
              <div className="relative mb-5">
                <div className="w-16 h-16 rounded-2xl bg-cyan-950/60 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-[0_0_35px_rgba(6,182,212,0.18)]">
                  <Bot className="w-8 h-8 text-cyan-400" />
                </div>
                <span className="absolute -bottom-1 -right-1 flex h-4 w-4">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-4 w-4 bg-emerald-500 border-2 border-[#0a0e17]"></span>
                </span>
              </div>

              {/* Title & Status */}
              <div className="space-y-2 mb-6">
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-[11px] font-mono text-cyan-400">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                  <span>CLEAN WORKSPACE READY • STANDBY</span>
                </div>
                <h2 className="text-xl sm:text-2xl font-bold font-mono tracking-tight text-slate-100">
                  SecOps Intelligence Copilot
                </h2>
                <p className="text-xs sm:text-sm text-slate-400 font-mono max-w-lg mx-auto leading-relaxed">
                  Autonomous threat correlation, observable investigation, and incident triaging. Enter any IP, Domain, Hash, or CVE below, or upload forensic telemetry to begin.
                </p>
              </div>

              {/* Quick Starter Action Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 w-full text-left mb-5">
                <button
                  onClick={() => handleSend('Investigate 185.220.101.5')}
                  className="p-3 rounded-xl bg-slate-900/80 hover:bg-slate-900 border border-slate-800 hover:border-cyan-500/50 transition-all group cursor-pointer"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <Crosshair className="w-3.5 h-3.5 text-cyan-400 group-hover:scale-110 transition-transform" />
                    <span className="text-xs font-semibold font-mono text-slate-200 group-hover:text-cyan-300">
                      Investigate Suspicious IP
                    </span>
                  </div>
                  <p className="text-[10px] sm:text-[11px] font-mono text-slate-400">
                    Query AbuseIPDB, Shodan open ports, and attribution for <span className="text-cyan-400 font-bold">185.220.101.5</span>
                  </p>
                </button>

                <button
                  onClick={() => handleSend('Check Shodan ports and AbuseIPDB reputation for 194.26.29.114')}
                  className="p-3 rounded-xl bg-slate-900/80 hover:bg-slate-900 border border-slate-800 hover:border-cyan-500/50 transition-all group cursor-pointer"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <Globe2 className="w-3.5 h-3.5 text-emerald-400 group-hover:scale-110 transition-transform" />
                    <span className="text-xs font-semibold font-mono text-slate-200 group-hover:text-emerald-300">
                      Perimeter Recon (194.26.29.114)
                    </span>
                  </div>
                  <p className="text-[10px] sm:text-[11px] font-mono text-slate-400">
                    Passive banner reconnaissance, SSL certs, and GreyNoise detection
                  </p>
                </button>

                <button
                  onClick={() => handleSend('Summarize known MITRE ATT&CK techniques and C2 protocols used by APT29')}
                  className="p-3 rounded-xl bg-slate-900/80 hover:bg-slate-900 border border-slate-800 hover:border-cyan-500/50 transition-all group cursor-pointer"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <ShieldAlert className="w-3.5 h-3.5 text-amber-400 group-hover:scale-110 transition-transform" />
                    <span className="text-xs font-semibold font-mono text-slate-200 group-hover:text-amber-300">
                      APT29 TTP Intelligence
                    </span>
                  </div>
                  <p className="text-[10px] sm:text-[11px] font-mono text-slate-400">
                    Retrieve C2 beaconing jitter signatures, Tor hops, and token hijacking
                  </p>
                </button>

                <button
                  onClick={() => handleSend('Draft a Suricata rule to detect Cobalt Strike malleable C2 HTTP beacons on port 8080')}
                  className="p-3 rounded-xl bg-slate-900/80 hover:bg-slate-900 border border-slate-800 hover:border-cyan-500/50 transition-all group cursor-pointer"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <FileCode className="w-3.5 h-3.5 text-purple-400 group-hover:scale-110 transition-transform" />
                    <span className="text-xs font-semibold font-mono text-slate-200 group-hover:text-purple-300">
                      Draft Detection Rule
                    </span>
                  </div>
                  <p className="text-[10px] sm:text-[11px] font-mono text-slate-400">
                    Synthesize Suricata AST signature for anomalous egress jitter
                  </p>
                </button>
              </div>

              {/* Drag & Drop Hint */}
              <div
                onClick={() => fileInputRef.current?.click()}
                className="w-full p-3 rounded-xl border border-dashed border-slate-800 hover:border-cyan-500/50 bg-slate-950/40 hover:bg-slate-900/60 transition-all flex items-center justify-center gap-2.5 cursor-pointer group"
              >
                <UploadCloud className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 transition-colors" />
                <span className="text-xs font-mono text-slate-400 group-hover:text-slate-200">
                  Drop forensic logs, incident PCAPs, or threat reports here (or click to browse)
                </span>
              </div>

              {/* Passive Reconnaissance Badge */}
              <div className="mt-4 flex items-center gap-2 text-[10px] font-mono text-slate-500">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400/80" />
                <span>Zero-Impact Guarantee: Passive OSINT feeds only. Non-disruptive reconnaissance.</span>
              </div>
            </div>
          ) : (
            messages.map((msg) => (
            <div 
              key={msg.id}
              className={`flex gap-3 max-w-4xl ${msg.role === 'user' ? 'ml-auto flex-row-reverse' : ''}`}
            >
              {/* Avatar */}
              <div className={`w-8 h-8 rounded-lg shrink-0 flex items-center justify-center font-mono text-xs ${
                msg.role === 'user' 
                  ? 'bg-slate-800 border border-slate-700 text-slate-200' 
                  : 'bg-cyan-950 border border-cyan-500/40 text-cyan-400'
              }`}>
                {msg.role === 'user' ? 'ME' : <Bot className="w-4 h-4" />}
              </div>

              {/* Message Box */}
              <div className={`flex flex-col space-y-2.5 max-w-2xl ${msg.role === 'user' ? 'items-end' : 'items-start'}`}>
                <div className="flex items-center gap-2 text-[10px] font-mono text-slate-500">
                  <span className="font-semibold text-slate-400">
                    {msg.role === 'user' ? 'Lead Analyst (Sarah Chen)' : (msg.model || 'CIPHER AI Engine')}
                  </span>
                  <span>•</span>
                  <span>{msg.timestamp}</span>
                </div>

                {/* Reasoning Steps Accordion (if AI) */}
                {msg.reasoningSteps && msg.reasoningSteps.length > 0 && (
                  <div className="w-full rounded-lg bg-slate-900/90 border border-slate-800/90 p-3 space-y-2 text-xs font-mono">
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span className="flex items-center gap-1.5 text-cyan-400 font-medium">
                        <Terminal className="w-3.5 h-3.5" />
                        Autonomous SecOps Tool Execution ({msg.reasoningSteps.length} operations)
                      </span>
                      <span className="text-[10px] text-emerald-400 flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" /> Validated
                      </span>
                    </div>

                    <div className="space-y-1.5 pt-1">
                      {msg.reasoningSteps.map((step, idx) => (
                        <div key={idx} className="flex items-start justify-between p-2 rounded bg-slate-950/60 border border-slate-800/60">
                          <div>
                            <div className="text-slate-200 font-medium flex items-center gap-1.5">
                              <span className="text-cyan-400">›</span> {step.title}
                              {step.toolName && (
                                <code className="text-[10px] text-slate-400 bg-slate-900 px-1 py-0.5 rounded">
                                  {step.toolName}()
                                </code>
                              )}
                            </div>
                            <div className="text-[11px] text-slate-400 pl-3 pt-0.5">
                              {step.description}
                            </div>
                          </div>
                          {step.duration && (
                            <span className="text-[10px] text-slate-500 font-mono shrink-0 pl-2">
                              {step.duration}
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Main Content Body */}
                <div className={`p-4 rounded-xl text-xs leading-relaxed w-full ${
                  msg.role === 'user'
                    ? 'bg-cyan-950/40 border border-cyan-500/30 text-slate-200 rounded-tr-none'
                    : 'bg-slate-900/90 border border-slate-800/90 text-slate-200 rounded-tl-none shadow-lg'
                }`}>
                  <div className="prose prose-invert max-w-none text-xs space-y-2 whitespace-pre-wrap font-mono">
                    {msg.content}
                  </div>

                  {/* 1. INTERACTIVE TARGET SCOPE SAFETY CARD (Directive 1, 2, 3) */}
                  {msg.investigationScope?.status === 'pending_approval' && (
                    <TargetScopeSafetyCard 
                      targetValue={msg.investigationScope.target}
                      targetType={msg.investigationScope.targetType}
                      environment={msg.investigationScope.environment}
                      onConfirmInvestigation={(type) => {
                        handleLaunchInvestigationPlan(
                          msg.id, 
                          msg.investigationScope!.target, 
                          msg.investigationScope!.targetType, 
                          type
                        );
                      }}
                      onCancel={() => handleCancelPlan(msg.id)}
                    />
                  )}

                  {/* 2. INTERACTIVE INVESTIGATION PLAN CARD (Directive 5) */}
                  {msg.investigationScope?.status === 'plan_ready' && msg.investigationPlan && (
                    <InvestigationPlanCard 
                      plan={msg.investigationPlan}
                      onApprove={() => handleApprovePlan(msg.id, msg.investigationPlan!)}
                      onCancel={() => handleCancelPlan(msg.id)}
                    />
                  )}

                  {/* 3. INTERACTIVE EVIDENCE CENTER & ASSESSMENT CARD (Directive 6, 7, 8, 9, 13) */}
                  {msg.evidenceResult && (
                    <EvidenceCenterCard 
                      evidence={msg.evidenceResult.evidence}
                      verdict={msg.evidenceResult.verdict}
                      onAskFollowup={(q) => handleSend(q)}
                      onSaveCase={(verdict) => {
                        onSaveCase?.(verdict);
                        onRecordAudit?.('INVESTIGATION_STARTED', `Saved investigation case file for ${verdict.target}`);
                        showToast(`Investigation case saved for target ${verdict.target}`);
                      }}
                      onSaveIoc={(iocVal) => {
                        onSaveIOC?.(iocVal, msg.investigationScope?.targetType || 'ipv4');
                        onRecordAudit?.('IOC_SAVED', `Saved IOC ${iocVal} to Threat Ledger`);
                        showToast(`Saved indicator ${iocVal} to IOC Threat Ledger`);
                      }}
                      onGenerateReport={(target) => {
                        onRecordAudit?.('REPORT_GENERATED', `Generated Incident Assessment Report for ${target}`);
                        onNavigate('security-intel');
                      }}
                    />
                  )}

                  {/* 4. DETECTED INDICATORS CARD (Directive 12) */}
                  {msg.extractedIndicators && msg.extractedIndicators.length > 0 && (
                    <DetectedIndicatorsCard 
                      indicators={msg.extractedIndicators}
                      onInvestigate={(ind) => handleSend(`Investigate ${ind.value}`)}
                      onSaveIoc={(ind) => {
                        onSaveIOC?.(ind.value, ind.type);
                        onRecordAudit?.('IOC_SAVED', `Saved ${ind.type.toUpperCase()} observable ${ind.value}`);
                        showToast(`Saved ${ind.value} to IOC Ledger`);
                      }}
                    />
                  )}

                  {/* Extracted Artifacts Chips */}
                  {msg.extractedArtifacts && msg.extractedArtifacts.length > 0 && (
                    <div className="mt-4 pt-3 border-t border-slate-800/80 space-y-1.5">
                      <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                        Extracted Threat Artifacts
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {msg.extractedArtifacts.map((art, i) => (
                          <div 
                            key={i}
                            className="flex items-center gap-1.5 px-2 py-1 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300"
                          >
                            <span className="text-[9px] uppercase px-1 rounded bg-slate-800 text-slate-400">
                              {art.type}
                            </span>
                            <span className="text-cyan-300 font-medium">{art.value}</span>
                            <button 
                              onClick={() => handleCopy(art.value)}
                              className="text-slate-500 hover:text-slate-300 ml-1"
                              title="Copy to clipboard"
                            >
                              {copiedText === art.value ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Action Suggestion Buttons */}
                  {msg.suggestedActions && msg.suggestedActions.length > 0 && (
                    <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-wrap gap-2">
                      {msg.suggestedActions.map((act, i) => (
                        <button
                          key={i}
                          onClick={() => handleActionClick(act.action)}
                          className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all flex items-center gap-1.5 shadow-sm ${
                            act.type === 'primary'
                              ? 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-cyan-900/30'
                              : act.type === 'destructive'
                              ? 'bg-rose-950/80 hover:bg-rose-900 border border-rose-500/40 text-rose-300'
                              : 'bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700'
                          }`}
                        >
                          <span>{act.label}</span>
                          <ExternalLink className="w-3 h-3 opacity-70" />
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))
        )}

          {/* AI Generating Indicator */}
          {isGenerating && (
            <div className="flex gap-3 max-w-2xl">
              <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-500/40 text-cyan-400 flex items-center justify-center font-mono text-xs shrink-0">
                <Bot className="w-4 h-4" />
              </div>
              <div className="p-4 rounded-xl rounded-tl-none bg-slate-900/90 border border-slate-800/90 text-slate-400 text-xs font-mono flex items-center gap-3">
                <div className="flex gap-1">
                  <div className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></div>
                  <div className="w-2 h-2 rounded-full bg-cyan-400 animate-ping delay-150"></div>
                  <div className="w-2 h-2 rounded-full bg-cyan-400 animate-ping delay-300"></div>
                </div>
                <span>Autonomous SecOps reasoning & multi-engine recon in progress...</span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Quick Prompts Bar */}
        <div className="px-3 sm:px-6 py-2 border-t border-slate-800/60 bg-[#0a0e17]/50 flex items-center gap-2 overflow-x-auto text-[11px] font-mono scrollbar-none shrink-0">
          <span className="text-slate-500 text-[10px] uppercase font-semibold shrink-0">Prompts:</span>
          {quickPrompts.map((p, idx) => (
            <button
              key={idx}
              onClick={() => handleSend(p.query)}
              className="px-2.5 py-1 rounded-full bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/40 text-slate-300 shrink-0 transition-colors"
            >
              {p.label}
            </button>
          ))}
        </div>

        {/* Input Bar & Drag-and-Drop Area (Directive 1, 11) */}
        <div 
          className={`p-3 sm:p-4 border-t border-slate-800 bg-[#0a0e17] space-y-2 font-mono shrink-0 transition-all ${
            isDraggingFile ? 'border-cyan-500 bg-cyan-950/20' : ''
          }`}
          onDragOver={(e) => {
            e.preventDefault();
            setIsDraggingFile(true);
          }}
          onDragLeave={() => setIsDraggingFile(false)}
          onDrop={(e) => {
            e.preventDefault();
            setIsDraggingFile(false);
            if (e.dataTransfer.files && e.dataTransfer.files[0]) {
              handleProcessUploadedFile(e.dataTransfer.files[0]);
            }
          }}
        >
          {/* Active Security Tools Toggles */}
          <div className="flex items-center justify-between text-[11px] text-slate-400 flex-wrap gap-2">
            <div className="flex items-center gap-3">
              <span className="text-slate-500 text-[10px] uppercase">Active Tools:</span>
              <label className="flex items-center gap-1 cursor-pointer">
                <input 
                  type="checkbox" 
                  checked={activeTools.shodan}
                  onChange={(e) => setActiveTools({ ...activeTools, shodan: e.target.checked })}
                  className="rounded border-slate-700 text-cyan-500 focus:ring-0 w-3 h-3" 
                />
                <span className={activeTools.shodan ? 'text-cyan-400' : 'text-slate-500'}>Shodan</span>
              </label>
              <label className="flex items-center gap-1 cursor-pointer">
                <input 
                  type="checkbox" 
                  checked={activeTools.abuseIPDB}
                  onChange={(e) => setActiveTools({ ...activeTools, abuseIPDB: e.target.checked })}
                  className="rounded border-slate-700 text-cyan-500 focus:ring-0 w-3 h-3" 
                />
                <span className={activeTools.abuseIPDB ? 'text-cyan-400' : 'text-slate-500'}>AbuseIPDB</span>
              </label>
              <label className="flex items-center gap-1 cursor-pointer">
                <input 
                  type="checkbox" 
                  checked={activeTools.virusTotal}
                  onChange={(e) => setActiveTools({ ...activeTools, virusTotal: e.target.checked })}
                  className="rounded border-slate-700 text-cyan-500 focus:ring-0 w-3 h-3" 
                />
                <span className={activeTools.virusTotal ? 'text-cyan-400' : 'text-slate-500'}>VirusTotal</span>
              </label>
              <label className="flex items-center gap-1 cursor-pointer">
                <input 
                  type="checkbox" 
                  checked={activeTools.siemLogs}
                  onChange={(e) => setActiveTools({ ...activeTools, siemLogs: e.target.checked })}
                  className="rounded border-slate-700 text-cyan-500 focus:ring-0 w-3 h-3" 
                />
                <span className={activeTools.siemLogs ? 'text-cyan-400' : 'text-slate-500'}>SIEM / RAG</span>
              </label>
            </div>
            <span className="text-slate-500 hidden sm:inline">Press Enter to send, Shift+Enter for newline</span>
          </div>

          <div className="relative flex items-center">
            {/* File Upload Attachment Button (Directive 1) */}
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="absolute left-3 p-1.5 rounded-lg text-slate-400 hover:text-cyan-400 hover:bg-slate-800 transition-colors"
              title="Upload security document, PCAP, or incident log (RAG)"
            >
              <Paperclip className="w-4 h-4" />
            </button>

            <textarea
              value={inputPrompt}
              onChange={(e) => setInputPrompt(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  handleSend();
                }
              }}
              placeholder="Enter question, IP (185.220.101.5), CVE, hash, domain, or drag-and-drop document..."
              rows={2}
              className="w-full bg-slate-900/90 border border-slate-800 rounded-xl py-3 pl-11 pr-14 text-xs font-mono text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 resize-none"
            />

            <button
              onClick={() => handleSend()}
              disabled={!inputPrompt.trim() || isGenerating}
              className="absolute right-3 p-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 disabled:hover:bg-cyan-600 text-white transition-all shadow-md"
              title="Send to Copilot"
            >
              <Send className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Right Column: Live Target Dossier */}
      <div className={`w-full xl:w-80 2xl:w-96 border-l border-slate-800/80 bg-[#090d15] flex-col shrink-0 overflow-y-auto select-none ${mobileTab === 'dossier' ? 'flex' : 'hidden xl:flex'}`}>
        {/* Dossier Header */}
        <div className="p-3 sm:p-4 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <button 
              onClick={() => setMobileTab('chat')}
              className="xl:hidden p-1 rounded bg-slate-800 text-slate-300 hover:text-white"
              title="Return to Control Plane"
            >
              ←
            </button>
            <Flame className="w-4 h-4 text-rose-400 animate-pulse" />
            <span className="text-xs font-semibold font-mono tracking-wider text-slate-200 uppercase">
              Live Target Dossier
            </span>
          </div>
          <div className="flex items-center gap-2">
            {activeTarget && onClearActiveTarget && (
              <button
                onClick={onClearActiveTarget}
                className="text-[10px] px-2 py-0.5 rounded bg-slate-850 hover:bg-rose-950/60 text-slate-400 hover:text-rose-300 border border-slate-700 transition-colors cursor-pointer"
                title="Deselect active target scope"
              >
                Clear
              </button>
            )}
            {onOpenAddTargetModal && (
              <button
                onClick={onOpenAddTargetModal}
                className="text-[10px] px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-500/40 hover:bg-cyan-900 transition-colors flex items-center gap-1 cursor-pointer"
                title="Input new target IP or asset"
              >
                <PlusCircle className="w-3 h-3" />
                <span>Input IP</span>
              </button>
            )}
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-bold ${
              activeTarget
                ? (activeTarget.threatScore >= 90 ? 'bg-rose-950/60 border-rose-500/40 text-rose-300' : 'bg-cyan-950/60 border-cyan-500/40 text-cyan-300')
                : 'bg-slate-900 border-slate-800 text-slate-500'
            }`}>
              SCORE: {activeTarget ? `${activeTarget.threatScore}%` : 'STANDBY'}
            </span>
          </div>
        </div>

        {!activeTarget ? (
          <div className="p-6 text-center space-y-4 my-auto">
            <div className="w-12 h-12 mx-auto rounded-xl bg-slate-900 border border-dashed border-slate-800 flex items-center justify-center text-slate-500">
              <Crosshair className="w-6 h-6 text-slate-500" />
            </div>
            <div className="space-y-1.5">
              <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider font-mono">
                No Target in Scope
              </h3>
              <p className="text-[11px] text-slate-400 font-mono leading-relaxed max-w-[220px] mx-auto">
                Ask Copilot to investigate an IP or domain to display correlated threat telemetry here.
              </p>
            </div>
            <div className="pt-2 space-y-2">
              {onOpenAddTargetModal && (
                <button
                  onClick={onOpenAddTargetModal}
                  className="w-full py-2 px-3 rounded-lg bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-300 text-xs font-mono transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
                >
                  <PlusCircle className="w-3.5 h-3.5" />
                  <span>Input Observable Target</span>
                </button>
              )}
              <button
                onClick={() => handleSend('Investigate 185.220.101.5')}
                className="w-full py-1.5 px-3 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-slate-200 text-[11px] font-mono transition-colors cursor-pointer"
              >
                Try Sample: 185.220.101.5
              </button>
            </div>
          </div>
        ) : (
        <div className="p-4 space-y-4 text-xs font-mono">
          {/* Target IP Card */}
          <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-slate-400 text-[10px]">Observable ({activeTarget?.type?.toUpperCase() || 'IPv4'})</span>
              <span className={`text-[9px] px-1.5 py-0.2 rounded border font-bold ${
                (activeTarget?.verdict ?? 'malicious') === 'malicious' ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' :
                activeTarget?.verdict === 'suspicious' ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' :
                'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
              }`}>
                {(activeTarget?.verdict || 'MALICIOUS C2').toUpperCase()}
              </span>
            </div>
            <div className="text-base font-bold text-slate-100 flex items-center justify-between">
              <span className="truncate mr-2">{activeTarget ? activeTarget.value : TARGET_IP_DOSSIER.ip}</span>
              <button 
                onClick={() => handleCopy(activeTarget ? activeTarget.value : TARGET_IP_DOSSIER.ip)}
                className="text-slate-400 hover:text-cyan-400 shrink-0"
                title="Copy IP"
              >
                {copiedText === (activeTarget ? activeTarget.value : TARGET_IP_DOSSIER.ip) ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
            <div className="text-[11px] text-slate-400 truncate">
              {activeTarget ? activeTarget.label : TARGET_IP_DOSSIER.hostname}
            </div>
          </div>

          {/* Quick Metrics Bar */}
          <div className="grid grid-cols-2 gap-2">
            <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800">
              <div className="text-[10px] text-slate-400">Environment Scope</div>
              <div className="text-xs font-bold text-slate-200 mt-0.5 truncate uppercase">
                {activeTarget ? activeTarget.environment.replace('_', ' ') : 'External Threat'}
              </div>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800">
              <div className="text-[10px] text-slate-400">Priority Level</div>
              <div className="text-xs font-bold text-amber-400 mt-0.5 truncate uppercase">
                {activeTarget ? activeTarget.priority : 'Critical'}
              </div>
            </div>
          </div>

          {/* Geolocation & ASN */}
          <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Globe2 className="w-3.5 h-3.5 text-cyan-400" /> Location
              </span>
              <span className="text-slate-200">
                {activeTarget ? `${activeTarget.city || ''} ${activeTarget.country || 'Global'}` : `${TARGET_IP_DOSSIER.city}, ${TARGET_IP_DOSSIER.country}`}
              </span>
            </div>
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-cyan-400" /> ASN
              </span>
              <span className="text-slate-200 truncate max-w-[170px]">
                {activeTarget?.asn || TARGET_IP_DOSSIER.asn}
              </span>
            </div>
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-slate-400">Added By</span>
              <span className="text-slate-300 text-right truncate max-w-[150px]">
                {activeTarget?.addedBy || 'Sarah Chen'}
              </span>
            </div>
          </div>

          {/* Shodan Open Ports */}
          <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="text-[11px] text-slate-400 flex items-center justify-between">
              <span>Observed Open Ports</span>
              <span className="text-[10px] text-emerald-400">Port Recon Active</span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {(activeTarget?.openPorts || TARGET_IP_DOSSIER.openPorts).map((port) => (
                <span 
                  key={port}
                  className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                    port === 8080 
                      ? 'bg-rose-950/80 text-rose-300 border-rose-500/50 font-bold' 
                      : 'bg-slate-800 text-slate-300 border-slate-700'
                  }`}
                >
                  {port} {port === 8080 ? '(Beacon)' : ''}
                </span>
              ))}
            </div>
          </div>

          {/* Observed MITRE TTPs */}
          <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="text-[11px] text-slate-400">Observed MITRE TTPs</div>
            <div className="space-y-1.5">
              {TARGET_IP_DOSSIER.ttps.map((ttp, idx) => (
                <div key={idx} className="text-[10px] text-slate-300 p-1.5 rounded bg-slate-950/70 border border-slate-800/80">
                  {ttp}
                </div>
              ))}
            </div>
          </div>

          {/* Fast Response Operations */}
          <div className="space-y-2 pt-2">
            <div className="text-[10px] text-slate-400 uppercase tracking-wider">
              Fast Response Actions
            </div>
            <button
              onClick={() => onNavigate('threat-intel')}
              className="w-full py-2 px-3 rounded-lg bg-cyan-950/60 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-300 text-xs font-mono font-medium flex items-center justify-center gap-2 transition-colors"
            >
              <Eye className="w-3.5 h-3.5" />
              <span>Deep Multi-Source Intel View</span>
            </button>

            <button
              onClick={() => {
                showToast('🛡️ Drop rule injected into Palo Alto Panorama Global Blocklist');
                onRecordAudit?.('TOOL_EXECUTED', `Injected perimeter firewall drop rule for ${activeTarget?.value || 'target'}`);
              }}
              className="w-full py-2 px-3 rounded-lg bg-rose-950/60 hover:bg-rose-900 border border-rose-500/40 text-rose-300 text-xs font-mono font-medium flex items-center justify-center gap-2 transition-colors"
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>Block on Edge Firewalls (Drop)</span>
            </button>

            <button
              onClick={() => {
                onRecordAudit?.('REPORT_GENERATED', `Generated Incident Assessment Report for ${activeTarget?.value || 'target'}`);
                onNavigate('security-intel');
              }}
              className="w-full py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono flex items-center justify-center gap-2 transition-colors"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Generate Audit Incident Report</span>
            </button>
          </div>
        </div>
        )}
      </div>
    </div>
  );
};
