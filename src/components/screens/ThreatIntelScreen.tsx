import React, { useState } from 'react';
import { 
  Globe2, 
  Server, 
  ShieldAlert, 
  ExternalLink, 
  Terminal, 
  Radio, 
  Copy, 
  Check, 
  Bot, 
  Layers, 
  Activity,
  Calendar,
  CheckCircle2,
  Lock,
  ArrowRight
} from 'lucide-react';
import { ScreenType } from '../../types';
import { TARGET_IP_DOSSIER } from '../../data/mockData';

interface ThreatIntelScreenProps {
  onNavigate: (screen: ScreenType) => void;
  onSendToCopilot?: (query: string) => void;
}

export const ThreatIntelScreen: React.FC<ThreatIntelScreenProps> = ({ onNavigate, onSendToCopilot }) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'shodan' | 'abuse' | 'virustotal' | 'cve'>('overview');
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const showFeedback = (msg: string) => {
    setActionFeedback(msg);
    setTimeout(() => setActionFeedback(null), 3000);
  };

  return (
    <div className="flex-1 flex flex-col overflow-y-auto bg-[#080b11] text-slate-100 font-mono">
      {/* Toast */}
      {actionFeedback && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 bg-cyan-950/90 border border-cyan-400/50 text-cyan-200 px-4 py-3 rounded-lg shadow-xl backdrop-blur-md animate-in fade-in text-xs">
          <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>{actionFeedback}</span>
        </div>
      )}

      {/* Header */}
      <div className="p-6 border-b border-slate-800/80 bg-[#0a0e17]/80 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-cyan-400 text-xs">
              <Globe2 className="w-4 h-4" />
              <span>FEDERATED THREAT INTELLIGENCE DOSSIER</span>
            </div>
            <div className="flex items-center gap-3">
              <h1 className="text-xl font-bold tracking-tight text-slate-100">
                Target Observable: {TARGET_IP_DOSSIER.ip}
              </h1>
              <span className="text-xs px-2 py-0.5 rounded bg-rose-950/80 border border-rose-500/40 text-rose-300 font-bold">
                MALICIOUS C2 RELAY
              </span>
            </div>
            <p className="text-xs text-slate-400">
              {TARGET_IP_DOSSIER.hostname} • {TARGET_IP_DOSSIER.city}, {TARGET_IP_DOSSIER.country} ({TARGET_IP_DOSSIER.asn})
            </p>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              onClick={() => {
                if (onSendToCopilot) {
                  onSendToCopilot(`Provide full deep-dive correlation on target IP ${TARGET_IP_DOSSIER.ip}`);
                }
                onNavigate('copilot');
              }}
              className="px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-md"
            >
              <Bot className="w-3.5 h-3.5" />
              <span>Query in Copilot</span>
            </button>
            <button
              onClick={() => onNavigate('ioc-manager')}
              className="px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-xs flex items-center gap-1.5 transition-colors"
            >
              <Layers className="w-3.5 h-3.5" />
              <span>View in IOC Ledger</span>
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-2 border-t border-slate-800/80 pt-3 text-xs overflow-x-auto pb-1.5">
          {[
            { id: 'overview', label: 'Threat Overview & Attribution' },
            { id: 'shodan', label: 'Shodan Port Recon (4 Open)' },
            { id: 'abuse', label: 'AbuseIPDB Reports (47 Hits)' },
            { id: 'virustotal', label: 'VirusTotal Graph (64 Detections)' },
            { id: 'cve', label: 'Exploited CVEs & Stagers' }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-3 py-1.5 rounded-lg transition-colors border whitespace-nowrap shrink-0 ${
                activeTab === tab.id
                  ? 'bg-cyan-950/60 text-cyan-300 border-cyan-500/40 font-semibold'
                  : 'bg-slate-900/60 text-slate-400 border-slate-800 hover:text-slate-200'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Main Content Area */}
      <div className="max-w-6xl w-full mx-auto p-4 sm:p-6 space-y-6 text-xs">
        {/* Metric Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
            <div className="text-[11px] text-slate-400">Abuse Confidence Score</div>
            <div className="text-2xl font-bold text-rose-400 mt-1">92%</div>
            <div className="text-[10px] text-slate-400 mt-1">Severe Malicious Profile</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
            <div className="text-[11px] text-slate-400">Reported Attacks (24h)</div>
            <div className="text-2xl font-bold text-amber-400 mt-1">2,841</div>
            <div className="text-[10px] text-slate-400 mt-1">Global sensor network</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
            <div className="text-[11px] text-slate-400">Attributed Actor</div>
            <div className="text-base font-bold text-cyan-300 mt-1">APT29 / Nobelium</div>
            <div className="text-[10px] text-slate-400 mt-1">High confidence match</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
            <div className="text-[11px] text-slate-400">Reverse DNS</div>
            <div className="text-xs font-bold text-slate-200 mt-1 truncate">tor-exit-frankfurt-04</div>
            <div className="text-[10px] text-slate-400 mt-1">Zwiebelfreunde e.V.</div>
          </div>
        </div>

        {/* Tab Content Display */}
        {activeTab === 'overview' && (
          <div className="space-y-4">
            <div className="p-6 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4">
              <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-cyan-400" />
                Comprehensive Target Dossier Analysis
              </h2>
              <p className="text-slate-300 font-sans leading-relaxed text-xs">
                Target IP <code className="text-cyan-300">185.220.101.5</code> is a known Tor exit node hosted in Frankfurt am Main, Germany, operated on AS206238. Starting in mid-February 2025, security telemetry began recording persistent high-frequency HTTPS connections with specific cookie jitter patterns characteristic of a Cobalt Strike malleable C2 profile.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                  <div className="text-slate-400 text-[11px]">Primary Campaign TTPs</div>
                  <ul className="space-y-1 text-slate-300">
                    <li>• T1071.001 - Web Protocols (Port 8080 C2 Beaconing)</li>
                    <li>• T1090.003 - Tor Multi-Hop Anonymization Proxy</li>
                    <li>• T1059.001 - In-Memory PowerShell Download Cradle</li>
                    <li>• T1078.004 - Cloud Admin Credential Theft</li>
                  </ul>
                </div>
                <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                  <div className="text-slate-400 text-[11px]">Associated Incident Files</div>
                  <div className="space-y-1.5">
                    <div 
                      onClick={() => onNavigate('investigations')}
                      className="p-2 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 cursor-pointer flex items-center justify-between transition-colors"
                    >
                      <span className="text-rose-300 font-semibold">INC-8941: Active Cobalt Strike Beacon</span>
                      <ArrowRight className="w-3 h-3 text-slate-400" />
                    </div>
                    <div 
                      onClick={() => onNavigate('investigations')}
                      className="p-2 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 cursor-pointer flex items-center justify-between transition-colors"
                    >
                      <span className="text-slate-300">INC-8812: CVE-2024-38077 Probe</span>
                      <ArrowRight className="w-3 h-3 text-slate-400" />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'shodan' && (
          <div className="p-6 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4">
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              Shodan Internet Reconnaissance & Banner Dumps
            </h2>
            <div className="space-y-3">
              {[
                { port: 22, service: 'SSH', banner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\nKey: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...' },
                { port: 443, service: 'HTTPS / TLS', banner: 'HTTP/1.1 200 OK\nServer: nginx/1.18.0\nTLS: TLSv1.3 / ECDHE-RSA-AES256-GCM-SHA384' },
                { port: 8080, service: 'HTTP (Cobalt Strike C2)', banner: 'HTTP/1.1 404 Not Found\nContent-Type: text/plain\nCookie: __cfduid=... (Matches Malleable C2 Profile)' },
                { port: 9001, service: 'Tor Relay', banner: 'Tor ORPort 9001 open\nFingerprint: 7B90 4128 FA41 88A9 0019 321C' }
              ].map(p => (
                <div key={p.port} className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 font-bold">
                        TCP PORT {p.port}
                      </span>
                      <span className="text-slate-300">{p.service}</span>
                    </div>
                    <span className="text-[10px] text-emerald-400">LISTEN</span>
                  </div>
                  <pre className="p-2 rounded bg-slate-900 text-[10px] text-slate-300 font-mono whitespace-pre overflow-x-auto">
                    {p.banner}
                  </pre>
                </div>
              ))}
            </div>
          </div>
        )}

        {(activeTab === 'abuse' || activeTab === 'virustotal' || activeTab === 'cve') && (
          <div className="p-6 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4">
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Live Feed Ingestion: {activeTab.toUpperCase()}
            </h2>
            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 leading-relaxed font-sans">
              Aggregated 64 malicious vendor verdicts (Kaspersky, CrowdStrike, SentinelOne, Microsoft Defender) confirming payload staging and beaconing behavior targeting cloud workloads.
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
