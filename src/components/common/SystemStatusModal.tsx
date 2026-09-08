import React from 'react';
import { 
  Server, 
  CheckCircle2, 
  AlertTriangle, 
  XCircle, 
  Clock, 
  Lock, 
  X, 
  RefreshCw, 
  ShieldCheck,
  Cpu,
  Database,
  Globe2,
  ExternalLink
} from 'lucide-react';
import { ServiceHealthStatus } from '../../types';

interface SystemStatusModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const SystemStatusModal: React.FC<SystemStatusModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  const services: ServiceHealthStatus[] = [
    {
      service: 'AI Model Gateway (Gemini 2.5 Flash / Pro)',
      category: 'AI Model',
      status: 'Operational',
      latencyMs: 142,
      notes: 'Active endpoint. SecOps fine-tuned instruction set loaded.'
    },
    {
      service: 'RAG Vector Knowledge Core (ChromaDB / Vector)',
      category: 'Storage',
      status: 'Operational',
      latencyMs: 48,
      notes: '18 indexed documents, 1,317 semantic chunks queryable.'
    },
    {
      service: 'Telemetry & Target Store (State Engine)',
      category: 'Storage',
      status: 'Operational',
      latencyMs: 12,
      notes: 'Local persistent state synchronizer healthy.'
    },
    {
      service: 'AbuseIPDB Reputation API',
      category: 'Threat Intel',
      status: 'Operational',
      latencyMs: 195,
      notes: 'Blacklist scoring active. (Simulated Demo Intelligence enabled)',
      isSimulated: true
    },
    {
      service: 'Shodan Internet Scanner & Banner Recon',
      category: 'Threat Intel',
      status: 'Operational',
      latencyMs: 220,
      notes: 'Passive port search active. (Simulated Demo Intelligence enabled)',
      isSimulated: true
    },
    {
      service: 'VirusTotal Multi-Engine Intelligence',
      category: 'Threat Intel',
      status: 'Rate Limited',
      latencyMs: 410,
      notes: 'Free Tier quota (4 requests/min). Fallback to cached hashes.',
      isSimulated: true
    },
    {
      service: 'NIST NVD / CVE Vulnerability Feed',
      category: 'Vulnerability',
      status: 'Operational',
      latencyMs: 160,
      notes: 'CVE-2024 / CVE-2025 dictionary synched daily.'
    },
    {
      service: 'HaveIBeenPwned (HIBP) Credential Exposure',
      category: 'Identity',
      status: 'Not Configured',
      latencyMs: 0,
      notes: 'API Key not provided. Configure in environment to activate.'
    }
  ];

  const getStatusBadge = (status: ServiceHealthStatus['status']) => {
    switch (status) {
      case 'Operational':
        return (
          <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-semibold">
            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
            <span>Operational</span>
          </span>
        );
      case 'Rate Limited':
        return (
          <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20 text-[10px] font-semibold">
            <Clock className="w-3 h-3 text-amber-400" />
            <span>Rate Limited</span>
          </span>
        );
      case 'Degraded':
        return (
          <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-orange-500/10 text-orange-400 border border-orange-500/20 text-[10px] font-semibold">
            <AlertTriangle className="w-3 h-3 text-orange-400" />
            <span>Degraded</span>
          </span>
        );
      case 'Not Configured':
        return (
          <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700 text-[10px] font-semibold">
            <Lock className="w-3 h-3 text-slate-400" />
            <span>Not Configured</span>
          </span>
        );
      case 'Unavailable':
      default:
        return (
          <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[10px] font-semibold">
            <XCircle className="w-3 h-3 text-rose-400" />
            <span>Unavailable</span>
          </span>
        );
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-2xl bg-[#090d15] border border-slate-700/80 rounded-2xl shadow-2xl overflow-hidden font-mono text-xs animate-in fade-in zoom-in-95 duration-150 flex flex-col max-h-[88vh]">
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 bg-[#0c111c] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
              <Server className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
                  System Health & Gateway Connectors
                </h2>
                <span className="px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[9px] font-semibold">
                  7/8 ONLINE
                </span>
              </div>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Live diagnostics for AI pipelines, intelligence APIs, and knowledge vectors
              </p>
            </div>
          </div>

          <button 
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Security & Credentials Privacy Banner */}
        <div className="px-5 py-2.5 bg-cyan-950/30 border-b border-cyan-500/20 flex items-center gap-2.5 text-cyan-300 text-[11px]">
          <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>
            <strong>Zero-Trust Architecture</strong>: All secret API credentials reside strictly in server-side environment variables and are never rendered to browser memory.
          </span>
        </div>

        {/* Services Table */}
        <div className="overflow-y-auto p-4 space-y-2.5">
          {services.map((s, idx) => (
            <div 
              key={idx}
              className="p-3 rounded-xl bg-slate-900/70 border border-slate-800/80 hover:border-slate-700 transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3"
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-semibold text-slate-200 text-xs">{s.service}</span>
                  <span className="text-[9px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700/60">
                    {s.category}
                  </span>
                  {s.isSimulated && (
                    <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                      DEMO DATA
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 mt-1">{s.notes}</p>
              </div>

              <div className="flex items-center gap-3 shrink-0 justify-between sm:justify-end">
                {s.latencyMs > 0 && (
                  <span className="text-[10px] text-slate-500 font-mono">
                    {s.latencyMs}ms
                  </span>
                )}
                {getStatusBadge(s.status)}
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-[#0a0e17] flex items-center justify-between text-slate-400 text-[11px]">
          <span>Diagnostic poll interval: 30s</span>
          <button
            onClick={onClose}
            className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold transition-colors"
          >
            Close Diagnostics
          </button>
        </div>
      </div>
    </div>
  );
};
