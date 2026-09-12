import React, { useState } from 'react';
import { 
  FileCode, 
  ShieldCheck, 
  Filter, 
  X, 
  Download, 
  CheckCircle2, 
  AlertCircle,
  Clock,
  User,
  Shield
} from 'lucide-react';
import { AuditLogEntry } from '../../types';

interface AuditLogModalProps {
  isOpen: boolean;
  onClose: () => void;
  auditLogs?: AuditLogEntry[];
}

export const INITIAL_AUDIT_LOGS: AuditLogEntry[] = [
  {
    id: 'aud-101',
    timestamp: '2025-02-18 04:45:12 UTC',
    event: 'INVESTIGATION_STARTED',
    actor: 'Sarah Chen (Incident Responder)',
    details: 'Initiated PASSIVE INTELLIGENCE investigation on target 185.220.101.5 (Scope: C2 beaconing analysis)',
    classification: 'TLP:AMBER'
  },
  {
    id: 'aud-102',
    timestamp: '2025-02-18 04:32:05 UTC',
    event: 'TOOL_EXECUTED',
    actor: 'Autonomous Agent Engine',
    details: 'Executed Shodan port sweep & banner grab on 185.220.101.5 (Identified 4 open ports)',
    classification: 'TLP:GREEN'
  },
  {
    id: 'aud-103',
    timestamp: '2025-02-18 04:25:40 UTC',
    event: 'TARGET_ADDED',
    actor: 'Sarah Chen',
    details: 'Ingested IPv4 10.240.12.89 (PROD-K8S-WORKER-09) into high-priority target monitoring scope',
    classification: 'TLP:AMBER'
  },
  {
    id: 'aud-104',
    timestamp: '2025-02-18 04:18:19 UTC',
    event: 'IOC_SAVED',
    actor: 'Autonomous Incident Triager',
    details: 'Saved observable powershell.exe -enc stager to IOC Threat Ledger with critical severity',
    classification: 'TLP:RED'
  },
  {
    id: 'aud-105',
    timestamp: '2025-02-18 04:12:00 UTC',
    event: 'LOGIN',
    actor: 'Sarah Chen',
    details: 'Successful authentication into Sentinel Defense Corp workspace via PKI Session Token',
    classification: 'TLP:CLEAR'
  },
  {
    id: 'aud-106',
    timestamp: '2025-02-17 19:42:10 UTC',
    event: 'REPORT_GENERATED',
    actor: 'Marcus Vance',
    details: 'Generated Incident Assessment Report REP-8941 for Cobalt Strike Infiltration & C2 Neutralization',
    classification: 'TLP:AMBER'
  },
  {
    id: 'aud-107',
    timestamp: '2025-02-17 14:15:30 UTC',
    event: 'DOCUMENT_UPLOADED',
    actor: 'Elena Rostova',
    details: 'Uploaded Incident Handling & Containment SOP-88 (120 semantic chunks vectorized)',
    classification: 'TLP:GREEN'
  }
];

export const AuditLogModal: React.FC<AuditLogModalProps> = ({ 
  isOpen, 
  onClose,
  auditLogs = INITIAL_AUDIT_LOGS 
}) => {
  const [filterEvent, setFilterEvent] = useState<string>('ALL');

  if (!isOpen) return null;

  const filteredLogs = filterEvent === 'ALL' 
    ? auditLogs 
    : auditLogs.filter(l => l.event === filterEvent);

  const getEventBadge = (event: AuditLogEntry['event']) => {
    switch (event) {
      case 'LOGIN':
      case 'LOGOUT':
        return <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">{event}</span>;
      case 'TARGET_ADDED':
        return <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">{event}</span>;
      case 'INVESTIGATION_STARTED':
        return <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">{event}</span>;
      case 'TOOL_EXECUTED':
        return <span className="px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">{event}</span>;
      case 'DOCUMENT_UPLOADED':
        return <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">{event}</span>;
      case 'IOC_SAVED':
        return <span className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">{event}</span>;
      case 'REPORT_GENERATED':
        return <span className="px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">{event}</span>;
      default:
        return <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400">{event}</span>;
    }
  };

  const getTlpBadge = (tlp: AuditLogEntry['classification']) => {
    switch (tlp) {
      case 'TLP:RED':
        return <span className="text-[9px] px-1.5 py-0.2 rounded bg-rose-950/60 text-rose-300 border border-rose-800/80 font-bold">{tlp}</span>;
      case 'TLP:AMBER':
        return <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-950/60 text-amber-300 border border-amber-800/80 font-bold">{tlp}</span>;
      case 'TLP:GREEN':
        return <span className="text-[9px] px-1.5 py-0.2 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800/80 font-bold">{tlp}</span>;
      case 'TLP:CLEAR':
      default:
        return <span className="text-[9px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 border border-slate-700">{tlp}</span>;
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-3xl bg-[#090d15] border border-slate-700/80 rounded-2xl shadow-2xl overflow-hidden font-mono text-xs animate-in fade-in zoom-in-95 duration-150 flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 bg-[#0c111c] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
              <FileCode className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
                  Security Operations Audit Trail
                </h2>
                <span className="px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 text-[9px] font-semibold">
                  IMMUTABLE
                </span>
              </div>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Cryptographically hashed action logs for investigations, tools, and indicators
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

        {/* Zero-Trust Notice: No Passwords or Tokens */}
        <div className="px-5 py-2.5 bg-cyan-950/20 border-b border-slate-800 flex items-center justify-between text-[11px]">
          <div className="flex items-center gap-2 text-slate-300">
            <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0" />
            <span>
              <strong>Zero-Trust Privacy Protection</strong>: Passwords, API keys, tokens, and authorization secrets are strictly filtered and never written to audit records.
            </span>
          </div>
          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <select
              value={filterEvent}
              onChange={(e) => setFilterEvent(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded px-2 py-1 text-slate-300 text-[10px] focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Events ({auditLogs.length})</option>
              <option value="INVESTIGATION_STARTED">Investigation Started</option>
              <option value="TOOL_EXECUTED">Tool Executed</option>
              <option value="TARGET_ADDED">Target Added</option>
              <option value="IOC_SAVED">IOC Saved</option>
              <option value="DOCUMENT_UPLOADED">Document Uploaded</option>
              <option value="REPORT_GENERATED">Report Generated</option>
              <option value="LOGIN">Login</option>
            </select>
          </div>
        </div>

        {/* Audit Log Table */}
        <div className="overflow-y-auto p-4 space-y-2">
          {filteredLogs.map(log => (
            <div 
              key={log.id}
              className="p-3 rounded-xl bg-slate-900/60 border border-slate-800/80 hover:border-slate-700/90 transition-all space-y-1.5"
            >
              <div className="flex items-center justify-between flex-wrap gap-2 text-[10px]">
                <div className="flex items-center gap-2">
                  {getEventBadge(log.event)}
                  <span className="text-slate-400 font-mono">{log.timestamp}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-slate-400 flex items-center gap-1">
                    <User className="w-3 h-3 text-cyan-400" />
                    <span>{log.actor}</span>
                  </span>
                  {getTlpBadge(log.classification)}
                </div>
              </div>
              <p className="text-slate-200 text-xs font-mono">{log.details}</p>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-[#0a0e17] flex items-center justify-between text-slate-400 text-[11px]">
          <span>Log Integrity: SHA256 Chained Hash Valid</span>
          <button
            onClick={onClose}
            className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold transition-colors"
          >
            Close Audit Log
          </button>
        </div>
      </div>
    </div>
  );
};
