import React, { useState } from 'react';
import { 
  Activity, 
  ShieldAlert, 
  Clock, 
  CheckCircle2, 
  FileText, 
  ExternalLink, 
  Terminal, 
  AlertTriangle, 
  Bot, 
  RotateCw,
  Server,
  Lock,
  User,
  Zap
} from 'lucide-react';
import { ScreenType, InvestigationCase } from '../../types';
import { ACTIVE_CASES } from '../../data/mockData';

interface InvestigationsScreenProps {
  onNavigate: (screen: ScreenType) => void;
  onSendToCopilot?: (query: string) => void;
}

export const InvestigationsScreen: React.FC<InvestigationsScreenProps> = ({ onNavigate, onSendToCopilot }) => {
  const [cases, setCases] = useState<InvestigationCase[]>(ACTIVE_CASES);
  const [selectedCase, setSelectedCase] = useState<InvestigationCase>(ACTIVE_CASES[0]);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const handleContainIncident = () => {
    const updated = {
      ...selectedCase,
      status: 'contained' as const,
      summary: selectedCase.summary + ' [CONTAINED: Automated AWS IAM STS token revocation completed]'
    };
    setSelectedCase(updated);
    setCases(cases.map(c => c.id === updated.id ? updated : c));
    showToast('⚡ Incident contained! AWS IAM role session revoked and container isolated.');
  };

  return (
    <div className="flex-1 flex overflow-hidden bg-[#080b11] text-slate-100 font-mono text-xs">
      {/* Toast */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 bg-emerald-950/90 border border-emerald-400/50 text-emerald-200 px-4 py-3 rounded-lg shadow-xl backdrop-blur-md animate-in fade-in">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Left Pane: Incident Cases List */}
      <div className="w-80 lg:w-96 border-r border-slate-800/80 bg-[#090d15] flex flex-col shrink-0 overflow-y-auto select-none">
        <div className="p-4 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-2 text-cyan-400 font-semibold">
            <Activity className="w-4 h-4" />
            <span>Active Incidents ({cases.length})</span>
          </div>
          <span className="text-[10px] px-2 py-0.5 rounded bg-rose-950/60 border border-rose-500/40 text-rose-300">
            1 Critical
          </span>
        </div>

        <div className="divide-y divide-slate-800/60">
          {cases.map(c => {
            const isSelected = selectedCase.id === c.id;
            return (
              <div
                key={c.id}
                onClick={() => setSelectedCase(c)}
                className={`p-4 cursor-pointer transition-colors space-y-2 ${
                  isSelected ? 'bg-cyan-950/40 border-l-2 border-cyan-400' : 'hover:bg-slate-900/60'
                }`}
              >
                <div className="flex items-center justify-between text-[10px]">
                  <span className="font-bold text-cyan-300">{c.caseNumber}</span>
                  <span className={`px-1.5 py-0.2 rounded uppercase font-bold border ${
                    c.status === 'contained' ? 'bg-emerald-950/80 text-emerald-300 border-emerald-500/40' :
                    'bg-rose-950/80 text-rose-300 border-rose-500/40'
                  }`}>
                    {c.status}
                  </span>
                </div>

                <div className="font-semibold text-slate-200 line-clamp-2">
                  {c.title}
                </div>

                <div className="flex items-center justify-between text-[10px] text-slate-500">
                  <span>Lead: {c.leadAnalyst.split(' ')[0]}</span>
                  <span>{c.createdAt}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Right Pane: Selected Case Deep Forensics */}
      <div className="flex-1 flex flex-col min-w-0 overflow-y-auto">
        <div className="p-6 border-b border-slate-800/80 bg-[#0a0e17]/80 space-y-4">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 text-cyan-400 text-xs mb-1">
                <span>INCIDENT INVESTIGATION HUB</span>
                <span>•</span>
                <span className="text-slate-400">{selectedCase.createdAt}</span>
              </div>
              <h1 className="text-lg font-bold text-slate-100">
                {selectedCase.caseNumber}: {selectedCase.title}
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Assigned AI Agent: <span className="text-cyan-300">{selectedCase.assignedAiAgent}</span> • Lead: {selectedCase.leadAnalyst}
              </p>
            </div>

            <div className="flex items-center gap-2.5">
              <button
                onClick={() => onNavigate('security-intel')}
                className="px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-200 flex items-center gap-1.5 transition-colors"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>View Full Audit Report</span>
              </button>

              <button
                onClick={handleContainIncident}
                disabled={selectedCase.status === 'contained'}
                className="px-3.5 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:bg-emerald-950/80 disabled:text-emerald-300 text-white font-semibold flex items-center gap-1.5 transition-colors shadow-md"
              >
                <Zap className="w-3.5 h-3.5" />
                <span>{selectedCase.status === 'contained' ? 'Quarantine Active' : 'Execute Containment'}</span>
              </button>
            </div>
          </div>
        </div>

        {/* Case Details Body */}
        <div className="p-6 space-y-6 max-w-5xl">
          {/* Summary Box */}
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
            <div className="text-slate-400 text-[11px] uppercase tracking-wider">Executive Investigation Brief</div>
            <p className="text-slate-300 leading-relaxed font-sans text-xs">
              {selectedCase.summary}
            </p>
          </div>

          {/* Impacted Assets & IOCs */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
              <div className="text-slate-400 text-[11px] uppercase">Target Assets in Scope</div>
              <div className="space-y-1.5">
                {selectedCase.targetAssets.map((asset, i) => (
                  <div key={i} className="p-2 rounded bg-slate-950 border border-slate-800 text-slate-200 flex items-center justify-between">
                    <span>{asset}</span>
                    <span className="text-[10px] text-rose-400">ISOLATE TARGET</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
              <div className="text-slate-400 text-[11px] uppercase">Correlated IOCs</div>
              <div className="space-y-1.5">
                {selectedCase.iocs.map((ioc, i) => (
                  <div key={i} className="p-2 rounded bg-slate-950 border border-slate-800 text-cyan-300 flex items-center justify-between">
                    <span className="truncate">{ioc}</span>
                    <button 
                      onClick={() => onNavigate('threat-intel')}
                      className="text-[10px] text-slate-400 hover:text-cyan-300 underline"
                    >
                      Dossier
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Forensic Timeline */}
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
            <div className="text-slate-400 text-[11px] uppercase tracking-wider flex items-center gap-2">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              <span>Forensic Chronological Timeline</span>
            </div>

            <div className="space-y-2 relative pl-4 border-l border-slate-800">
              {selectedCase.timeline.map((evt, idx) => (
                <div key={idx} className="relative group">
                  <span className="absolute -left-[21px] top-1.5 w-2 h-2 rounded-full bg-cyan-400 ring-2 ring-slate-900" />
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                    <div className="flex items-center justify-between text-[10px] text-slate-500">
                      <span className="font-bold text-slate-300">{evt.time}</span>
                      <span className="px-1.5 py-0.2 rounded bg-slate-900 text-cyan-400 border border-slate-800">{evt.source}</span>
                    </div>
                    <div className="text-slate-200 text-xs font-sans">
                      {evt.event}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
