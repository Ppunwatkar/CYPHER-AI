import React, { useState } from 'react';
import { 
  GitFork, 
  CheckCircle2, 
  Clock, 
  AlertTriangle, 
  ShieldAlert, 
  Terminal, 
  Lock, 
  Play, 
  RotateCw,
  Cpu,
  Layers,
  Check,
  X
} from 'lucide-react';
import { ScreenType, WorkflowNode } from '../../types';

interface AgentWorkflowsScreenProps {
  onNavigate: (screen: ScreenType) => void;
}

export const AgentWorkflowsScreen: React.FC<AgentWorkflowsScreenProps> = ({ onNavigate }) => {
  const [approvalStatus, setApprovalStatus] = useState<'waiting' | 'approved' | 'rejected'>('waiting');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const nodes: WorkflowNode[] = [
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
      status: approvalStatus === 'waiting' ? 'waiting_approval' : approvalStatus === 'approved' ? 'completed' : 'failed',
      details: 'Analyst approval required before severing container network interfaces'
    },
    {
      id: 'n-5',
      title: 'Automated Token Invalidation & NGFW Drop',
      type: 'remediation',
      status: approvalStatus === 'approved' ? 'completed' : 'pending',
      details: 'Revoke AWS STS credentials & inject IP to Panorama Blocklist'
    }
  ];

  const handleApprove = () => {
    setApprovalStatus('approved');
    showToast('✅ HITL Gate Approved: Container network severed and credentials revoked');
  };

  const handleReject = () => {
    setApprovalStatus('rejected');
    showToast('❌ HITL Gate Rejected: Automated remediation aborted by analyst');
  };

  return (
    <div className="flex-1 flex flex-col overflow-y-auto bg-[#080b11] text-slate-100 font-mono text-xs">
      {/* Toast */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 bg-cyan-950/90 border border-cyan-400/50 text-cyan-200 px-4 py-3 rounded-lg shadow-xl backdrop-blur-md animate-in fade-in">
          <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Header */}
      <div className="p-6 border-b border-slate-800/80 bg-[#0a0e17]/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 text-xs mb-1">
            <GitFork className="w-4 h-4" />
            <span>AUTONOMOUS THREAT HUNTING DAG (DIRECTED ACYCLIC GRAPH)</span>
          </div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100">
            Autonomous Incident Triager & Remediation Pipeline
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time execution DAG with Human-in-the-Loop authorization safeguards
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300">
            Pipeline: <span className="text-cyan-300 font-bold">PL-AUTO-CONTAIN-04</span>
          </span>
        </div>
      </div>

      {/* DAG View */}
      <div className="max-w-4xl w-full mx-auto p-6 space-y-6">
        {/* HITL Gate Banner if waiting */}
        {approvalStatus === 'waiting' && (
          <div className="p-5 rounded-xl bg-amber-950/40 border border-amber-500/50 space-y-3 shadow-lg">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-amber-300 font-bold text-sm">
                <Lock className="w-4 h-4" />
                <span>HUMAN-IN-THE-LOOP AUTHORIZATION REQUIRED</span>
              </div>
              <span className="text-[10px] px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                AWAITING DECISION
              </span>
            </div>
            <p className="text-slate-300 font-sans leading-relaxed text-xs">
              The autonomous triager has confirmed active Cobalt Strike beaconing from <strong>PROD-K8S-WORKER-09</strong> to <strong>185.220.101.5</strong>. The next automated action will disconnect the host from the internal network and revoke all AWS IAM credentials. Do you authorize this action?
            </p>
            <div className="flex items-center gap-3 pt-1">
              <button
                onClick={handleApprove}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold flex items-center gap-1.5 transition-colors shadow-md"
              >
                <Check className="w-4 h-4" />
                <span>Authorize Remediation Execution</span>
              </button>
              <button
                onClick={handleReject}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 flex items-center gap-1.5 transition-colors"
              >
                <X className="w-4 h-4" />
                <span>Abort / Hold for Manual Triage</span>
              </button>
            </div>
          </div>
        )}

        {/* Pipeline Nodes List */}
        <div className="space-y-4">
          {nodes.map((n, idx) => (
            <div 
              key={n.id}
              className={`p-4 rounded-xl border transition-all ${
                n.status === 'completed' ? 'bg-slate-900/90 border-slate-800' :
                n.status === 'waiting_approval' ? 'bg-amber-950/30 border-amber-500/40 shadow-[0_0_15px_rgba(245,158,11,0.1)]' :
                'bg-slate-950/40 border-slate-800/60 opacity-60'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className={`w-7 h-7 rounded-lg flex items-center justify-center font-bold ${
                    n.status === 'completed' ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/40' :
                    n.status === 'waiting_approval' ? 'bg-amber-950 text-amber-400 border border-amber-500/40 animate-pulse' :
                    'bg-slate-800 text-slate-400'
                  }`}>
                    {idx + 1}
                  </div>
                  <div>
                    <div className="font-semibold text-slate-200 text-xs">
                      {n.title}
                    </div>
                    <div className="text-[11px] text-slate-400 font-sans mt-0.5">
                      {n.details}
                    </div>
                  </div>
                </div>

                <div className="text-right">
                  <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${
                    n.status === 'completed' ? 'bg-emerald-950/80 text-emerald-300 border-emerald-500/40' :
                    n.status === 'waiting_approval' ? 'bg-amber-950/80 text-amber-300 border-amber-500/40' :
                    'bg-slate-900 text-slate-500 border-slate-800'
                  }`}>
                    {n.status.replace('_', ' ')}
                  </span>
                  {n.duration && (
                    <div className="text-[10px] text-slate-500 mt-1">{n.duration}</div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
