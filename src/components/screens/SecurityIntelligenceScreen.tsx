import React, { useState } from 'react';
import { 
  FileText, 
  Download, 
  Share2, 
  Copy, 
  Check, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  Clock, 
  Key, 
  Layers, 
  ArrowRight, 
  ExternalLink,
  Lock,
  Sparkles,
  Printer,
  ChevronRight,
  Stamp
} from 'lucide-react';
import { ScreenType, SecurityReport } from '../../types';
import { INITIAL_SECURITY_REPORT } from '../../data/mockData';

interface SecurityIntelligenceScreenProps {
  onNavigate: (screen: ScreenType) => void;
}

export const SecurityIntelligenceScreen: React.FC<SecurityIntelligenceScreenProps> = ({ onNavigate }) => {
  const [report, setReport] = useState<SecurityReport>(INITIAL_SECURITY_REPORT);
  const [selectedReportType, setSelectedReportType] = useState<string>('rep-8941');
  const [copiedHash, setCopiedHash] = useState(false);
  const [isSignedOff, setIsSignedOff] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const handleCopyHash = () => {
    navigator.clipboard.writeText(report.hashVerification);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const handleDownloadPDF = () => {
    showToast('📄 Generated high-resolution forensic audit report (PDF format)');
  };

  const handleSignOff = () => {
    setIsSignedOff(true);
    showToast('🔏 Cryptographic analyst attestation signed with YubiKey FIDO2 token');
  };

  return (
    <div className="flex-1 flex flex-col overflow-y-auto bg-[#080b11] text-slate-100 font-mono">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 bg-cyan-950/90 border border-cyan-400/50 text-cyan-200 px-4 py-3 rounded-lg shadow-xl backdrop-blur-md animate-in fade-in text-xs">
          <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Header Bar */}
      <div className="p-6 border-b border-slate-800/80 bg-[#0a0e17]/80 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 text-xs mb-1">
              <FileText className="w-4 h-4" />
              <span>FORENSIC ASSESSMENT & COMPLIANCE DOSSIER</span>
            </div>
            <h1 className="text-xl font-bold tracking-tight text-slate-100 font-mono">
              CIPHER AI — Security Intelligence & Compliance Reports
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Cryptographically verified incident assessments, MITRE ATT&CK mapping, and automated remediation roadmaps
            </p>
          </div>

          {/* Action Bar */}
          <div className="flex items-center gap-2.5">
            <button
              onClick={handleDownloadPDF}
              className="px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 text-slate-200 text-xs flex items-center gap-1.5 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download PDF</span>
            </button>

            <button
              onClick={() => {
                navigator.clipboard.writeText(report.attackNarrative);
                showToast('📋 Attack narrative markdown copied to clipboard');
              }}
              className="px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 text-slate-200 text-xs flex items-center gap-1.5 transition-colors"
            >
              <Copy className="w-3.5 h-3.5" />
              <span>Copy MD</span>
            </button>

            <button
              onClick={handleSignOff}
              disabled={isSignedOff}
              className={`px-4 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all shadow-md ${
                isSignedOff
                  ? 'bg-emerald-950/80 border border-emerald-500/40 text-emerald-300 cursor-default'
                  : 'bg-cyan-600 hover:bg-cyan-500 text-white'
              }`}
            >
              {isSignedOff ? (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Attested & Signed-Off</span>
                </>
              ) : (
                <>
                  <Stamp className="w-3.5 h-3.5" />
                  <span>Sign-Off Report</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Report Template Selector Pills */}
        <div className="flex items-center gap-2 overflow-x-auto pt-2 text-xs">
          <span className="text-slate-500 text-[11px] shrink-0">Available Reports:</span>
          {[
            { id: 'rep-8941', label: 'INC-8941: Cobalt Strike Infiltration Post-Mortem', active: true },
            { id: 'rep-cve', label: 'CVE-2024-38077 Perimeter Vulnerability Analysis', active: false },
            { id: 'rep-soc2', label: 'SOC 2 Type II Incident Response Compliance Audit', active: false },
            { id: 'rep-apt29', label: 'APT29 (Midnight Blizzard) Global Threat Campaign', active: false }
          ].map(tpl => (
            <button
              key={tpl.id}
              onClick={() => {
                setSelectedReportType(tpl.id);
                showToast(`Loaded report: ${tpl.label}`);
              }}
              className={`px-3 py-1.5 rounded-lg shrink-0 transition-colors border ${
                selectedReportType === tpl.id
                  ? 'bg-cyan-950/60 text-cyan-300 border-cyan-500/40 font-semibold'
                  : 'bg-slate-900/60 text-slate-400 border-slate-800 hover:text-slate-200'
              }`}
            >
              {tpl.label}
            </button>
          ))}
        </div>
      </div>

      {/* Main Document Content Container */}
      <div className="max-w-5xl w-full mx-auto p-6 space-y-6">
        {/* Verification & Metadata Ribbon */}
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4 text-xs">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2.5">
              <span className="px-2 py-0.5 rounded bg-amber-950/80 border border-amber-500/40 text-amber-300 font-bold text-[10px]">
                {report.classification}
              </span>
              <span className="text-slate-400">Published: {report.createdDate}</span>
              <span className="text-slate-600">•</span>
              <span className="text-slate-400">Author: {report.author}</span>
            </div>
            <div className="flex items-center gap-2 text-slate-400 text-[11px]">
              <Lock className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              <span className="truncate max-w-md">{report.hashVerification}</span>
              <button
                onClick={handleCopyHash}
                className="text-cyan-400 hover:text-cyan-300"
                title="Copy hash"
              >
                {copiedHash ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              </button>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="text-right">
              <div className="text-[10px] text-slate-400">Report Status</div>
              <div className="text-xs font-bold text-emerald-400">
                {isSignedOff ? 'LEGALLY ATTESTED' : 'AWAITING SIGN-OFF'}
              </div>
            </div>
            <div className="w-10 h-10 rounded-lg bg-emerald-950/60 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
              <CheckCircle2 className="w-5 h-5" />
            </div>
          </div>
        </div>

        {/* Executive Threat Metrics Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
            <div className="text-[11px] text-slate-400">CVSS v3.1 Score</div>
            <div className="text-2xl font-bold text-rose-400 mt-1 flex items-baseline gap-1">
              <span>{report.cvssScore}</span>
              <span className="text-xs text-rose-400/80 font-normal">/ 10.0 CRITICAL</span>
            </div>
            <div className="text-[10px] text-slate-400 mt-1">
              Vector: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
            <div className="text-[11px] text-slate-400">Lateral Exposure</div>
            <div className="text-base font-bold text-amber-400 mt-1">High</div>
            <div className="text-[10px] text-slate-400 mt-1">
              {report.lateralExposure}
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
            <div className="text-[11px] text-slate-400">Affected Infrastructure</div>
            <div className="text-2xl font-bold text-cyan-400 mt-1">
              {report.affectedSystems} Hosts
            </div>
            <div className="text-[10px] text-slate-400 mt-1">
              PROD Kubernetes cluster worker nodes
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
            <div className="text-[11px] text-slate-400">Containment Speed (MTTN)</div>
            <div className="text-2xl font-bold text-emerald-400 mt-1">35 mins</div>
            <div className="text-[10px] text-emerald-400/80 mt-1">
              Autonomous SOAR containment
            </div>
          </div>
        </div>

        {/* Attack Narrative Section */}
        <div className="p-6 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              1. Incident Overview & Attack Narrative
            </h2>
            <span className="text-[10px] text-slate-400">Source: CIPHER Threat Engine</span>
          </div>

          <div className="text-xs text-slate-300 leading-relaxed space-y-3 whitespace-pre-wrap font-sans">
            {report.attackNarrative}
          </div>

          {/* Quick Cross-Nav Buttons */}
          <div className="pt-2 flex flex-wrap gap-2 text-xs">
            <button
              onClick={() => onNavigate('threat-intel')}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 flex items-center gap-1.5 transition-colors"
            >
              <span>Inspect C2 Target 185.220.101.5</span>
              <ExternalLink className="w-3 h-3" />
            </button>
            <button
              onClick={() => onNavigate('investigations')}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 flex items-center gap-1.5 transition-colors"
            >
              <span>View Active Case INC-8941</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          </div>
        </div>

        {/* MITRE ATT&CK Kill-Chain Visualizer Flow */}
        <div className="p-6 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              2. MITRE ATT&CK® Kill-Chain Mapping
            </h2>
            <span className="text-[10px] text-cyan-400">Enterprise Matrix v14</span>
          </div>

          {/* Kill chain steps */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            {report.mitreChain.map((step, idx) => (
              <div 
                key={idx}
                className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex flex-col justify-between space-y-2 relative group hover:border-cyan-500/50 transition-colors"
              >
                <div>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 mb-1">
                    <span>STAGE {idx + 1}</span>
                    <span className="text-cyan-400 font-bold">{step.techniqueId}</span>
                  </div>
                  <div className="text-xs font-bold text-slate-200">
                    {step.tactic}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    {step.techniqueName}
                  </div>
                </div>

                <div className="text-[10px] text-slate-400 p-2 rounded bg-slate-900/80 border border-slate-800/80 leading-relaxed font-sans">
                  {step.evidence}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Remediation & Hardening Roadmap */}
        <div className="p-6 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              3. Remediation & Hardening Roadmap
            </h2>
            <span className="text-[10px] text-emerald-400">3-Tier Quarantine Protocol</span>
          </div>

          <div className="space-y-3">
            {report.remediationRoadmap.map((item, idx) => (
              <div 
                key={idx}
                className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2.5"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${
                      item.status === 'completed' ? 'bg-emerald-400' :
                      item.status === 'in_progress' ? 'bg-amber-400 animate-pulse' : 'bg-slate-500'
                    }`} />
                    <span className="text-xs font-bold text-slate-200">{item.phase}</span>
                    <span className="text-[10px] text-slate-500">({item.timeframe})</span>
                  </div>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${
                    item.status === 'completed' ? 'bg-emerald-950/80 text-emerald-300 border-emerald-500/40' :
                    item.status === 'in_progress' ? 'bg-amber-950/80 text-amber-300 border-amber-500/40' :
                    'bg-slate-900 text-slate-400 border-slate-700'
                  }`}>
                    {item.status.replace('_', ' ')}
                  </span>
                </div>

                <div className="space-y-1.5 pl-4 border-l border-slate-800">
                  {item.actions.map((act, aIdx) => (
                    <div key={aIdx} className="text-xs text-slate-300 flex items-start gap-2 font-sans">
                      <span className="text-cyan-400 font-mono">›</span>
                      <span>{act}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Regulatory & Compliance Attestation Box */}
        <div className="p-6 rounded-xl bg-gradient-to-br from-slate-900 to-slate-950 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              4. Formal Attestation & Governance Sign-Off
            </h2>
            <span className="text-[10px] text-slate-400">SOC2 CC7.3 • ISO 27001 A.16.1</span>
          </div>

          <p className="text-xs text-slate-400 leading-relaxed font-sans">
            By issuing this cryptographic signature, the SecOps Lead Analyst certifies that the containment procedures above have been executed in accordance with Enterprise Incident Handling Standards, and that lateral movement paths have been analyzed and neutralized.
          </p>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
            <div>
              <div className="text-slate-200 font-semibold">Lead Investigator: Sarah Chen</div>
              <div className="text-[10px] text-slate-500">Certificate: US-WEST-FED-PKI-88419</div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={handleSignOff}
                disabled={isSignedOff}
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:bg-emerald-950/80 disabled:text-emerald-300 disabled:border disabled:border-emerald-500/40 text-white font-medium transition-all"
              >
                {isSignedOff ? 'Signed with FIDO2 Hardware Token' : 'Apply Cryptographic Sign-Off'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
