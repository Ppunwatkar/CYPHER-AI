import React, { useState } from 'react';
import { 
  Crosshair, 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle, 
  Clock, 
  Globe2, 
  FileText, 
  ShieldCheck, 
  Bot, 
  ChevronDown, 
  ChevronUp, 
  Save, 
  FileCode, 
  ArrowRight,
  ExternalLink,
  Info,
  Radio,
  Plus
} from 'lucide-react';
import { 
  SecurityTarget, 
  InvestigationPlan, 
  EvidenceSourceItem, 
  InvestigationVerdict, 
  ExtractedIndicator,
  InvestigationType 
} from '../../types';

/**
 * 1. TARGET SCOPE SAFETY CARD
 * Displays target type, environment, passive vs active toggle, authorization warning, and [Investigate Target]
 */
interface TargetScopeSafetyCardProps {
  targetValue: string;
  targetType: SecurityTarget['type'];
  environment?: SecurityTarget['environment'];
  onConfirmInvestigation: (investigationType: InvestigationType) => void;
  onCancel?: () => void;
}

export const TargetScopeSafetyCard: React.FC<TargetScopeSafetyCardProps> = ({
  targetValue,
  targetType,
  environment = 'external_threat',
  onConfirmInvestigation,
  onCancel
}) => {
  const [investigationType, setInvestigationType] = useState<InvestigationType>('PASSIVE INTELLIGENCE');

  return (
    <div className="p-4 rounded-xl bg-[#0d1322] border border-cyan-500/40 text-xs font-mono space-y-3.5 my-2 shadow-[0_0_20px_rgba(6,182,212,0.1)]">
      <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
        <div className="flex items-center gap-2 text-cyan-400 font-bold">
          <Crosshair className="w-4 h-4 text-cyan-400 animate-pulse" />
          <span className="uppercase tracking-wider">Target Scope Detected: {targetType.toUpperCase()}</span>
        </div>
        <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 text-[10px]">
          RFC VALIDATED
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
        <div className="p-2 rounded bg-slate-900/80 border border-slate-800">
          <span className="text-slate-500 block text-[10px]">TARGET VALUE:</span>
          <span className="text-slate-200 font-bold font-mono truncate block">{targetValue}</span>
        </div>
        <div className="p-2 rounded bg-slate-900/80 border border-slate-800">
          <span className="text-slate-500 block text-[10px]">ENVIRONMENT SCOPE:</span>
          <span className="text-slate-200 capitalize font-medium">{environment.replace('_', ' ')}</span>
        </div>
      </div>

      {/* Passive vs Active Toggle */}
      <div className="space-y-1.5">
        <span className="text-slate-400 text-[10px] uppercase font-semibold">Investigation Mode:</span>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <button
            type="button"
            onClick={() => setInvestigationType('PASSIVE INTELLIGENCE')}
            className={`p-2.5 rounded-lg border text-left transition-all ${
              investigationType === 'PASSIVE INTELLIGENCE'
                ? 'bg-cyan-950/70 border-cyan-500 text-cyan-200'
                : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:border-slate-700'
            }`}
          >
            <div className="font-semibold text-xs flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
              <span>PASSIVE INTELLIGENCE</span>
            </div>
            <p className="text-[10px] text-slate-400 mt-1">
              OSINT query via AbuseIPDB, Shodan feeds, VirusTotal, and NVD. No packets sent to target.
            </p>
          </button>

          <button
            type="button"
            onClick={() => setInvestigationType('ACTIVE ANALYSIS')}
            className={`p-2.5 rounded-lg border text-left transition-all ${
              investigationType === 'ACTIVE ANALYSIS'
                ? 'bg-amber-950/50 border-amber-500 text-amber-200'
                : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:border-slate-700'
            }`}
          >
            <div className="font-semibold text-xs flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              <span>ACTIVE ANALYSIS</span>
            </div>
            <p className="text-[10px] text-slate-400 mt-1">
              Correlates internal VPC flow logs, eBPF telemetry, and EDR host agent process tables.
            </p>
          </button>
        </div>
      </div>

      {/* Safety Notice per Directive 3 */}
      <div className="p-2.5 rounded-lg bg-amber-950/20 border border-amber-500/30 text-amber-300/90 text-[11px] flex items-start gap-2">
        <Info className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <strong>Safety & Scope Notice:</strong> Only investigate assets you are authorized to assess. CIPHER strictly adheres to read-only observational intelligence and will not perform unauthorized active port scans or destructive actions.
        </div>
      </div>

      {/* Actions */}
      <div className="flex items-center justify-end gap-2 pt-1">
        {onCancel && (
          <button
            type="button"
            onClick={onCancel}
            className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 transition-colors"
          >
            Dismiss
          </button>
        )}
        <button
          type="button"
          onClick={() => onConfirmInvestigation(investigationType)}
          className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold flex items-center gap-2 transition-all shadow-md"
        >
          <Crosshair className="w-3.5 h-3.5" />
          <span>Investigate Target</span>
        </button>
      </div>
    </div>
  );
};

/**
 * 2. INVESTIGATION PLAN CARD
 * Before Agent Mode executes, shows target, objective, planned operations, and [Approve Plan] [Cancel]
 */
interface InvestigationPlanCardProps {
  plan: InvestigationPlan;
  onApprove: () => void;
  onCancel: () => void;
}

export const InvestigationPlanCard: React.FC<InvestigationPlanCardProps> = ({
  plan,
  onApprove,
  onCancel
}) => {
  return (
    <div className="p-4 rounded-xl bg-[#0a0f1d] border border-cyan-500/50 text-xs font-mono space-y-3.5 my-2 shadow-lg">
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <div className="flex items-center gap-2 text-cyan-400 font-bold">
          <ShieldAlert className="w-4 h-4 text-cyan-400" />
          <span>INVESTIGATION PLAN — PRE-EXECUTION APPROVAL</span>
        </div>
        <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20 text-[10px]">
          AWAITING ANALYST SIGN-OFF
        </span>
      </div>

      <div className="space-y-1 text-[11px]">
        <div className="flex items-center gap-2">
          <span className="text-slate-400">Target Asset:</span>
          <span className="text-slate-100 font-bold">{plan.target}</span>
          <span className="text-slate-500">({plan.targetType} / {plan.environment})</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-slate-400">Objective:</span>
          <span className="text-cyan-300">{plan.objective}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-slate-400">Classification:</span>
          <span className="text-slate-300">{plan.investigationType}</span>
        </div>
      </div>

      {/* Planned Operations Sequence */}
      <div className="space-y-1.5">
        <span className="text-slate-400 text-[10px] uppercase font-semibold">Planned Operations Sequence:</span>
        <div className="space-y-1 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800">
          {plan.plannedOperations.map((op, idx) => (
            <div key={idx} className="flex items-center justify-between text-[11px] py-1 border-b border-slate-900 last:border-0">
              <div className="flex items-center gap-2">
                <span className="w-4 h-4 rounded-full bg-slate-800 text-slate-400 flex items-center justify-center text-[9px] shrink-0">
                  {idx + 1}
                </span>
                <span className="text-slate-200 font-semibold">{op.name}</span>
                <span className="text-slate-500 hidden sm:inline">— {op.description}</span>
              </div>
              <span className={`text-[9px] px-1.5 py-0.2 rounded border shrink-0 ${
                op.isPassive 
                  ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20' 
                  : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
              }`}>
                {op.isPassive ? 'Passive OSINT' : 'Active Query'}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Controls */}
      <div className="flex items-center justify-end gap-2 pt-1">
        <button
          type="button"
          onClick={onCancel}
          className="px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 transition-colors"
        >
          Cancel Plan
        </button>
        <button
          type="button"
          onClick={onApprove}
          className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold flex items-center gap-2 transition-all shadow-md"
        >
          <CheckCircle2 className="w-4 h-4" />
          <span>Approve Plan & Execute</span>
        </button>
      </div>
    </div>
  );
};

/**
 * 3. EVIDENCE CENTER & ASSESSMENT CARD
 * Shows evidence table with source provenance, simulated labels, CIPHER assessment, "Why this verdict", and timeline
 */
interface EvidenceCenterCardProps {
  evidence: EvidenceSourceItem[];
  verdict: InvestigationVerdict;
  onAskFollowup: (q: string) => void;
  onSaveCase: (verdict: InvestigationVerdict) => void;
  onSaveIoc: (iocValue: string) => void;
  onGenerateReport: (target: string) => void;
}

export const EvidenceCenterCard: React.FC<EvidenceCenterCardProps> = ({
  evidence,
  verdict,
  onAskFollowup,
  onSaveCase,
  onSaveIoc,
  onGenerateReport
}) => {
  const [showWhyVerdict, setShowWhyVerdict] = useState(true);
  const [showTimeline, setShowTimeline] = useState(false);

  const getThreatBadge = (level: InvestigationVerdict['threatLevel']) => {
    switch (level) {
      case 'CRITICAL':
        return <span className="px-2.5 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/40 text-xs font-bold">CRITICAL THREAT</span>;
      case 'HIGH':
        return <span className="px-2.5 py-0.5 rounded-full bg-orange-500/20 text-orange-300 border border-orange-500/40 text-xs font-bold">HIGH THREAT</span>;
      case 'MEDIUM':
        return <span className="px-2.5 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40 text-xs font-bold">MEDIUM THREAT</span>;
      case 'LOW':
      default:
        return <span className="px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-xs font-bold">LOW RISK</span>;
    }
  };

  return (
    <div className="p-4 sm:p-5 rounded-xl bg-[#090d17] border border-slate-700/80 text-xs font-mono space-y-4 my-3 shadow-xl">
      {/* Evidence Center Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-3 flex-wrap gap-2">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
            <Globe2 className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">EVIDENCE CENTER</h3>
              <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                SIMULATED / DEMO DATA INCLUDED
              </span>
            </div>
            <p className="text-[11px] text-slate-400">Target observable: {verdict.target}</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {getThreatBadge(verdict.threatLevel)}
          <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700 text-xs font-semibold">
            {verdict.confidence}% Confidence
          </span>
        </div>
      </div>

      {/* Evidence Table */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between text-[11px] text-slate-400 font-semibold px-1">
          <span>SOURCE & PROVENANCE</span>
          <span>INTELLIGENCE FINDING</span>
        </div>

        <div className="space-y-2">
          {evidence.map(item => (
            <div 
              key={item.id}
              className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 hover:border-slate-700 transition-all space-y-1.5"
            >
              <div className="flex items-center justify-between flex-wrap gap-2 text-[10px]">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-cyan-400 text-xs">{item.source}</span>
                  <span className="text-slate-500">•</span>
                  <span className="text-slate-400">{item.retrievedAt}</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className={`px-1.5 py-0.2 rounded text-[9px] font-semibold border ${
                    item.status === 'Verified' 
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                      : item.status === 'Internal Knowledge'
                      ? 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20'
                      : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                  }`}>
                    {item.status}
                  </span>
                </div>
              </div>

              <p className="text-slate-200 text-xs font-semibold">{item.result}</p>
              {item.details && (
                <p className="text-slate-400 text-[11px] leading-relaxed">{item.details}</p>
              )}

              {/* If RAG Chunk, show document source and similarity */}
              {item.ragMeta && (
                <div className="mt-1.5 p-2 rounded bg-cyan-950/30 border border-cyan-500/20 text-[11px] text-cyan-200 space-y-1">
                  <div className="flex items-center justify-between text-[10px] text-cyan-300">
                    <span>Document: {item.ragMeta.document} (Page {item.ragMeta.page})</span>
                    <span className="text-emerald-400 font-semibold">{item.ragMeta.similarity}</span>
                  </div>
                  <p className="italic text-slate-300">"{item.ragMeta.retrievedChunk}"</p>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* CIPHER ASSESSMENT METRIC BOX */}
      <div className="p-3.5 rounded-xl bg-gradient-to-r from-slate-900 to-[#0c1424] border border-cyan-500/30 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div>
          <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider block">CIPHER ASSESSMENT</span>
          <div className="flex items-center gap-3 mt-1">
            <span className="text-sm font-bold text-slate-100">
              Threat Level: <span className="text-rose-400">{verdict.threatLevel}</span>
            </span>
            <span className="text-slate-600">|</span>
            <span className="text-sm font-bold text-slate-100">
              Confidence: <span className="text-cyan-400">{verdict.confidence}%</span>
            </span>
            <span className="text-slate-600">|</span>
            <span className="text-sm text-slate-300">
              Evidence Sources: <strong className="text-white">{evidence.length}</strong>
            </span>
          </div>
        </div>

        <div className="text-[10px] text-slate-400 italic text-right max-w-xs hidden sm:block">
          Severity reflects observed risk profile. Confidence reflects evidentiary corroboration.
        </div>
      </div>

      {/* "WHY THIS VERDICT?" EXPANDABLE SECTION (Directive 8) */}
      <div className="border border-slate-800 rounded-lg overflow-hidden">
        <button
          type="button"
          onClick={() => setShowWhyVerdict(!showWhyVerdict)}
          className="w-full p-2.5 bg-slate-900/80 hover:bg-slate-800/80 flex items-center justify-between text-slate-300 text-xs font-semibold transition-colors"
        >
          <div className="flex items-center gap-2">
            <Bot className="w-3.5 h-3.5 text-cyan-400" />
            <span>WHY THIS VERDICT? (Explainable Threat Reasoning)</span>
          </div>
          {showWhyVerdict ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
        </button>

        {showWhyVerdict && (
          <div className="p-3.5 bg-slate-950 space-y-3 text-[11px]">
            <div>
              <span className="text-rose-400 font-bold block mb-1">Key Risk Factors:</span>
              <ul className="list-disc pl-4 space-y-1 text-slate-300">
                {verdict.riskFactors.map((rf, i) => (
                  <li key={i}>{rf}</li>
                ))}
              </ul>
            </div>
            <div>
              <span className="text-cyan-400 font-bold block mb-1">Evidentiary Confidence Factors:</span>
              <ul className="list-disc pl-4 space-y-1 text-slate-300">
                {verdict.confidenceFactors.map((cf, i) => (
                  <li key={i}>{cf}</li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </div>

      {/* INVESTIGATION TIMELINE (Directive 9) */}
      <div className="border border-slate-800 rounded-lg overflow-hidden">
        <button
          type="button"
          onClick={() => setShowTimeline(!showTimeline)}
          className="w-full p-2.5 bg-slate-900/80 hover:bg-slate-800/80 flex items-center justify-between text-slate-300 text-xs font-semibold transition-colors"
        >
          <div className="flex items-center gap-2">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span>INVESTIGATION TIMELINE ({verdict.timeline.length} Steps Executed)</span>
          </div>
          {showTimeline ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
        </button>

        {showTimeline && (
          <div className="p-3.5 bg-slate-950 space-y-2 text-[11px]">
            {verdict.timeline.map((step, idx) => (
              <div key={idx} className="flex items-center justify-between py-1 border-b border-slate-900 last:border-0">
                <div className="flex items-center gap-2.5">
                  <span className="text-slate-500 font-mono text-[10px]">{step.time}</span>
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  <span className="text-slate-200">{step.step}</span>
                </div>
                {step.provenance && (
                  <span className="text-[9px] px-1.5 py-0.2 rounded bg-slate-900 text-slate-400 border border-slate-800">
                    {step.provenance}
                  </span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* INVESTIGATION COMPLETION ACTIONS (Directive 13) */}
      <div className="pt-2 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2">
        <span className="text-slate-500 text-[11px]">Investigation Complete</span>
        <div className="flex items-center gap-2 flex-wrap">
          <button
            type="button"
            onClick={() => onAskFollowup(`Analyze IOCs related to ${verdict.target} and cross-check against internal incident playbooks.`)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-200 flex items-center gap-1.5 transition-colors"
          >
            <Bot className="w-3.5 h-3.5 text-cyan-400" />
            <span>Ask CIPHER</span>
          </button>
          <button
            type="button"
            onClick={() => onSaveIoc(verdict.target)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-200 flex items-center gap-1.5 transition-colors"
          >
            <Save className="w-3.5 h-3.5 text-emerald-400" />
            <span>Save IOC</span>
          </button>
          <button
            type="button"
            onClick={() => onSaveCase(verdict)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-200 flex items-center gap-1.5 transition-colors"
          >
            <FileCode className="w-3.5 h-3.5 text-amber-400" />
            <span>Save Investigation</span>
          </button>
          <button
            type="button"
            onClick={() => onGenerateReport(verdict.target)}
            className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold flex items-center gap-1.5 transition-all shadow-md"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Generate Report</span>
          </button>
        </div>
      </div>
    </div>
  );
};

/**
 * 4. DETECTED INDICATORS CARD (Directive 12)
 * When text is parsed, displays detected indicators with [Investigate] and [Save IOC]
 */
interface DetectedIndicatorsCardProps {
  indicators: ExtractedIndicator[];
  onInvestigate: (ind: ExtractedIndicator) => void;
  onSaveIoc: (ind: ExtractedIndicator) => void;
}

export const DetectedIndicatorsCard: React.FC<DetectedIndicatorsCardProps> = ({
  indicators,
  onInvestigate,
  onSaveIoc
}) => {
  if (indicators.length === 0) return null;

  return (
    <div className="p-3 rounded-xl bg-[#0a0f1d] border border-cyan-500/30 text-xs font-mono space-y-2 my-2">
      <div className="flex items-center justify-between border-b border-slate-800 pb-1.5">
        <span className="text-cyan-400 font-bold uppercase text-[11px]">
          DETECTED INDICATORS ({indicators.length})
        </span>
        <span className="text-[10px] text-slate-500">Auto-extracted from input stream</span>
      </div>

      <div className="space-y-1.5">
        {indicators.map((ind, idx) => (
          <div key={idx} className="flex items-center justify-between p-2 rounded bg-slate-950/70 border border-slate-800/80 flex-wrap gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <span className="text-[9px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700 uppercase">
                {ind.type}
              </span>
              <span className="text-slate-200 font-mono truncate">{ind.value}</span>
            </div>

            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={() => onSaveIoc(ind)}
                className="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 text-[10px] border border-slate-800 hover:border-slate-700 transition-colors"
              >
                Save IOC
              </button>
              <button
                type="button"
                onClick={() => onInvestigate(ind)}
                className="px-2.5 py-1 rounded bg-cyan-600/30 hover:bg-cyan-600/50 text-cyan-300 text-[10px] font-semibold border border-cyan-500/40 transition-colors"
              >
                Investigate
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
