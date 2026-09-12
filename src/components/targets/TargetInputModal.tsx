import React, { useState } from 'react';
import { 
  Globe2, 
  Server, 
  Crosshair, 
  ShieldAlert, 
  Sparkles, 
  Layers, 
  Plus, 
  Check, 
  X, 
  Zap, 
  Terminal,
  Activity,
  AlertTriangle,
  FileText
} from 'lucide-react';
import { SecurityTarget } from '../../types';
import { validateTarget, normalizeTargetValue } from '../../utils/detector';

interface TargetInputModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAddTarget: (target: SecurityTarget) => void;
  onAddBulkTargets: (targets: SecurityTarget[]) => void;
  currentUser: string;
  existingTargets?: SecurityTarget[];
}

export const TargetInputModal: React.FC<TargetInputModalProps> = ({
  isOpen,
  onClose,
  onAddTarget,
  onAddBulkTargets,
  currentUser,
  existingTargets = []
}) => {
  const [activeTab, setActiveTab] = useState<'single' | 'bulk'>('single');

  // Single Target Form State
  const [targetValue, setTargetValue] = useState('');
  const [targetType, setTargetType] = useState<SecurityTarget['type']>('ipv4');
  const [label, setLabel] = useState('');
  const [environment, setEnvironment] = useState<SecurityTarget['environment']>('external_threat');
  const [priority, setPriority] = useState<SecurityTarget['priority']>('high');
  const [portsInput, setPortsInput] = useState('80, 443, 8080');
  const [tagsInput, setTagsInput] = useState('Zero-Trust, Perimeter');
  const [notes, setNotes] = useState('');
  const [autoEnrich, setAutoEnrich] = useState(true);
  const [validationWarning, setValidationWarning] = useState<string | null>(null);

  // Normalized value and duplicate detection
  const normalizedObj = normalizeTargetValue(targetValue);
  const normalizedValue = normalizedObj.normalized;
  const duplicateTarget = existingTargets.find(
    t => t.value.toLowerCase() === normalizedValue.toLowerCase() || t.value.toLowerCase() === targetValue.trim().toLowerCase()
  );

  // Bulk Ingestion State
  const [bulkText, setBulkText] = useState('');
  const [bulkDefaultEnv, setBulkDefaultEnv] = useState<SecurityTarget['environment']>('external_threat');
  const [bulkDefaultPriority, setBulkDefaultPriority] = useState<SecurityTarget['priority']>('high');

  if (!isOpen) return null;

  // Auto detect type as user types IP or Domain
  const handleValueChange = (val: string) => {
    setTargetValue(val);
    const trimmed = val.trim();
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(trimmed)) {
      setTargetType('cidr');
    } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(trimmed)) {
      setTargetType('ipv4');
    } else if (trimmed.startsWith('http://') || trimmed.startsWith('https://') || trimmed.startsWith('hxxp')) {
      setTargetType('url');
    } else if (trimmed.includes('.') && !trimmed.includes(' ')) {
      setTargetType('domain');
    } else if (trimmed.length > 0) {
      setTargetType('hostname');
    }
  };

  const handleApplyPreset = (ip: string, name: string, type: SecurityTarget['type']) => {
    setTargetValue(ip);
    setTargetType(type);
    setLabel(name);
  };

  const handleSingleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetValue.trim()) return;

    // Parse ports
    const parsedPorts = portsInput
      .split(',')
      .map(p => parseInt(p.trim(), 10))
      .filter(p => !isNaN(p));

    // Parse tags
    const parsedTags = tagsInput
      .split(',')
      .map(t => t.trim())
      .filter(t => t.length > 0);

    // Compute synthetic enrichment based on value
    let calculatedScore = 75;
    let computedVerdict: SecurityTarget['verdict'] = 'suspicious';
    let computedCountry = 'United States';
    let computedCity = 'Ashburn DataCenter';
    let computedAsn = 'AS14618 (Amazon.com)';

    if (targetValue.includes('185.220') || targetValue.includes('194.26') || targetValue.includes('c2') || targetValue.includes('tor')) {
      calculatedScore = 92;
      computedVerdict = 'malicious';
      computedCountry = 'Germany';
      computedCity = 'Frankfurt am Main';
      computedAsn = 'AS206238 (Zwiebelfreunde e.V.)';
    } else if (targetValue.startsWith('10.') || targetValue.startsWith('192.168') || targetValue.startsWith('172.16')) {
      calculatedScore = 40;
      computedVerdict = environment === 'production' ? 'suspicious' : 'benign';
      computedCountry = 'Internal Enterprise';
      computedCity = 'VPC Mesh';
      computedAsn = 'Private RFC-1918';
    }

    const validation = validateTarget(targetValue.trim(), targetType);
    if (!validation.isValid && validation.message) {
      setValidationWarning(validation.message);
    } else {
      setValidationWarning(null);
    }

    const cleanValue = normalizeTargetValue(targetValue.trim()).normalized;

    const newTarget: SecurityTarget = {
      id: `tgt-${Date.now()}`,
      value: cleanValue,
      type: targetType,
      label: label.trim() || cleanValue,
      environment: environment,
      priority: priority,
      threatScore: calculatedScore,
      verdict: computedVerdict,
      riskLevel: calculatedScore > 85 ? 'CRITICAL' : calculatedScore > 65 ? 'HIGH' : calculatedScore > 40 ? 'MEDIUM' : 'LOW',
      confidence: 88,
      status: 'QUEUED',
      owner: currentUser,
      validationStatus: validation.isValid ? 'valid' : 'invalid',
      investigationType: 'PASSIVE INTELLIGENCE',
      asn: computedAsn,
      country: computedCountry,
      city: computedCity,
      openPorts: parsedPorts.length > 0 ? parsedPorts : [80, 443],
      tags: parsedTags.length > 0 ? parsedTags : ['Custom-Target', 'Analyst-Ingest'],
      notes: notes.trim() || `Ingested by ${currentUser} into active investigation scope.`,
      addedBy: currentUser,
      addedAt: 'Just now',
      lastScannedAt: 'Just now',
      associatedIncidents: ['INC-8941'],
      firstSeen: new Date().toISOString()
    };

    onAddTarget(newTarget);
    onClose();
  };

  const handleBulkSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const lines = bulkText.split('\n').map(l => l.trim()).filter(l => l.length > 0 && !l.startsWith('#'));
    if (lines.length === 0) return;

    const parsedTargets: SecurityTarget[] = lines.map((line, idx) => {
      let type: SecurityTarget['type'] = 'ipv4';
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(line)) {
        type = 'cidr';
      } else if (line.includes('.') && !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(line)) {
        type = 'domain';
      }

      return {
        id: `tgt-bulk-${Date.now()}-${idx}`,
        value: line,
        type: type,
        label: `Bulk Ingest: ${line}`,
        environment: bulkDefaultEnv,
        priority: bulkDefaultPriority,
        threatScore: Math.floor(55 + Math.random() * 35),
        verdict: 'suspicious',
        asn: 'Autonomous Recon In-Progress',
        country: 'Global Relay',
        openPorts: [80, 443],
        tags: ['Bulk-Ingested', 'Auto-Scan'],
        addedBy: currentUser,
        addedAt: 'Just now',
        lastScannedAt: 'Pending Initial Scan'
      };
    });

    onAddBulkTargets(parsedTargets);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-md flex items-center justify-center p-4">
      <div className="w-full max-w-2xl bg-[#090d15] border border-slate-700/80 rounded-2xl shadow-2xl overflow-hidden font-mono text-xs animate-in fade-in zoom-in-95 duration-200 flex flex-col max-h-[90vh]">
        
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-800 bg-[#0c111c] flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.2)]">
              <Crosshair className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
                  Target Scope & IP Ingestion Engine
                </h2>
                <span className="text-[9px] px-1.5 py-0.2 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
                  REAL-TIME ENRICHMENT
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-sans mt-0.5">
                Input custom IPs, CIDR ranges, domains, or infrastructure assets for autonomous investigation
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Tab Switcher */}
        <div className="flex border-b border-slate-800 bg-slate-950/60 p-1.5 text-xs shrink-0">
          <button
            onClick={() => setActiveTab('single')}
            className={`flex-1 py-2 rounded-lg font-semibold flex items-center justify-center gap-2 transition-all ${
              activeTab === 'single'
                ? 'bg-slate-900 text-cyan-300 border border-slate-700/80 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Crosshair className="w-3.5 h-3.5" />
            <span>Single Target IP / Asset Input</span>
          </button>
          <button
            onClick={() => setActiveTab('bulk')}
            className={`flex-1 py-2 rounded-lg font-semibold flex items-center justify-center gap-2 transition-all ${
              activeTab === 'bulk'
                ? 'bg-slate-900 text-cyan-300 border border-slate-700/80 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Bulk Ingest (Multi-IP List)</span>
          </button>
        </div>

        {/* Modal Scrollable Body */}
        <div className="p-6 overflow-y-auto flex-1 space-y-5">
          {activeTab === 'single' ? (
            /* ================= SINGLE TARGET MODE ================= */
            <form onSubmit={handleSingleSubmit} className="space-y-4">
              {/* Quick Sample Presets */}
              <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/90 space-y-2">
                <div className="flex items-center justify-between text-[10px] text-slate-400 uppercase">
                  <span>Quick Test Targets (Click to Fill)</span>
                  <span className="text-cyan-400">Threat Presets</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => handleApplyPreset('185.220.101.5', 'Frankfurt Cobalt C2', 'ipv4')}
                    className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/40 text-slate-300 text-[11px] transition-colors"
                  >
                    185.220.101.5 (Tor C2)
                  </button>
                  <button
                    type="button"
                    onClick={() => handleApplyPreset('194.26.29.114', 'Mirai Vulnerability Scanner', 'ipv4')}
                    className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/40 text-slate-300 text-[11px] transition-colors"
                  >
                    194.26.29.114 (Scanner)
                  </button>
                  <button
                    type="button"
                    onClick={() => handleApplyPreset('10.240.12.89', 'PROD-K8S-WORKER-09', 'ipv4')}
                    className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/40 text-slate-300 text-[11px] transition-colors"
                  >
                    10.240.12.89 (K8s Node)
                  </button>
                  <button
                    type="button"
                    onClick={() => handleApplyPreset('c2.threat-beacon.net', 'Dynamic DNS C2', 'domain')}
                    className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/40 text-slate-300 text-[11px] transition-colors"
                  >
                    c2.threat-beacon.net
                  </button>
                </div>
              </div>

              {/* Target Value & Detected Type */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-[11px]">
                  <label className="text-slate-300 font-medium">
                    Target Value (IP, CIDR, FQDN, or Hostname) *
                  </label>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-500/40 font-bold uppercase">
                    Detected: {targetType}
                  </span>
                </div>
                <div className="relative">
                  <Globe2 className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
                  <input
                    type="text"
                    required
                    value={targetValue}
                    onChange={(e) => handleValueChange(e.target.value)}
                    placeholder="e.g. 185.220.101.5 or 10.240.0.0/16 or c2-gateway.org"
                    className={`w-full bg-slate-950 border rounded-xl pl-9 pr-3 py-2 text-slate-200 placeholder:text-slate-600 focus:outline-none font-mono text-xs ${
                      duplicateTarget 
                        ? 'border-amber-500/80 focus:border-amber-400' 
                        : 'border-slate-800 focus:border-cyan-500'
                    }`}
                  />
                </div>

                {/* Duplicate Detection Alert (Directive 2) */}
                {duplicateTarget && (
                  <div className="p-2.5 rounded-lg bg-amber-950/30 border border-amber-500/40 text-amber-300 text-[11px] flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                      <span>
                        Target <strong>{duplicateTarget.value}</strong> already exists in inventory ({duplicateTarget.label}).
                      </span>
                    </div>
                    <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-200 font-bold uppercase">
                      DUPLICATE
                    </span>
                  </div>
                )}

                {validationWarning && (
                  <div className="p-2 rounded-lg bg-rose-950/30 border border-rose-500/40 text-rose-300 text-[11px] flex items-center gap-2">
                    <AlertTriangle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                    <span>{validationWarning}</span>
                  </div>
                )}
              </div>

              {/* Alias Label & Environment */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1 text-[11px]">
                    Target Scope Label / Alias
                  </label>
                  <input
                    type="text"
                    value={label}
                    onChange={(e) => setLabel(e.target.value)}
                    placeholder="e.g. Frankfurt Tor Exit Node"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 text-[11px]">
                    Environment Classification
                  </label>
                  <select
                    value={environment}
                    onChange={(e) => setEnvironment(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                  >
                    <option value="external_threat">External Threat / Adversary C2</option>
                    <option value="production">Production Workload / Core Node</option>
                    <option value="dmz">Perimeter DMZ / Edge Gateway</option>
                    <option value="internal_mesh">Internal Mesh / Corporate Network</option>
                    <option value="staging">Staging / Development Sandbox</option>
                  </select>
                </div>
              </div>

              {/* Priority & Open Ports */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1 text-[11px]">
                    Investigation Priority
                  </label>
                  <select
                    value={priority}
                    onChange={(e) => setPriority(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-rose-300 font-bold focus:outline-none focus:border-cyan-500 font-mono text-xs"
                  >
                    <option value="critical">Critical (Real-time eBPF & Drop)</option>
                    <option value="high">High (Active Correlation)</option>
                    <option value="medium">Medium (Standard Monitoring)</option>
                    <option value="low">Low (Passive Telemetry)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 text-[11px]">
                    Observed Open Ports (Comma separated)
                  </label>
                  <input
                    type="text"
                    value={portsInput}
                    onChange={(e) => setPortsInput(e.target.value)}
                    placeholder="e.g. 22, 80, 443, 8080"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                  />
                </div>
              </div>

              {/* Tags & Context Notes */}
              <div>
                <label className="block text-slate-400 mb-1 text-[11px]">
                  Threat Tags
                </label>
                <input
                  type="text"
                  value={tagsInput}
                  onChange={(e) => setTagsInput(e.target.value)}
                  placeholder="e.g. Cobalt Strike, Tor, C2, APT29"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 text-[11px]">
                  Analyst Context Notes
                </label>
                <textarea
                  rows={2}
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Provide context on why this IP/target is being tracked..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 font-mono text-xs resize-none"
                />
              </div>

              {/* Auto Enrichment Toggle */}
              <div className="p-3 rounded-xl bg-cyan-950/30 border border-cyan-500/30 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Zap className="w-4 h-4 text-cyan-400" />
                  <div>
                    <div className="text-slate-200 font-semibold text-xs">Run Autonomous Telemetry Synthesis</div>
                    <div className="text-[10px] text-slate-400">Trigger simulated Shodan port sweep, AbuseIPDB lookup, and risk verdict</div>
                  </div>
                </div>
                <input
                  type="checkbox"
                  checked={autoEnrich}
                  onChange={(e) => setAutoEnrich(e.target.checked)}
                  className="rounded border-slate-700 text-cyan-500 focus:ring-0 w-4 h-4 cursor-pointer"
                />
              </div>

              <div className="pt-2 flex items-center justify-end gap-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold flex items-center gap-1.5 transition-colors shadow-lg"
                >
                  <Plus className="w-4 h-4" />
                  <span>Ingest Target & Set Active Scope</span>
                </button>
              </div>
            </form>
          ) : (
            /* ================= BULK INGESTION MODE ================= */
            <form onSubmit={handleBulkSubmit} className="space-y-4">
              <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/90 text-slate-300 text-xs font-sans leading-relaxed">
                Paste one target per line (IP addresses, CIDRs, or domains). Lines starting with <code className="text-cyan-400 font-mono">#</code> are ignored.
              </div>

              <div>
                <label className="block text-slate-400 mb-1 text-[11px]">
                  Multi-Line Target List
                </label>
                <textarea
                  rows={7}
                  value={bulkText}
                  onChange={(e) => setBulkText(e.target.value)}
                  placeholder={`185.220.101.5\n194.26.29.114\nupdate-svc-catalog.azure-edge-sync.net\n10.240.12.89\n45.154.255.89`}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 font-mono text-xs leading-relaxed"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1 text-[11px]">
                    Default Ingest Environment
                  </label>
                  <select
                    value={bulkDefaultEnv}
                    onChange={(e) => setBulkDefaultEnv(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                  >
                    <option value="external_threat">External Threat / Adversary C2</option>
                    <option value="production">Production Workload</option>
                    <option value="dmz">Perimeter DMZ</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 text-[11px]">
                    Default Priority
                  </label>
                  <select
                    value={bulkDefaultPriority}
                    onChange={(e) => setBulkDefaultPriority(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-amber-300 font-bold focus:outline-none focus:border-cyan-500 font-mono text-xs"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                  </select>
                </div>
              </div>

              <div className="pt-2 flex items-center justify-end gap-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!bulkText.trim()}
                  className="px-5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white font-semibold flex items-center gap-1.5 transition-colors shadow-lg"
                >
                  <Layers className="w-4 h-4" />
                  <span>Parse & Ingest All Targets</span>
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};
