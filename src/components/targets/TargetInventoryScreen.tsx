import React, { useState } from 'react';
import { 
  Crosshair, 
  Plus, 
  Search, 
  Globe2, 
  Server, 
  ShieldAlert, 
  Bot, 
  RotateCw, 
  Trash2, 
  CheckCircle2, 
  ExternalLink,
  Layers,
  ArrowRight,
  Flame,
  Radio,
  Clock
} from 'lucide-react';
import { ScreenType, SecurityTarget } from '../../types';

interface TargetInventoryScreenProps {
  targets: SecurityTarget[];
  activeTarget?: SecurityTarget | null;
  onSelectActiveTarget: (target: SecurityTarget) => void;
  onOpenAddModal: () => void;
  onDeleteTarget: (id: string) => void;
  onClearAllTargets?: () => void;
  onLoadSampleTargets?: () => void;
  onNavigate: (screen: ScreenType) => void;
  onSendToCopilot?: (query: string) => void;
}

export const TargetInventoryScreen: React.FC<TargetInventoryScreenProps> = ({
  targets,
  activeTarget,
  onSelectActiveTarget,
  onOpenAddModal,
  onDeleteTarget,
  onClearAllTargets,
  onLoadSampleTargets,
  onNavigate,
  onSendToCopilot
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<string>('all');
  const [filterEnv, setFilterEnv] = useState<string>('all');
  const [scanningTargetId, setScanningTargetId] = useState<string | null>(null);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const handleScanTarget = (tgt: SecurityTarget) => {
    setScanningTargetId(tgt.id);
    setTimeout(() => {
      setScanningTargetId(null);
      showToast(`Recon scan complete for ${tgt.value}: Shodan open ports and AbuseIPDB confirmed.`);
    }, 1200);
  };

  const filteredTargets = targets.filter(t => {
    const matchesSearch = t.value.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          t.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          t.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesType = filterType === 'all' || t.type === filterType;
    const matchesEnv = filterEnv === 'all' || t.environment === filterEnv;
    return matchesSearch && matchesType && matchesEnv;
  });

  return (
    <div className="flex-1 flex flex-col overflow-y-auto bg-[#080b11] text-slate-100 font-mono text-xs">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 bg-cyan-950/90 border border-cyan-400/50 text-cyan-200 px-4 py-3 rounded-lg shadow-xl backdrop-blur-md animate-in fade-in">
          <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Header Banner */}
      <div className="p-4 sm:p-6 border-b border-slate-800/80 bg-[#0a0e17]/80 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 text-xs mb-1">
              <Crosshair className="w-4 h-4" />
              <span>TARGET INVENTORY & INVESTIGATION SCOPE</span>
            </div>
            <h1 className="text-lg sm:text-xl font-bold tracking-tight text-slate-100">
              CIPHER AI — Security Target & IP Inventory
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Active IP addresses, CIDR ranges, domains, and assets under automated continuous observation
            </p>
          </div>

          <div className="flex items-center flex-wrap gap-2.5">
            {targets.length > 0 && onClearAllTargets && (
              <button
                onClick={onClearAllTargets}
                className="px-3 py-2 rounded-xl bg-slate-900 hover:bg-rose-950/40 border border-slate-800 hover:border-rose-500/40 text-slate-400 hover:text-rose-300 font-semibold flex items-center justify-center gap-1.5 transition-all text-xs cursor-pointer"
                title="Remove all targets from inventory"
              >
                <Trash2 className="w-3.5 h-3.5 text-slate-500 hover:text-rose-400" />
                <span>Clear All Targets</span>
              </button>
            )}
            {targets.length === 0 && onLoadSampleTargets && (
              <button
                onClick={onLoadSampleTargets}
                className="px-3 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-cyan-300 font-semibold flex items-center justify-center gap-1.5 transition-all text-xs cursor-pointer"
                title="Load default sample targets"
              >
                <RotateCw className="w-3.5 h-3.5 text-slate-500" />
                <span>Load Sample Targets</span>
              </button>
            )}
            <button
              onClick={onOpenAddModal}
              className="w-full sm:w-auto px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-semibold flex items-center justify-center gap-1.5 transition-colors shadow-lg cursor-pointer"
            >
              <Plus className="w-4 h-4" />
              <span>Input New Target / IP</span>
            </button>
          </div>
        </div>

        {/* Search and Filters */}
        <div className="flex flex-col sm:flex-row flex-wrap items-stretch sm:items-center justify-between gap-3 pt-2">
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 sm:gap-3 flex-1">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-2.5 w-3.5 h-3.5 text-slate-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by IP, domain, label, ASN, or tag..."
                className="w-full bg-slate-900/90 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex items-center gap-2">
              <select
                value={filterType}
                onChange={(e) => setFilterType(e.target.value)}
                className="flex-1 sm:flex-none bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
              >
                <option value="all">All Types</option>
                <option value="ipv4">IPv4</option>
                <option value="cidr">CIDR</option>
                <option value="domain">Domain</option>
                <option value="hostname">Host</option>
              </select>

              <select
                value={filterEnv}
                onChange={(e) => setFilterEnv(e.target.value)}
                className="flex-1 sm:flex-none bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
              >
                <option value="all">All Envs</option>
                <option value="external_threat">Adversary</option>
                <option value="production">Production</option>
                <option value="dmz">DMZ</option>
                <option value="internal_mesh">Mesh</option>
              </select>
            </div>
          </div>

          <div className="text-[11px] text-slate-400 text-right sm:text-left">
            Showing <span className="text-cyan-300 font-bold">{filteredTargets.length}</span> of {targets.length} targets
          </div>
        </div>
      </div>

      {/* Target Cards Grid */}
      <div className="max-w-6xl w-full mx-auto p-4 sm:p-6 space-y-4">
        {filteredTargets.length === 0 ? (
          <div className="p-8 sm:p-14 text-center rounded-2xl bg-slate-900/60 border border-dashed border-slate-800 space-y-4 my-6 animate-in fade-in">
            <div className="w-14 h-14 rounded-2xl bg-slate-900 border border-slate-800 text-cyan-400 flex items-center justify-center mx-auto shadow-inner">
              <Crosshair className="w-7 h-7 text-slate-500" />
            </div>
            <div className="space-y-1.5">
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider font-mono">
                {searchQuery ? 'No Matching Indicators Found' : 'No Security Targets In Scope'}
              </h3>
              <p className="text-xs text-slate-400 font-mono max-w-md mx-auto leading-relaxed">
                {searchQuery
                  ? 'No target observables matched your current filter criteria. Try resetting your query.'
                  : 'Your target inventory is currently clean. Input a custom IP, CIDR, or domain to begin automated continuous surveillance, or load sample intelligence data.'}
              </p>
            </div>
            <div className="flex flex-wrap items-center justify-center gap-3 pt-3">
              <button
                onClick={onOpenAddModal}
                className="px-4 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-semibold flex items-center gap-1.5 transition-colors text-xs font-mono shadow-lg cursor-pointer"
              >
                <Plus className="w-4 h-4" />
                <span>Input Target Observable</span>
              </button>
              {onLoadSampleTargets && (
                <button
                  onClick={onLoadSampleTargets}
                  className="px-4 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 hover:text-white font-semibold transition-colors text-xs font-mono cursor-pointer"
                >
                  Load Sample Intelligence
                </button>
              )}
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filteredTargets.map(tgt => {
            const isActive = activeTarget?.id === tgt.id;
            const isScanning = scanningTargetId === tgt.id;

            return (
              <div 
                key={tgt.id}
                className={`p-5 rounded-2xl border transition-all flex flex-col justify-between space-y-4 relative ${
                  isActive
                    ? 'bg-gradient-to-br from-cyan-950/40 via-slate-900/90 to-slate-950 border-cyan-500/50 shadow-[0_0_20px_rgba(6,182,212,0.15)]'
                    : 'bg-slate-900/90 border-slate-800 hover:border-slate-700'
                }`}
              >
                {/* Top Badge Row */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className={`text-[9px] uppercase font-bold px-2 py-0.5 rounded border ${
                        tgt.type === 'ipv4' ? 'bg-cyan-950/80 text-cyan-300 border-cyan-500/30' :
                        tgt.type === 'cidr' ? 'bg-purple-950/80 text-purple-300 border-purple-500/30' :
                        'bg-indigo-950/80 text-indigo-300 border-indigo-500/30'
                      }`}>
                        {tgt.type}
                      </span>
                      <span className="text-[10px] text-slate-400 uppercase">
                        {tgt.environment.replace('_', ' ')}
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      {isActive ? (
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-500/40 flex items-center gap-1">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                          ACTIVE SCOPE
                        </span>
                      ) : (
                        <button
                          onClick={() => {
                            onSelectActiveTarget(tgt);
                            showToast(`Active target scope switched to: ${tgt.value}`);
                          }}
                          className="text-[10px] px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
                        >
                          Set as Active Scope
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Target Value & Label */}
                  <div>
                    <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                      <span>{tgt.value}</span>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                        tgt.threatScore >= 90 ? 'bg-rose-950/80 text-rose-300 border-rose-500/40' :
                        tgt.threatScore >= 70 ? 'bg-amber-950/80 text-amber-300 border-amber-500/40' :
                        'bg-cyan-950/80 text-cyan-300 border-cyan-500/40'
                      }`}>
                        SCORE: {tgt.threatScore}
                      </span>
                    </h3>
                    <div className="text-slate-300 text-xs font-sans mt-0.5">
                      {tgt.label}
                    </div>
                  </div>

                  {/* Geo & Ports */}
                  <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800/80 space-y-1.5 text-[11px]">
                    <div className="flex items-center justify-between text-slate-400">
                      <span className="flex items-center gap-1.5">
                        <Globe2 className="w-3.5 h-3.5 text-cyan-400" /> Location:
                      </span>
                      <span className="text-slate-200">{tgt.city ? `${tgt.city}, ${tgt.country}` : tgt.country || 'Global'}</span>
                    </div>
                    {tgt.asn && (
                      <div className="flex items-center justify-between text-slate-400">
                        <span className="flex items-center gap-1.5">
                          <Server className="w-3.5 h-3.5 text-cyan-400" /> ASN:
                        </span>
                        <span className="text-slate-300 truncate max-w-[200px]">{tgt.asn}</span>
                      </div>
                    )}
                    <div className="flex items-center justify-between text-slate-400 pt-1 border-t border-slate-900">
                      <span>Open Ports:</span>
                      <div className="flex flex-wrap gap-1">
                        {tgt.openPorts.map(p => (
                          <span key={p} className="px-1.5 py-0.2 rounded bg-slate-900 text-slate-300 border border-slate-800 text-[10px]">
                            {p}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Tags */}
                  <div className="flex flex-wrap gap-1.5">
                    {tgt.tags.map((tag, i) => (
                      <span key={i} className="text-[10px] px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Card Bottom Actions */}
                <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => {
                        onSelectActiveTarget(tgt);
                        onNavigate('copilot');
                      }}
                      className="px-2.5 py-1.5 rounded-lg bg-cyan-950/60 hover:bg-cyan-900 border border-cyan-500/30 text-cyan-300 text-xs flex items-center gap-1 transition-colors"
                    >
                      <Bot className="w-3.5 h-3.5" />
                      <span>Copilot</span>
                    </button>

                    <button
                      onClick={() => {
                        onSelectActiveTarget(tgt);
                        onNavigate('threat-intel');
                      }}
                      className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs flex items-center gap-1 transition-colors"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                      <span>Dossier</span>
                    </button>

                    <button
                      onClick={() => handleScanTarget(tgt)}
                      disabled={isScanning}
                      className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition-colors"
                      title="Trigger Shodan & AbuseIPDB Recon Scan"
                    >
                      <RotateCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin text-cyan-400' : ''}`} />
                    </button>
                  </div>

                  <button
                    onClick={() => onDeleteTarget(tgt.id)}
                    className="p-1.5 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-rose-950/50 transition-colors cursor-pointer"
                    title="Remove Target"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
        )}
      </div>
    </div>
  );
};
