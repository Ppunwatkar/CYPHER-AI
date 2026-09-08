import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Search, 
  Filter, 
  Plus, 
  Download, 
  ExternalLink, 
  Bot, 
  Flame, 
  Check, 
  Copy, 
  ShieldAlert, 
  Globe2, 
  Server, 
  Terminal, 
  Database,
  ArrowUpDown,
  Tag,
  CheckCircle2,
  X,
  AlertCircle
} from 'lucide-react';
import { ScreenType, IOCItem } from '../../types';
import { INITIAL_IOC_LIST } from '../../data/mockData';

interface IOCManagerScreenProps {
  onNavigate: (screen: ScreenType) => void;
  onSendToCopilot?: (query: string) => void;
}

export const IOCManagerScreen: React.FC<IOCManagerScreenProps> = ({ onNavigate, onSendToCopilot }) => {
  const [iocList, setIocList] = useState<IOCItem[]>(INITIAL_IOC_LIST);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedIOC, setSelectedIOC] = useState<IOCItem>(INITIAL_IOC_LIST[0]);
  const [selectedRows, setSelectedRows] = useState<string[]>([INITIAL_IOC_LIST[0].id]);
  const [ruleTab, setRuleTab] = useState<'suricata' | 'iptables' | 'paloalto' | 'snort'>('paloalto');
  const [copiedCode, setCopiedCode] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [isMobileDrawerOpen, setIsMobileDrawerOpen] = useState(false);

  // New IOC Modal
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [newVal, setNewVal] = useState('');
  const [newType, setNewType] = useState<'ipv4' | 'domain' | 'sha256' | 'url' | 'cve'>('ipv4');
  const [newThreat, setNewThreat] = useState('');
  const [newSeverity, setNewSeverity] = useState<'critical' | 'high' | 'medium' | 'low'>('high');

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const filteredIOCs = iocList.filter(item => {
    const matchesSearch = item.value.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          item.threatType.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          item.tags.some(t => t.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesType = selectedType === 'all' || item.type === selectedType;
    const matchesSeverity = selectedSeverity === 'all' || item.severity === selectedSeverity;
    return matchesSearch && matchesType && matchesSeverity;
  });

  const toggleRowSelect = (id: string) => {
    if (selectedRows.includes(id)) {
      setSelectedRows(selectedRows.filter(r => r !== id));
    } else {
      setSelectedRows([...selectedRows, id]);
    }
  };

  const toggleSelectAll = () => {
    if (selectedRows.length === filteredIOCs.length) {
      setSelectedRows([]);
    } else {
      setSelectedRows(filteredIOCs.map(i => i.id));
    }
  };

  const handleCopyCode = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const handleAddNewIOC = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newVal.trim()) return;

    const newEntry: IOCItem = {
      id: `ioc-${Date.now()}`,
      value: newVal.trim(),
      type: newType,
      threatType: newThreat || 'Suspicious Observable',
      confidence: 85,
      severity: newSeverity,
      firstSeen: 'Just now',
      lastSeen: 'Just now',
      source: 'Analyst Submission (Manual)',
      tags: ['Manual-Ingest', 'Zero-Trust'],
      status: 'investigating',
      maliciousHits: 1,
      totalHits: 1,
      associatedIncidents: ['INC-8941']
    };

    setIocList([newEntry, ...iocList]);
    setSelectedIOC(newEntry);
    setIsAddModalOpen(false);
    setNewVal('');
    setNewThreat('');
    showToast(`Added observable: ${newEntry.value}`);
  };

  const getRuleSnippet = () => {
    const val = selectedIOC?.value || '185.220.101.5';
    switch (ruleTab) {
      case 'paloalto':
        return `# Palo Alto PAN-OS Dynamic Address Group & Security Rule
set address "IOC-${selectedIOC.id}" ip-netmask ${val}/32
set address-group "CIPHER-AUTO-BLOCK" static "IOC-${selectedIOC.id}"
set rulebase security rules "BLOCK-CIPHER-IOCS" from any to any source any destination "CIPHER-AUTO-BLOCK" application any service any action drop log-start yes`;
      case 'suricata':
        return `# Suricata IDS/IPS Drop Signature
drop ip [${val}] any -> $HOME_NET any (msg:"CIPHER AI - Automated C2 Quarantine"; classtype:trojan-activity; sid:992014; rev:1;)
drop ip $HOME_NET any -> [${val}] any (msg:"CIPHER AI - Outbound C2 Beacon Block"; classtype:trojan-activity; sid:992015; rev:1;)`;
      case 'iptables':
        return `# Linux iptables Kernel Drop
iptables -I INPUT -s ${val} -j DROP -m comment --comment "CIPHER-AI-BLOCK-${selectedIOC.id}"
iptables -I FORWARD -s ${val} -j DROP
iptables -I OUTPUT -d ${val} -j DROP`;
      case 'snort':
        return `# Snort 3 Community Rule
reject tcp $HOME_NET any -> [${val}] any (msg:"CIPHER AI C2 Connection Severed"; react:block; sid:390141; rev:1;)`;
    }
  };

  return (
    <div className="flex-1 flex overflow-hidden bg-[#080b11] text-slate-100">
      {/* Toast */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 bg-emerald-950/90 border border-emerald-400/50 text-emerald-200 px-4 py-3 rounded-lg shadow-xl backdrop-blur-md animate-in fade-in font-mono text-xs">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Main Ledger Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-y-auto">
        {/* Header & Stats Banner */}
        <div className="p-6 border-b border-slate-800/80 bg-[#0a0e17]/80 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono mb-1">
                <ShieldCheck className="w-4 h-4" />
                <span>INTELLIGENCE REPOSITORY • STIX 2.1 COMPLIANT</span>
              </div>
              <h1 className="text-xl font-bold tracking-tight text-slate-100 font-mono">
                CIPHER AI — Indicators of Compromise (IOC) Manager
              </h1>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Correlated Threat Ledger aggregating real-time C2 beacons, maldocs, and adversary infrastructure
              </p>
            </div>

            <div className="flex items-center gap-2.5">
              <button
                onClick={() => {
                  showToast('📦 Exported STIX 2.1 bundle (1,482 indicators) to stix2_export.json');
                }}
                className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-xs font-mono flex items-center gap-1.5 transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export STIX 2.1</span>
              </button>

              <button
                onClick={() => setIsAddModalOpen(true)}
                className="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-medium flex items-center gap-1.5 shadow-md transition-colors"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Observable</span>
              </button>
            </div>
          </div>

          {/* Stats Bento Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800">
              <div className="text-[11px] font-mono text-slate-400">Total Observables</div>
              <div className="text-xl font-bold font-mono text-slate-100 mt-1">1,482</div>
              <div className="text-[10px] font-mono text-emerald-400 mt-1 flex items-center gap-1">
                <span>↑ +14.2%</span> <span className="text-slate-500">vs yesterday</span>
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800">
              <div className="text-[11px] font-mono text-slate-400">High Confidence (&gt;90%)</div>
              <div className="text-xl font-bold font-mono text-rose-400 mt-1">894</div>
              <div className="text-[10px] font-mono text-rose-400/80 mt-1">
                Verified malicious C2 & loaders
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800">
              <div className="text-[11px] font-mono text-slate-400">Active C2 Beacons</div>
              <div className="text-xl font-bold font-mono text-amber-400 mt-1">43</div>
              <div className="text-[10px] font-mono text-amber-400/80 mt-1">
                Cobalt Strike & Brute Ratel
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800">
              <div className="text-[11px] font-mono text-slate-400">STIX 2.1 Sync Health</div>
              <div className="text-xl font-bold font-mono text-cyan-400 mt-1">99.4%</div>
              <div className="text-[10px] font-mono text-cyan-400/80 mt-1">
                24 feeds polling every 60s
              </div>
            </div>
          </div>
        </div>

        {/* Filter and Bulk Action Bar */}
        <div className="p-4 border-b border-slate-800/80 bg-[#090d15] flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3 flex-1 min-w-[280px]">
            {/* Search */}
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 w-3.5 h-3.5 text-slate-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter by IP, domain, hash, CVE, actor, or tag..."
                className="w-full bg-slate-900/90 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs font-mono text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            {/* Type selector */}
            <select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All Types</option>
              <option value="ipv4">IPv4</option>
              <option value="domain">Domain</option>
              <option value="sha256">SHA-256</option>
              <option value="url">URL</option>
              <option value="cve">CVE</option>
            </select>

            {/* Severity selector */}
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          {/* Bulk Action Pills */}
          <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
            {/* Mobile / Tablet button to inspect current IOC */}
            <button
              onClick={() => setIsMobileDrawerOpen(true)}
              className="xl:hidden px-2.5 py-1.5 rounded-lg bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-300 text-xs font-mono flex items-center gap-1.5 transition-colors"
              title="Inspect observable telemetry in slide-over drawer"
            >
              <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
              <span>Inspect ({selectedIOC?.value?.slice(0, 14)}...)</span>
            </button>

            {selectedRows.length > 0 && (
              <>
                <span className="text-slate-400 text-[11px]">
                  {selectedRows.length} selected
                </span>
                <button
                  onClick={() => showToast(`🛡️ Pushed ${selectedRows.length} indicators to CrowdStrike Falcon EDR Blocklist`)}
                  className="px-2.5 py-1 rounded bg-rose-950/80 hover:bg-rose-900 border border-rose-500/40 text-rose-300 transition-colors"
                >
                  Push to EDR
                </button>
                <button
                  onClick={() => showToast(`⚡ Initiated deep enrichment across ${selectedRows.length} items`)}
                  className="px-2.5 py-1 rounded bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-300 transition-colors"
                >
                  Enrich
                </button>
              </>
            )}
          </div>
        </div>

        {/* Ledger Table */}
        <div className="flex-1 overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 border-b border-slate-800/80 text-[11px] text-slate-400 sticky top-0 z-10">
              <tr>
                <th className="p-3 w-10">
                  <input
                    type="checkbox"
                    checked={selectedRows.length === filteredIOCs.length && filteredIOCs.length > 0}
                    onChange={toggleSelectAll}
                    className="rounded border-slate-700 text-cyan-500 focus:ring-0 w-3.5 h-3.5"
                  />
                </th>
                <th className="p-3">Observable</th>
                <th className="p-3">Classification & Threat</th>
                <th className="p-3">Confidence</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Source Feed</th>
                <th className="p-3">Hits</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredIOCs.map((ioc) => {
                const isSelected = selectedIOC?.id === ioc.id;
                const isChecked = selectedRows.includes(ioc.id);

                return (
                  <tr
                    key={ioc.id}
                    onClick={() => {
                      setSelectedIOC(ioc);
                      setIsMobileDrawerOpen(true);
                    }}
                    className={`cursor-pointer transition-colors ${
                      isSelected 
                        ? 'bg-cyan-950/30 text-cyan-200' 
                        : 'hover:bg-slate-900/60 text-slate-300'
                    }`}
                  >
                    <td className="p-3" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => toggleRowSelect(ioc.id)}
                        className="rounded border-slate-700 text-cyan-500 focus:ring-0 w-3.5 h-3.5"
                      />
                    </td>
                    <td className="p-3">
                      <div className="flex items-center gap-2">
                        <span className={`text-[9px] uppercase font-bold px-1.5 py-0.5 rounded border ${
                          ioc.type === 'ipv4' ? 'bg-cyan-950/60 text-cyan-400 border-cyan-500/30' :
                          ioc.type === 'domain' ? 'bg-indigo-950/60 text-indigo-400 border-indigo-500/30' :
                          ioc.type === 'sha256' ? 'bg-purple-950/60 text-purple-400 border-purple-500/30' :
                          ioc.type === 'cve' ? 'bg-rose-950/60 text-rose-400 border-rose-500/30' :
                          'bg-slate-800 text-slate-300 border-slate-700'
                        }`}>
                          {ioc.type}
                        </span>
                        <span className="font-semibold text-slate-100 max-w-xs truncate" title={ioc.value}>
                          {ioc.value}
                        </span>
                      </div>
                      {ioc.threatActor && (
                        <div className="text-[10px] text-slate-400 pl-10 mt-0.5 flex items-center gap-1">
                          <span>Actor:</span>
                          <span className="text-amber-300">{ioc.threatActor}</span>
                        </div>
                      )}
                    </td>
                    <td className="p-3">
                      <div className="text-slate-200 font-medium">{ioc.threatType}</div>
                      <div className="flex items-center gap-1.5 mt-1">
                        {ioc.tags.slice(0, 3).map((tag, idx) => (
                          <span key={idx} className="text-[9px] px-1.5 py-0.2 rounded bg-slate-900 text-slate-400 border border-slate-800">
                            {tag}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="p-3">
                      <div className="flex items-center gap-2">
                        <div className="w-16 bg-slate-800 h-1.5 rounded-full overflow-hidden">
                          <div 
                            className={`h-full rounded-full ${
                              ioc.confidence >= 90 ? 'bg-rose-500' :
                              ioc.confidence >= 70 ? 'bg-amber-500' : 'bg-cyan-500'
                            }`}
                            style={{ width: `${ioc.confidence}%` }}
                          />
                        </div>
                        <span className="font-bold text-slate-200">{ioc.confidence}%</span>
                      </div>
                    </td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${
                        ioc.severity === 'critical' ? 'bg-rose-950/80 text-rose-300 border-rose-500/40' :
                        ioc.severity === 'high' ? 'bg-amber-950/80 text-amber-300 border-amber-500/40' :
                        'bg-cyan-950/80 text-cyan-300 border-cyan-500/40'
                      }`}>
                        {ioc.severity}
                      </span>
                    </td>
                    <td className="p-3 text-slate-400">
                      <div>{ioc.source}</div>
                      <div className="text-[10px] text-slate-400">{ioc.lastSeen}</div>
                    </td>
                    <td className="p-3 text-slate-300">
                      <span className="text-rose-400 font-bold">{ioc.maliciousHits}</span>
                      <span className="text-slate-500"> / {ioc.totalHits}</span>
                    </td>
                    <td className="p-3 text-right" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => {
                            if (onSendToCopilot) {
                              onSendToCopilot(`Correlate and investigate observable ${ioc.value}`);
                            }
                            onNavigate('copilot');
                          }}
                          className="p-1.5 rounded bg-slate-900 hover:bg-cyan-950 hover:text-cyan-300 border border-slate-800 text-slate-400 transition-colors"
                          title="Chat in Copilot"
                        >
                          <Bot className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => {
                            showToast(`Quarantine rule deployed for ${ioc.value}`);
                          }}
                          className="p-1.5 rounded bg-slate-900 hover:bg-rose-950 hover:text-rose-300 border border-slate-800 text-slate-400 transition-colors"
                          title="Block Observable"
                        >
                          <ShieldAlert className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Right-Hand IOC Inspector Drawer (Desktop) */}
      <div className="hidden xl:flex w-80 2xl:w-96 border-l border-slate-800/80 bg-[#090d15] flex-col shrink-0 overflow-y-auto font-mono text-xs select-none">
        {/* Drawer Header */}
        <div className="p-4 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-2 text-cyan-400 font-semibold uppercase tracking-wider text-xs">
            <ShieldCheck className="w-4 h-4" />
            <span>IOC Inspector Drawer</span>
          </div>
          <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
            {selectedIOC.status.toUpperCase()}
          </span>
        </div>

        <div className="p-4 space-y-4">
          {/* Observable Title Card */}
          <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-[10px] text-slate-400">
              <span className="uppercase">{selectedIOC.type}</span>
              <span className="text-rose-400 font-bold">{selectedIOC.severity.toUpperCase()} SEVERITY</span>
            </div>
            <div className="text-sm font-bold text-slate-100 break-all">
              {selectedIOC.value}
            </div>
            <div className="text-[11px] text-slate-300">
              {selectedIOC.threatType}
            </div>
            {selectedIOC.notes && (
              <div className="p-2 rounded bg-slate-950/80 border border-slate-800 text-[11px] text-slate-400 leading-relaxed">
                {selectedIOC.notes}
              </div>
            )}
          </div>

          {/* Node Geolocation & ASN Card */}
          {selectedIOC.country && (
            <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-slate-400 text-[11px] flex items-center gap-1.5">
                  <Globe2 className="w-3.5 h-3.5 text-cyan-400" /> Geolocation
                </span>
                <span className="text-slate-200">{selectedIOC.city || selectedIOC.country}</span>
              </div>
              {selectedIOC.asn && (
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-slate-400 flex items-center gap-1.5">
                    <Server className="w-3.5 h-3.5 text-cyan-400" /> ASN
                  </span>
                  <span className="text-slate-300 truncate max-w-[170px]">{selectedIOC.asn}</span>
                </div>
              )}
              {/* Simulated Map Visualizer Pill */}
              <div className="h-16 rounded-lg bg-[#05080f] border border-slate-800 flex items-center justify-center relative overflow-hidden">
                <div className="absolute inset-0 bg-grid-cyber opacity-40" />
                <div className="relative flex items-center gap-2 text-cyan-400 text-[11px]">
                  <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
                  <span>Frankfurt Hub Node • Lat: 50.1109 Long: 8.6821</span>
                </div>
              </div>
            </div>
          )}

          {/* Associated Active Incidents */}
          {selectedIOC.associatedIncidents && selectedIOC.associatedIncidents.length > 0 && (
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
              <div className="text-[11px] text-slate-400 flex items-center justify-between">
                <span>Associated Incidents</span>
                <span className="text-rose-400 font-bold">{selectedIOC.associatedIncidents.length} Linked</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {selectedIOC.associatedIncidents.map(inc => (
                  <button
                    key={inc}
                    onClick={() => onNavigate('investigations')}
                    className="px-2.5 py-1 rounded bg-rose-950/60 hover:bg-rose-900 border border-rose-500/40 text-rose-300 text-xs font-mono flex items-center gap-1 transition-colors"
                  >
                    <span>{inc}</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Zero-Trust Block Rule Generator */}
          <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="text-slate-300 font-semibold flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                Zero-Trust Block Rules
              </span>
              <button
                onClick={() => handleCopyCode(getRuleSnippet())}
                className="text-slate-400 hover:text-cyan-400 flex items-center gap-1 text-[10px]"
              >
                {copiedCode ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copiedCode ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            {/* Rule tabs */}
            <div className="flex rounded-lg bg-slate-950 p-1 border border-slate-800 text-[10px]">
              {(['paloalto', 'suricata', 'iptables', 'snort'] as const).map(tab => (
                <button
                  key={tab}
                  onClick={() => setRuleTab(tab)}
                  className={`flex-1 py-1 rounded transition-colors uppercase ${
                    ruleTab === tab ? 'bg-cyan-600 text-white font-bold' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab}
                </button>
              ))}
            </div>

            {/* Code Block */}
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/90 text-[10px] text-slate-300 overflow-x-auto whitespace-pre font-mono leading-relaxed max-h-36">
              {getRuleSnippet()}
            </div>
          </div>

          {/* Action Buttons */}
          <div className="space-y-2 pt-1">
            <button
              onClick={() => {
                if (onSendToCopilot) {
                  onSendToCopilot(`Provide a complete mitigation plan and threat actor attribution for ${selectedIOC.value}`);
                }
                onNavigate('copilot');
              }}
              className="w-full py-2 px-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-medium flex items-center justify-center gap-2 transition-colors shadow-md"
            >
              <Bot className="w-3.5 h-3.5" />
              <span>Send to Copilot for AI Analysis</span>
            </button>

            <button
              onClick={() => onNavigate('threat-intel')}
              className="w-full py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono flex items-center justify-center gap-2 transition-colors"
            >
              <Globe2 className="w-3.5 h-3.5" />
              <span>View In-Depth Threat Telemetry</span>
            </button>
          </div>
        </div>
      </div>

      {/* Mobile/Tablet Slide-Over Drawer Modal */}
      {isMobileDrawerOpen && (
        <div className="fixed inset-0 z-50 xl:hidden flex justify-end">
          <div 
            className="fixed inset-0 bg-black/75 backdrop-blur-sm transition-opacity" 
            onClick={() => setIsMobileDrawerOpen(false)} 
          />
          <div className="relative w-full max-w-md bg-[#090d15] border-l border-slate-800 h-full flex flex-col z-10 shadow-2xl overflow-y-auto font-mono text-xs select-none">
            {/* Mobile Drawer Header with Close Button */}
            <div className="p-4 border-b border-slate-800/80 flex items-center justify-between sticky top-0 bg-[#090d15] z-20">
              <div className="flex items-center gap-2 text-cyan-400 font-semibold uppercase tracking-wider text-xs">
                <ShieldCheck className="w-4 h-4" />
                <span>IOC Inspector</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  {selectedIOC.status.toUpperCase()}
                </span>
                <button 
                  onClick={() => setIsMobileDrawerOpen(false)}
                  className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white"
                  title="Close Drawer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            <div className="p-4 space-y-4">
              {/* Observable Title Card */}
              <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between text-[10px] text-slate-400">
                  <span className="uppercase">{selectedIOC.type}</span>
                  <span className="text-rose-400 font-bold">{selectedIOC.severity.toUpperCase()} SEVERITY</span>
                </div>
                <div className="text-sm font-bold text-slate-100 break-all">
                  {selectedIOC.value}
                </div>
                <div className="text-[11px] text-slate-300">
                  {selectedIOC.threatType}
                </div>
                {selectedIOC.notes && (
                  <div className="p-2 rounded bg-slate-950/80 border border-slate-800 text-[11px] text-slate-400 leading-relaxed">
                    {selectedIOC.notes}
                  </div>
                )}
              </div>

              {/* Node Geolocation & ASN Card */}
              {selectedIOC.country && (
                <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400 text-[11px] flex items-center gap-1.5">
                      <Globe2 className="w-3.5 h-3.5 text-cyan-400" /> Geolocation
                    </span>
                    <span className="text-slate-200">{selectedIOC.city || selectedIOC.country}</span>
                  </div>
                  {selectedIOC.asn && (
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-slate-400 flex items-center gap-1.5">
                        <Server className="w-3.5 h-3.5 text-cyan-400" /> ASN
                      </span>
                      <span className="text-slate-300 truncate max-w-[170px]">{selectedIOC.asn}</span>
                    </div>
                  )}
                </div>
              )}

              {/* Associated Active Incidents */}
              {selectedIOC.associatedIncidents && selectedIOC.associatedIncidents.length > 0 && (
                <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
                  <div className="text-[11px] text-slate-400 flex items-center justify-between">
                    <span>Associated Incidents</span>
                    <span className="text-rose-400 font-bold">{selectedIOC.associatedIncidents.length} Linked</span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {selectedIOC.associatedIncidents.map(inc => (
                      <button
                        key={inc}
                        onClick={() => {
                          setIsMobileDrawerOpen(false);
                          onNavigate('investigations');
                        }}
                        className="px-2.5 py-1 rounded bg-rose-950/60 hover:bg-rose-900 border border-rose-500/40 text-rose-300 text-xs font-mono flex items-center gap-1"
                      >
                        <span>{inc}</span>
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Zero-Trust Block Rule Generator */}
              <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-slate-300 font-semibold flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                    Zero-Trust Block Rules
                  </span>
                  <button
                    onClick={() => handleCopyCode(getRuleSnippet())}
                    className="text-slate-400 hover:text-cyan-400 flex items-center gap-1 text-[10px]"
                  >
                    {copiedCode ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedCode ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>

                {/* Rule tabs */}
                <div className="flex rounded-lg bg-slate-950 p-1 border border-slate-800 text-[10px]">
                  {(['paloalto', 'suricata', 'iptables', 'snort'] as const).map(tab => (
                    <button
                      key={tab}
                      onClick={() => setRuleTab(tab)}
                      className={`flex-1 py-1 rounded transition-colors uppercase ${
                        ruleTab === tab ? 'bg-cyan-600 text-white font-bold' : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {tab}
                    </button>
                  ))}
                </div>

                {/* Code Block */}
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/90 text-[10px] text-slate-300 overflow-x-auto whitespace-pre font-mono leading-relaxed max-h-36">
                  {getRuleSnippet()}
                </div>
              </div>

              {/* Action Buttons */}
              <div className="space-y-2 pt-1 pb-6">
                <button
                  onClick={() => {
                    setIsMobileDrawerOpen(false);
                    if (onSendToCopilot) {
                      onSendToCopilot(`Provide a complete mitigation plan and threat actor attribution for ${selectedIOC.value}`);
                    }
                    onNavigate('copilot');
                  }}
                  className="w-full py-2.5 px-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-medium flex items-center justify-center gap-2 transition-colors shadow-md"
                >
                  <Bot className="w-3.5 h-3.5" />
                  <span>Send to Copilot for AI Analysis</span>
                </button>

                <button
                  onClick={() => {
                    setIsMobileDrawerOpen(false);
                    onNavigate('threat-intel');
                  }}
                  className="w-full py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono flex items-center justify-center gap-2 transition-colors"
                >
                  <Globe2 className="w-3.5 h-3.5" />
                  <span>View In-Depth Threat Telemetry</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Add Observable Modal */}
      {isAddModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-slate-900 border border-slate-700 rounded-2xl p-6 shadow-2xl space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm">
                <Plus className="w-4 h-4" />
                <span>Add Indicator of Compromise</span>
              </div>
              <button onClick={() => setIsAddModalOpen(false)} className="text-slate-400 hover:text-slate-200">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleAddNewIOC} className="space-y-3.5">
              <div>
                <label className="block text-slate-400 mb-1">Observable Value</label>
                <input
                  type="text"
                  required
                  value={newVal}
                  onChange={(e) => setNewVal(e.target.value)}
                  placeholder="e.g. 192.168.1.5, malicious-domain.com, or sha256..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Type</label>
                  <select
                    value={newType}
                    onChange={(e) => setNewType(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="ipv4">IPv4</option>
                    <option value="domain">Domain</option>
                    <option value="sha256">SHA-256</option>
                    <option value="url">URL</option>
                    <option value="cve">CVE</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Severity</label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Threat Classification</label>
                <input
                  type="text"
                  value={newThreat}
                  onChange={(e) => setNewThreat(e.target.value)}
                  placeholder="e.g. Cobalt Strike Beacon, Mirai C2, Ransomware Drop"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div className="pt-2 flex items-center justify-end gap-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsAddModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium transition-colors"
                >
                  Save Observable
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
