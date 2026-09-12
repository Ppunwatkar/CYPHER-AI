import React, { useState, useEffect, useRef } from 'react';
import { 
  Search, 
  Bot, 
  Crosshair, 
  UploadCloud, 
  ShieldCheck, 
  Activity, 
  FileText, 
  Globe2, 
  Cpu, 
  Database, 
  ActivitySquare, 
  FileCode, 
  X, 
  ArrowRight,
  ShieldAlert,
  Radio,
  Server
} from 'lucide-react';
import { ScreenType } from '../../types';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigate: (screen: ScreenType) => void;
  onOpenAddTarget: () => void;
  onOpenSystemStatus: () => void;
  onOpenAuditLog: () => void;
  onNewChat: () => void;
}

interface CommandItem {
  id: string;
  category: 'Actions' | 'Navigation' | 'Security Operations' | 'Diagnostics';
  title: string;
  subtitle: string;
  icon: React.ElementType;
  shortcut?: string;
  action: () => void;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  isOpen,
  onClose,
  onNavigate,
  onOpenAddTarget,
  onOpenSystemStatus,
  onOpenAuditLog,
  onNewChat
}) => {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50);
      setSelectedIndex(0);
    }
  }, [isOpen]);

  const commands: CommandItem[] = [
    {
      id: 'new-chat',
      category: 'Actions',
      title: 'New AI Chat Session',
      subtitle: 'Reset context and launch new SecOps conversation',
      icon: Bot,
      shortcut: 'N',
      action: () => {
        onNewChat();
        onNavigate('copilot');
      }
    },
    {
      id: 'investigate-target',
      category: 'Actions',
      title: 'Investigate Target / Input IP',
      subtitle: 'Analyze IPv4, CIDR, domain, or observable',
      icon: Crosshair,
      shortcut: 'I',
      action: () => {
        onOpenAddTarget();
      }
    },
    {
      id: 'upload-doc',
      category: 'Actions',
      title: 'Upload Security Document (RAG)',
      subtitle: 'Ingest runbook, advisory, or incident log into vector core',
      icon: UploadCloud,
      shortcut: 'U',
      action: () => {
        onNavigate('rag-core');
      }
    },
    {
      id: 'nav-copilot',
      category: 'Navigation',
      title: 'Intelligence Copilot',
      subtitle: 'Primary AI Control Plane & Threat Reasoning',
      icon: Bot,
      shortcut: '1',
      action: () => onNavigate('copilot')
    },
    {
      id: 'nav-ioc',
      category: 'Navigation',
      title: 'IOC Threat Ledger',
      subtitle: 'View correlated indicators of compromise & STIX 2.1 bundles',
      icon: ShieldCheck,
      shortcut: '2',
      action: () => onNavigate('ioc-manager')
    },
    {
      id: 'nav-report',
      category: 'Navigation',
      title: 'Security Intelligence & Reports',
      subtitle: 'Incident assessments, CVSS scores, and mitigation roadmaps',
      icon: FileText,
      shortcut: '3',
      action: () => onNavigate('security-intel')
    },
    {
      id: 'nav-target-inventory',
      category: 'Navigation',
      title: 'Target Scope & Inventory',
      subtitle: 'Monitored IP addresses, subnets, and host registries',
      icon: Crosshair,
      action: () => onNavigate('target-inventory')
    },
    {
      id: 'nav-threat-intel',
      category: 'Navigation',
      title: 'Threat Intelligence Dossier',
      subtitle: 'Deep OSINT, Shodan banners, and AbuseIPDB records',
      icon: Globe2,
      action: () => onNavigate('threat-intel')
    },
    {
      id: 'nav-investigations',
      category: 'Navigation',
      title: 'Forensic Hub (INC-8941)',
      subtitle: 'Active incident timeline and blast radius analysis',
      icon: Activity,
      action: () => onNavigate('investigations')
    },
    {
      id: 'nav-rag',
      category: 'Navigation',
      title: 'RAG Knowledge Core',
      subtitle: 'MITRE ATT&CK enterprise vectors & defense runbooks',
      icon: Database,
      action: () => onNavigate('rag-core')
    },
    {
      id: 'open-system-status',
      category: 'Diagnostics',
      title: 'System Health & API Connectors',
      subtitle: 'Inspect operational health of AI models, Shodan, VT, and NVD',
      icon: Server,
      shortcut: 'S',
      action: () => onOpenSystemStatus()
    },
    {
      id: 'open-audit-log',
      category: 'Diagnostics',
      title: 'Security Audit Event Ledger',
      subtitle: 'Zero-trust audit trail of analyst actions and investigations',
      icon: FileCode,
      shortcut: 'A',
      action: () => onOpenAuditLog()
    }
  ];

  const filtered = commands.filter(c => 
    c.title.toLowerCase().includes(query.toLowerCase()) ||
    c.subtitle.toLowerCase().includes(query.toLowerCase()) ||
    c.category.toLowerCase().includes(query.toLowerCase())
  );

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      onClose();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex(prev => (prev + 1) % (filtered.length || 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex(prev => (prev - 1 + filtered.length) % (filtered.length || 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (filtered[selectedIndex]) {
        filtered[selectedIndex].action();
        onClose();
      }
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-start justify-center pt-20 p-4">
      <div 
        className="w-full max-w-xl bg-[#090d15] border border-slate-700/90 rounded-2xl shadow-2xl overflow-hidden font-mono text-xs animate-in fade-in zoom-in-95 duration-150 flex flex-col max-h-[80vh]"
        onKeyDown={handleKeyDown}
      >
        {/* Search Header */}
        <div className="p-3.5 border-b border-slate-800 bg-[#0c111c] flex items-center gap-3">
          <Search className="w-4 h-4 text-cyan-400 shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            placeholder="Type a command, search screen, or action..."
            className="flex-1 bg-transparent border-none text-slate-100 placeholder:text-slate-500 text-xs focus:outline-none font-mono"
          />
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
            ESC to close
          </span>
          <button 
            onClick={onClose}
            className="text-slate-500 hover:text-slate-300 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results List */}
        <div className="overflow-y-auto p-2 space-y-1">
          {filtered.length === 0 ? (
            <div className="p-8 text-center text-slate-500 text-xs">
              No matching SecOps commands or screens found.
            </div>
          ) : (
            filtered.map((cmd, idx) => {
              const Icon = cmd.icon;
              const isSelected = idx === selectedIndex;
              return (
                <button
                  key={cmd.id}
                  onClick={() => {
                    cmd.action();
                    onClose();
                  }}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  className={`w-full text-left p-2.5 rounded-xl flex items-center justify-between transition-all ${
                    isSelected 
                      ? 'bg-cyan-950/60 border border-cyan-500/50 text-cyan-200' 
                      : 'hover:bg-slate-900/80 border border-transparent text-slate-300'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 ${
                      isSelected ? 'bg-cyan-500/20 text-cyan-300' : 'bg-slate-800 text-slate-400'
                    }`}>
                      <Icon className="w-3.5 h-3.5" />
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold truncate text-xs">{cmd.title}</span>
                        <span className="text-[9px] px-1.5 py-0.2 rounded bg-slate-800/80 text-slate-400 border border-slate-700/60">
                          {cmd.category}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 truncate mt-0.5">{cmd.subtitle}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0 ml-2">
                    {cmd.shortcut && (
                      <kbd className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 text-[10px]">
                        {cmd.shortcut}
                      </kbd>
                    )}
                    <ArrowRight className={`w-3.5 h-3.5 ${isSelected ? 'text-cyan-400' : 'text-slate-600'}`} />
                  </div>
                </button>
              );
            })
          )}
        </div>

        {/* Footer shortcuts */}
        <div className="px-4 py-2 border-t border-slate-800 bg-[#0a0e17] flex items-center justify-between text-[10px] text-slate-500 font-mono">
          <div className="flex items-center gap-3">
            <span>Use <kbd className="px-1 rounded bg-slate-800 border border-slate-700">↑</kbd> <kbd className="px-1 rounded bg-slate-800 border border-slate-700">↓</kbd> to navigate</span>
            <span><kbd className="px-1 rounded bg-slate-800 border border-slate-700">Enter</kbd> to select</span>
          </div>
          <span className="text-cyan-400">CIPHER AI Control Plane</span>
        </div>
      </div>
    </div>
  );
};
