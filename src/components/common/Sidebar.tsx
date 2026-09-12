import React from 'react';
import { 
  Bot, 
  ShieldCheck, 
  FileText, 
  Globe2, 
  Activity, 
  GitFork, 
  Database,
  Cpu,
  Layers,
  ChevronRight,
  Radio,
  Crosshair,
  X,
  ShieldAlert
} from 'lucide-react';
import { ScreenType, SecurityTarget } from '../../types';
import { IS_DEMO_MODE } from '../../utils/config';

interface SidebarProps {
  currentScreen: ScreenType;
  onNavigate: (screen: ScreenType) => void;
  isMobileOpen?: boolean;
  onCloseMobile?: () => void;
  onOpenSystemStatus?: () => void;
  onOpenAuditLog?: () => void;
  targetsCount?: number;
  activeTarget?: SecurityTarget | null;
  iocCount?: number;
  casesCount?: number;
  reportCount?: number;
  docCount?: number;
  workflowCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({ 
  currentScreen, 
  onNavigate,
  isMobileOpen = false,
  onCloseMobile,
  onOpenSystemStatus,
  onOpenAuditLog,
  targetsCount,
  activeTarget,
  iocCount,
  casesCount,
  reportCount,
  docCount,
  workflowCount
}) => {
  const primaryNavItems = [
    {
      id: 'copilot' as ScreenType,
      label: 'Intelligence Copilot',
      subtitle: 'Multi-Model AI SecOps Chat',
      icon: Bot,
      badge: 'Active',
      badgeColor: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30'
    },
    {
      id: 'ioc-manager' as ScreenType,
      label: 'IOC Threat Ledger',
      subtitle: 'Correlated Observables & STIX',
      icon: ShieldCheck,
      badge: iocCount !== undefined ? String(iocCount) : (IS_DEMO_MODE ? '1,482' : '0'),
      badgeColor: iocCount !== undefined && iocCount > 0 
        ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' 
        : 'bg-slate-800 text-slate-400 border-slate-700'
    },
    {
      id: 'security-intel' as ScreenType,
      label: 'Security Intelligence',
      subtitle: 'Audit & Incident Reports',
      icon: FileText,
      badge: reportCount !== undefined && reportCount > 0 
        ? `${reportCount} Reports` 
        : (IS_DEMO_MODE ? 'CVSS 9.8' : '0 Reports'),
      badgeColor: reportCount !== undefined && reportCount > 0 
        ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' 
        : 'bg-slate-800 text-slate-400 border-slate-700'
    }
  ];

  const secondaryNavItems = [
    {
      id: 'target-inventory' as ScreenType,
      label: 'Target Scope & IPs',
      icon: Crosshair,
      tag: targetsCount !== undefined 
        ? `${targetsCount} Monitored` 
        : (IS_DEMO_MODE ? '5 Monitored' : '0 Monitored')
    },
    {
      id: 'threat-intel' as ScreenType,
      label: 'Target Dossier',
      icon: Globe2,
      tag: activeTarget ? activeTarget.value : (IS_DEMO_MODE ? '185.220.101.5' : 'No Target')
    },
    {
      id: 'investigations' as ScreenType,
      label: 'Forensic Hub',
      icon: Activity,
      tag: casesCount !== undefined && casesCount > 0 
        ? `${casesCount} Active` 
        : (IS_DEMO_MODE ? 'Active' : '0 Active')
    },
    {
      id: 'agent-workflows' as ScreenType,
      label: 'Autonomous Agent DAG',
      icon: GitFork,
      tag: workflowCount !== undefined && workflowCount > 0 
        ? 'Active' 
        : (IS_DEMO_MODE ? 'HITL Gate' : '0 Active')
    },
    {
      id: 'rag-core' as ScreenType,
      label: 'RAG Knowledge Core',
      icon: Database,
      tag: docCount !== undefined 
        ? `${docCount} Docs` 
        : (IS_DEMO_MODE ? '18 Docs' : '0 Docs')
    }
  ];

  const handleItemClick = (screenId: ScreenType) => {
    onNavigate(screenId);
    if (onCloseMobile) {
      onCloseMobile();
    }
  };

  const renderNavContent = () => (
    <div className="flex flex-col h-full justify-between overflow-y-auto">
      <div className="p-3 space-y-6">
        {/* Core Prototype Nav Group */}
        <div>
          <div className="px-3 pb-2 flex items-center justify-between text-[11px] font-mono uppercase tracking-wider text-slate-400">
            <span>Core Operations</span>
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 animate-pulse" />
          </div>
          <div className="space-y-1">
            {primaryNavItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentScreen === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => handleItemClick(item.id)}
                  className={`w-full text-left p-2.5 rounded-lg transition-all flex items-center justify-between group relative ${
                    isActive
                      ? 'bg-gradient-to-r from-cyan-950/60 to-slate-900 border border-cyan-500/40 text-slate-100 shadow-[0_0_15px_rgba(6,182,212,0.12)]'
                      : 'hover:bg-slate-900/60 border border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <div className={`p-1.5 rounded-md ${
                      isActive 
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' 
                        : 'bg-slate-900 text-slate-400 group-hover:text-cyan-300 group-hover:bg-slate-800'
                    }`}>
                      <Icon className="w-4 h-4" />
                    </div>
                    <div>
                      <div className={`text-xs font-medium ${isActive ? 'text-slate-100 font-semibold' : 'text-slate-300'}`}>
                        {item.label}
                      </div>
                      <div className="text-[10px] text-slate-400 font-mono">
                        {item.subtitle}
                      </div>
                    </div>
                  </div>
                  {item.badge && (
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${item.badgeColor}`}>
                      {item.badge}
                    </span>
                  )}
                  {isActive && (
                    <span className="absolute left-0 top-2 bottom-2 w-0.5 bg-cyan-400 rounded-r" />
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Specialized Intelligence Modules */}
        <div>
          <div className="px-3 pb-2 flex items-center justify-between text-[11px] font-mono uppercase tracking-wider text-slate-400">
            <span>Specialized Intelligence</span>
            <Layers className="w-3 h-3 text-slate-400" />
          </div>
          <div className="space-y-1">
            {secondaryNavItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentScreen === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => handleItemClick(item.id)}
                  className={`w-full text-left px-3 py-2.5 rounded-lg transition-all flex items-center justify-between group ${
                    isActive
                      ? 'bg-slate-900 border border-slate-700 text-cyan-300 font-medium'
                      : 'hover:bg-slate-900/50 text-slate-400 hover:text-slate-300'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-400 group-hover:text-slate-300'}`} />
                    <span className="text-xs">{item.label}</span>
                  </div>
                  {item.tag && (
                    <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-800/80 text-slate-400 border border-slate-700/60">
                      {item.tag}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Bottom Telemetry Mini Card */}
      <div className="p-3 border-t border-slate-800/80 bg-slate-950/40">
        <button
          type="button"
          onClick={onOpenSystemStatus}
          className="w-full text-left p-2.5 rounded-lg border border-slate-800 hover:border-cyan-500/40 bg-slate-900/60 hover:bg-slate-900 transition-colors space-y-2 group cursor-pointer"
          title="Open System Diagnostics & Connector Health"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              <Radio className={`w-3 h-3 ${IS_DEMO_MODE ? 'text-emerald-400 animate-pulse' : 'text-slate-500'}`} />
              <span className="text-[11px] font-mono text-slate-300 group-hover:text-cyan-300 transition-colors">EDR Engine Status</span>
            </div>
            <span className={`text-[9px] font-mono px-1 py-0.5 rounded border ${
              IS_DEMO_MODE 
                ? 'text-emerald-400 bg-emerald-950/50 border-emerald-800/60' 
                : 'text-slate-400 bg-slate-800/50 border-slate-700/60'
            }`}>
              {IS_DEMO_MODE ? 'OPTIMAL' : 'Not configured'}
            </span>
          </div>
          <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
            <span>Latency: {IS_DEMO_MODE ? '14ms' : '--'}</span>
            <span>Cluster: {IS_DEMO_MODE ? 'eu-west-1' : 'Not connected'}</span>
          </div>
          <div className="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
            <div className={`bg-gradient-to-r from-emerald-500 to-cyan-400 h-full ${IS_DEMO_MODE ? 'w-[94%]' : 'w-0'}`} />
          </div>
        </button>
      </div>
    </div>
  );

  return (
    <>
      {/* 1. Desktop Persistent Sidebar */}
      <aside className="hidden lg:flex w-64 border-r border-slate-800/80 bg-[#080b11] flex-col justify-between shrink-0 select-none">
        {renderNavContent()}
      </aside>

      {/* 2. Mobile & Tablet Slide-Over Drawer */}
      {isMobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          {/* Backdrop overlay */}
          <div 
            className="fixed inset-0 bg-black/80 backdrop-blur-sm transition-opacity animate-in fade-in"
            onClick={onCloseMobile}
          />

          {/* Drawer Panel */}
          <div className="relative w-72 max-w-[85vw] bg-[#090d15] border-r border-slate-700/90 shadow-2xl flex flex-col h-full z-10 animate-in slide-in-from-left duration-200">
            {/* Mobile Header in Drawer */}
            <div className="p-3.5 border-b border-slate-800 bg-[#0c111c] flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <div className="w-7 h-7 rounded-lg bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
                  <ShieldAlert className="w-4 h-4" />
                </div>
                <div className="font-mono text-xs font-bold tracking-wider text-slate-100">
                  CIPHER <span className="text-cyan-400">AI</span>
                </div>
              </div>
              <button
                onClick={onCloseMobile}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
                aria-label="Close navigation"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Nav content */}
            <div className="flex-1 overflow-y-auto">
              {renderNavContent()}
            </div>
          </div>
        </div>
      )}
    </>
  );
};
