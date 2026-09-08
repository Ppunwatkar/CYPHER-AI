import React, { useState, useRef, useEffect } from 'react';
import { 
  ShieldAlert, 
  Search, 
  Bell, 
  Terminal, 
  CheckCircle2, 
  Sparkles,
  RefreshCw,
  Lock,
  Crosshair,
  ChevronDown,
  Plus,
  LogOut,
  User,
  Key,
  ShieldCheck,
  Building,
  Globe2,
  Layers,
  Menu,
  X
} from 'lucide-react';
import { ScreenType, UserProfile, SecurityTarget } from '../../types';

interface HeaderProps {
  currentScreen: ScreenType;
  onNavigate: (screen: ScreenType) => void;
  currentUser: UserProfile | null;
  onOpenAuthModal: (mode?: 'login' | 'signup') => void;
  onLogout: () => void;
  activeTarget?: SecurityTarget | null;
  targets?: SecurityTarget[];
  onSelectActiveTarget?: (target: SecurityTarget) => void;
  onOpenAddTargetModal?: () => void;
  onToggleMobileSidebar?: () => void;
  isMobileSidebarOpen?: boolean;
  onOpenCommandPalette?: () => void;
  onOpenSystemStatus?: () => void;
  onOpenAuditLog?: () => void;
  onClearActiveTarget?: () => void;
}

export const Header: React.FC<HeaderProps> = ({ 
  currentScreen, 
  onNavigate,
  currentUser,
  onOpenAuthModal,
  onLogout,
  activeTarget,
  targets = [],
  onSelectActiveTarget,
  onOpenAddTargetModal,
  onToggleMobileSidebar,
  isMobileSidebarOpen,
  onOpenCommandPalette,
  onOpenSystemStatus,
  onOpenAuditLog,
  onClearActiveTarget
}) => {
  const [showTargetMenu, setShowTargetMenu] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);

  const targetMenuRef = useRef<HTMLDivElement>(null);
  const userMenuRef = useRef<HTMLDivElement>(null);

  // Close menus on click outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (targetMenuRef.current && !targetMenuRef.current.contains(e.target as Node)) {
        setShowTargetMenu(false);
      }
      if (userMenuRef.current && !userMenuRef.current.contains(e.target as Node)) {
        setShowUserMenu(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <header className="h-14 border-b border-slate-800/80 bg-[#0a0e17]/95 backdrop-blur-md px-3 sm:px-4 flex items-center justify-between sticky top-0 z-30 select-none">
      {/* Left: Brand Identity & Mobile Hamburger & Target Scope */}
      <div className="flex items-center gap-2 sm:gap-4 lg:gap-6">
        {/* Mobile / Tablet Menu Button */}
        {onToggleMobileSidebar && (
          <button
            onClick={onToggleMobileSidebar}
            className="lg:hidden p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-cyan-400 hover:border-slate-700 transition-colors focus:outline-none focus:ring-1 focus:ring-cyan-500"
            aria-label="Toggle Navigation Menu"
          >
            {isMobileSidebarOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
          </button>
        )}

        <div 
          onClick={() => onNavigate('copilot')}
          className="flex items-center gap-2.5 sm:gap-3 cursor-pointer group"
        >
          <div className="relative flex items-center justify-center w-8 h-8 rounded-lg bg-cyan-950/70 border border-cyan-500/40 text-cyan-400 group-hover:border-cyan-400 transition-colors shadow-[0_0_15px_rgba(6,182,212,0.15)] shrink-0">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-emerald-400 ring-2 ring-[#0a0e17] animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-1.5 sm:gap-2">
              <span className="text-xs sm:text-sm font-semibold tracking-wider font-mono text-slate-100 uppercase">
                CIPHER <span className="text-cyan-400">AI</span>
              </span>
              <span className="text-[9px] sm:text-[10px] font-mono px-1.5 py-0.2 sm:py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hidden xs:inline-block">
                v4.8
              </span>
            </div>
            <p className="text-[9px] sm:text-[10px] text-slate-400 font-mono tracking-tight hidden md:block">
              CYBERSECURITY COPILOT
            </p>
          </div>
        </div>

        {/* ACTIVE TARGET SCOPE SELECTOR */}
        {activeTarget ? (
          <div className="relative" ref={targetMenuRef}>
            <button
              onClick={() => setShowTargetMenu(!showTargetMenu)}
              className="flex items-center gap-1.5 sm:gap-2 px-2 sm:px-2.5 py-1.5 rounded-lg bg-slate-900/90 border border-slate-700/80 hover:border-cyan-500/50 text-slate-200 text-xs font-mono transition-all group cursor-pointer"
            >
              <Crosshair className="w-3.5 h-3.5 text-cyan-400 group-hover:rotate-45 transition-transform shrink-0" />
              <div className="flex items-center gap-1 sm:gap-1.5 min-w-0">
                <span className="text-slate-400 hidden xl:inline">Scope:</span>
                <span className="font-semibold text-cyan-300 max-w-[90px] xs:max-w-[120px] sm:max-w-[160px] truncate">
                  {activeTarget.value}
                </span>
                <span className={`text-[8px] sm:text-[9px] px-1 py-0.2 rounded font-bold uppercase shrink-0 ${
                  activeTarget.threatScore >= 90 ? 'bg-rose-950 text-rose-300 border border-rose-500/30' :
                  activeTarget.threatScore >= 70 ? 'bg-amber-950 text-amber-300 border border-amber-500/30' :
                  'bg-cyan-950 text-cyan-300 border border-cyan-500/30'
                }`}>
                  {activeTarget.threatScore}%
                </span>
              </div>
              <ChevronDown className="w-3 h-3 text-slate-400 shrink-0" />
            </button>

            {/* Target Dropdown Menu */}
            {showTargetMenu && (
              <div className="absolute left-0 mt-2 w-72 sm:w-80 bg-[#090d16] border border-slate-700/90 rounded-xl shadow-2xl p-2 font-mono text-xs z-50 animate-in fade-in">
                <div className="flex items-center justify-between px-2 py-1.5 border-b border-slate-800 text-[10px] text-slate-400 uppercase">
                  <span>Monitored Targets ({targets.length})</span>
                  <div className="flex items-center gap-2">
                    {onClearActiveTarget && (
                      <button
                        onClick={() => {
                          setShowTargetMenu(false);
                          onClearActiveTarget();
                        }}
                        className="text-rose-400 hover:text-rose-300 transition-colors"
                      >
                        Clear Scope
                      </button>
                    )}
                    <button
                      onClick={() => {
                        setShowTargetMenu(false);
                        onNavigate('target-inventory' as any);
                      }}
                      className="text-cyan-400 hover:text-cyan-300 underline"
                    >
                      Manage All
                    </button>
                  </div>
                </div>

                <div className="max-h-56 overflow-y-auto py-1 space-y-1">
                  {targets.length === 0 ? (
                    <div className="p-3 text-center text-slate-500 text-[11px]">
                      No targets in inventory
                    </div>
                  ) : (
                    targets.map(tgt => (
                      <button
                        key={tgt.id}
                        onClick={() => {
                          if (onSelectActiveTarget) onSelectActiveTarget(tgt);
                          setShowTargetMenu(false);
                        }}
                        className={`w-full text-left p-2 rounded-lg flex items-center justify-between gap-2 transition-colors ${
                          activeTarget.id === tgt.id 
                            ? 'bg-cyan-950/60 border border-cyan-500/40 text-cyan-200' 
                            : 'hover:bg-slate-800/80 text-slate-300'
                        }`}
                      >
                        <div className="min-w-0 flex-1">
                          <div className="font-semibold text-xs truncate">{tgt.value}</div>
                          <div className="text-[10px] text-slate-400 truncate">{tgt.label}</div>
                        </div>
                        <span className={`text-[9px] px-1 py-0.2 rounded font-bold ${
                          tgt.threatScore >= 90 ? 'text-rose-400' : 'text-cyan-400'
                        }`}>
                          {tgt.threatScore}
                        </span>
                      </button>
                    ))
                  )}
                </div>

                <div className="pt-2 border-t border-slate-800">
                  <button
                    onClick={() => {
                      setShowTargetMenu(false);
                      if (onOpenAddTargetModal) onOpenAddTargetModal();
                    }}
                    className="w-full py-1.5 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/40 text-cyan-300 flex items-center justify-center gap-1.5 text-xs font-semibold transition-colors cursor-pointer"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>+ Input New Target / IP</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        ) : (
          <button
            onClick={() => {
              if (onOpenAddTargetModal) onOpenAddTargetModal();
            }}
            className="flex items-center gap-1.5 px-2 sm:px-2.5 py-1.5 rounded-lg bg-slate-900/80 border border-dashed border-slate-700/90 hover:border-cyan-500/60 hover:bg-slate-900 text-slate-400 hover:text-cyan-300 text-xs font-mono transition-all group cursor-pointer"
            title="Set active target scope"
          >
            <Crosshair className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 group-hover:rotate-45 transition-all shrink-0" />
            <span className="hidden sm:inline text-slate-500">Scope:</span>
            <span>+ Set Target</span>
          </button>
        )}
      </div>

      {/* Center Search bar (Command Palette Trigger) */}
      <div className="flex-1 max-w-sm mx-4 hidden lg:block">
        <button 
          onClick={onOpenCommandPalette}
          className="w-full h-8.5 bg-slate-900/90 hover:bg-slate-900 border border-slate-800 hover:border-cyan-500/50 rounded-lg pl-3 pr-2.5 flex items-center justify-between text-xs text-slate-400 font-mono transition-all group"
        >
          <div className="flex items-center gap-2">
            <Search className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition-colors" />
            <span className="text-slate-400 group-hover:text-slate-300">Command Palette, IP, CVE...</span>
          </div>
          <kbd className="px-1.5 py-0.5 rounded text-[9px] bg-slate-800 text-slate-400 border border-slate-700 font-mono group-hover:border-cyan-500/40">
            ⌘K
          </kbd>
        </button>
      </div>

      {/* Right Controls & User Auth */}
      <div className="flex items-center gap-2 sm:gap-3">
        {/* System Health Status Indicator */}
        {onOpenSystemStatus && (
          <button
            onClick={onOpenSystemStatus}
            className="hidden xl:flex items-center gap-1.5 px-2 py-1 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-slate-800 text-slate-300 text-[11px] font-mono transition-colors"
            title="AI Model Gateway & Connector Status"
          >
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-slate-400">CONNECTORS:</span>
            <span className="text-emerald-300 font-bold">7/8 ONLINE</span>
          </button>
        )}

        {/* Audit Log Quick Button */}
        {onOpenAuditLog && (
          <button
            onClick={onOpenAuditLog}
            className="hidden xl:flex items-center gap-1 px-2 py-1 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-slate-200 text-[11px] font-mono transition-colors"
            title="Immutable Security Audit Log"
          >
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span>Audit Log</span>
          </button>
        )}

        {/* Quick Add Target Shortcut - hidden on extra small */}
        <button
          onClick={onOpenAddTargetModal}
          className="hidden md:flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 text-slate-300 text-xs font-mono transition-colors"
          title="Input Target IP or Asset"
        >
          <Plus className="w-3.5 h-3.5 text-cyan-400" />
          <span>Add Target</span>
        </button>

        {/* Notifications */}
        <button 
          onClick={() => onNavigate('investigations')}
          className="relative p-2 rounded-lg bg-slate-900/80 border border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700 transition-colors shrink-0"
          title="Active incident notifications"
        >
          <Bell className="w-4 h-4" />
          <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-rose-500" />
        </button>

        {/* User Profile / Auth State */}
        {currentUser ? (
          <div className="relative" ref={userMenuRef}>
            <button
              onClick={() => setShowUserMenu(!showUserMenu)}
              className="flex items-center gap-2 pl-1 sm:pl-2 border-l border-slate-800 group hover:opacity-90 transition-opacity"
            >
              <div className="w-7 h-7 rounded-lg bg-cyan-950 border border-cyan-500/50 flex items-center justify-center text-cyan-300 font-mono text-xs font-bold shadow-[0_0_10px_rgba(6,182,212,0.2)] shrink-0">
                {currentUser.avatarInitials}
              </div>
              <div className="hidden sm:block text-left font-mono">
                <div className="text-xs font-semibold text-slate-200 leading-tight group-hover:text-cyan-300">
                  {currentUser.name.split(' ')[0]}
                </div>
                <div className="text-[9px] text-amber-400/90">
                  {currentUser.clearanceLevel.split(' ')[0]}
                </div>
              </div>
              <ChevronDown className="w-3 h-3 text-slate-400 hidden sm:block shrink-0" />
            </button>

            {/* User Dropdown */}
            {showUserMenu && (
              <div className="absolute right-0 mt-2 w-64 sm:w-72 bg-[#090d16] border border-slate-700/90 rounded-xl shadow-2xl p-3 font-mono text-xs z-50 animate-in fade-in space-y-3">
                <div className="p-2 rounded-lg bg-slate-950 border border-slate-800/80 space-y-1">
                  <div className="font-bold text-slate-100 text-xs">{currentUser.name}</div>
                  <div className="text-[10px] text-slate-400 truncate">{currentUser.email}</div>
                  <div className="text-[10px] text-cyan-300 font-semibold">{currentUser.role}</div>
                  <div className="text-[9px] text-slate-500">{currentUser.organization}</div>
                  <div className="pt-1 flex items-center gap-1 text-[9px] text-amber-400">
                    <ShieldCheck className="w-3 h-3" />
                    <span>Clearance: {currentUser.clearanceLevel}</span>
                  </div>
                </div>

                <div className="space-y-1">
                  {onOpenSystemStatus && (
                    <button
                      onClick={() => {
                        setShowUserMenu(false);
                        onOpenSystemStatus();
                      }}
                      className="w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-slate-800 text-slate-300 flex items-center gap-2 transition-colors"
                    >
                      <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
                      <span>System & Connector Health</span>
                    </button>
                  )}

                  {onOpenAuditLog && (
                    <button
                      onClick={() => {
                        setShowUserMenu(false);
                        onOpenAuditLog();
                      }}
                      className="w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-slate-800 text-slate-300 flex items-center gap-2 transition-colors"
                    >
                      <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Immutable Security Audit Log</span>
                    </button>
                  )}

                  <button
                    onClick={() => {
                      setShowUserMenu(false);
                      onOpenAuthModal('login');
                    }}
                    className="w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-slate-800 text-slate-300 flex items-center gap-2 transition-colors"
                  >
                    <User className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Switch Operational Analyst</span>
                  </button>

                  <button
                    onClick={() => {
                      setShowUserMenu(false);
                      onLogout();
                    }}
                    className="w-full text-left px-2.5 py-1.5 rounded-lg hover:bg-rose-950/40 text-rose-300 flex items-center gap-2 transition-colors"
                  >
                    <LogOut className="w-3.5 h-3.5 text-rose-400" />
                    <span>Revoke & Sign Out</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="flex items-center gap-1 sm:gap-2">
            <button
              onClick={() => onOpenAuthModal('login')}
              className="px-2.5 sm:px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-md shrink-0"
            >
              <Key className="w-3.5 h-3.5" />
              <span className="hidden xs:inline">Sign In</span>
            </button>
          </div>
        )}
      </div>
    </header>
  );
};

