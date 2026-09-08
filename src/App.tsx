import React, { useState, useEffect } from 'react';
import { ScreenType, UserProfile, SecurityTarget, AuditLogEntry, InvestigationVerdict } from './types';
import { DEFAULT_USERS, INITIAL_TARGETS, INITIAL_AUDIT_LOGS } from './data/mockData';
import { Header } from './components/common/Header';
import { Sidebar } from './components/common/Sidebar';
import { CopilotScreen } from './components/screens/CopilotScreen';
import { IOCManagerScreen } from './components/screens/IOCManagerScreen';
import { SecurityIntelligenceScreen } from './components/screens/SecurityIntelligenceScreen';
import { ThreatIntelScreen } from './components/screens/ThreatIntelScreen';
import { InvestigationsScreen } from './components/screens/InvestigationsScreen';
import { AgentWorkflowsScreen } from './components/screens/AgentWorkflowsScreen';
import { RAGCoreScreen } from './components/screens/RAGCoreScreen';
import { TargetInventoryScreen } from './components/targets/TargetInventoryScreen';
import { AuthModal } from './components/auth/AuthModal';
import { TargetInputModal } from './components/targets/TargetInputModal';
import { CommandPalette } from './components/common/CommandPalette';
import { SystemStatusModal } from './components/common/SystemStatusModal';
import { AuditLogModal } from './components/common/AuditLogModal';
import { CheckCircle2, ShieldCheck, Crosshair } from 'lucide-react';

export default function App() {
  const [currentScreen, setCurrentScreen] = useState<ScreenType>('copilot');

  // Authentication State
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(() => {
    try {
      const saved = localStorage.getItem('cipher_user');
      return saved ? JSON.parse(saved) : DEFAULT_USERS[0];
    } catch {
      return DEFAULT_USERS[0];
    }
  });
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [authModalMode, setAuthModalMode] = useState<'login' | 'signup'>('login');

  // Target Inventory State (User Inputs for IP & Targets)
  const [targets, setTargets] = useState<SecurityTarget[]>(() => {
    try {
      const saved = localStorage.getItem('cipher_targets');
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  const [activeTarget, setActiveTarget] = useState<SecurityTarget | null>(() => {
    try {
      const saved = localStorage.getItem('cipher_targets');
      if (saved) {
        const parsed = JSON.parse(saved);
        return parsed.length > 0 ? parsed[0] : null;
      }
      return null;
    } catch {
      return null;
    }
  });

  const [isTargetModalOpen, setIsTargetModalOpen] = useState(false);

  // Command Palette & Modal States
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);
  const [isSystemStatusOpen, setIsSystemStatusOpen] = useState(false);
  const [isAuditLogOpen, setIsAuditLogOpen] = useState(false);
  const [isMobileSidebarOpen, setIsMobileSidebarOpen] = useState(false);

  // Audit Logs State
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>(() => {
    try {
      const saved = localStorage.getItem('cipher_audit_logs');
      return saved ? JSON.parse(saved) : INITIAL_AUDIT_LOGS;
    } catch {
      return INITIAL_AUDIT_LOGS;
    }
  });

  // Global Toast Notification
  const [toast, setToast] = useState<{ message: string; type?: 'success' | 'target' | 'auth' } | null>(null);

  const showToast = (message: string, type: 'success' | 'target' | 'auth' = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 3800);
  };

  // Keyboard shortcut for Command Palette: Ctrl+K / Cmd+K
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsCommandPaletteOpen(prev => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Persist targets
  useEffect(() => {
    try {
      localStorage.setItem('cipher_targets', JSON.stringify(targets));
    } catch (e) {
      console.warn('Could not persist targets', e);
    }
  }, [targets]);

  // Persist audit logs
  useEffect(() => {
    try {
      localStorage.setItem('cipher_audit_logs', JSON.stringify(auditLogs));
    } catch (e) {
      console.warn('Could not persist audit logs', e);
    }
  }, [auditLogs]);

  // Persist user
  useEffect(() => {
    try {
      if (currentUser) {
        localStorage.setItem('cipher_user', JSON.stringify(currentUser));
      } else {
        localStorage.removeItem('cipher_user');
      }
    } catch (e) {
      console.warn('Could not persist user', e);
    }
  }, [currentUser]);

  // Record Audit Event Helper
  const handleRecordAudit = (event: AuditLogEntry['event'], details: string) => {
    const newEntry: AuditLogEntry = {
      id: `aud-${Date.now()}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC',
      event,
      actor: currentUser?.name || 'Autonomous SecOps Copilot',
      details,
      classification: currentUser?.clearanceLevel.includes('Top Secret') ? 'TLP:RED' : 'TLP:AMBER'
    };
    setAuditLogs(prev => [newEntry, ...prev]);
  };

  // Auth Handlers
  const handleOpenAuth = (mode: 'login' | 'signup' = 'login') => {
    setAuthModalMode(mode);
    setIsAuthModalOpen(true);
  };

  const handleAuthenticate = (user: UserProfile) => {
    setCurrentUser(user);
    handleRecordAudit('LOGIN', `User session initiated for ${user.name} (${user.role}, Clearance: ${user.clearanceLevel})`);
    showToast(`Authenticated as ${user.name} (${user.clearanceLevel})`, 'auth');
  };

  const handleLogout = () => {
    if (currentUser) {
      handleRecordAudit('LOGOUT', `Analyst ${currentUser.name} signed out of session`);
    }
    setCurrentUser(null);
    showToast('Signed out of SecOps session. Running in guest view.', 'auth');
  };

  // Target Handlers
  const handleAddTarget = (newTarget: SecurityTarget) => {
    // Check if target already exists by value
    const existingIndex = targets.findIndex(t => t.value.toLowerCase() === newTarget.value.toLowerCase());
    if (existingIndex >= 0) {
      // Update existing
      setTargets(prev => {
        const copy = [...prev];
        copy[existingIndex] = { ...copy[existingIndex], ...newTarget };
        return copy;
      });
      setActiveTarget(newTarget);
      handleRecordAudit('TARGET_ADDED', `Updated target observable ${newTarget.value} (${newTarget.label})`);
      showToast(`Target ${newTarget.value} updated in active inventory`, 'target');
    } else {
      setTargets(prev => [newTarget, ...prev]);
      setActiveTarget(newTarget);
      handleRecordAudit('TARGET_ADDED', `Ingested target observable ${newTarget.value} (${newTarget.type}, ${newTarget.environment})`);
      showToast(`Target ${newTarget.value} ingested and set as Active Investigation Scope`, 'target');
    }
  };

  const handleAddBulkTargets = (newTargets: SecurityTarget[]) => {
    setTargets(prev => [...newTargets, ...prev]);
    if (newTargets.length > 0) {
      setActiveTarget(newTargets[0]);
    }
    handleRecordAudit('TARGET_ADDED', `Bulk ingested ${newTargets.length} target observables into inventory`);
    showToast(`Ingested ${newTargets.length} targets into active inventory.`, 'target');
  };

  const handleDeleteTarget = (id: string) => {
    setTargets(prev => {
      const filtered = prev.filter(t => t.id !== id);
      if (activeTarget?.id === id) {
        setActiveTarget(filtered.length > 0 ? filtered[0] : null);
      }
      return filtered;
    });
    showToast('Target removed from inventory.', 'target');
  };

  const handleClearAllTargets = () => {
    setTargets([]);
    setActiveTarget(null);
    try {
      localStorage.removeItem('cipher_targets');
    } catch (e) {
      console.warn('Could not clear targets', e);
    }
    showToast('All targets removed. Target inventory is clean.', 'target');
    handleRecordAudit('TARGET_ADDED', 'Analyst cleared all targets from scope inventory');
  };

  const handleLoadSampleTargets = () => {
    setTargets(INITIAL_TARGETS);
    setActiveTarget(INITIAL_TARGETS[0]);
    showToast('Sample intelligence targets loaded into inventory.', 'target');
  };

  const handleSelectActiveTarget = (target: SecurityTarget) => {
    setActiveTarget(target);
    showToast(`Active target scope switched to: ${target.value}`, 'target');
  };

  const handleSaveIOC = (iocValue: string, type = 'ipv4') => {
    handleRecordAudit('IOC_SAVED', `Added observable ${iocValue} (${type.toUpperCase()}) to Threat Ledger`);
    showToast(`Saved indicator ${iocValue} to IOC Threat Ledger`, 'success');
  };

  const handleSaveCase = (verdict: InvestigationVerdict) => {
    handleRecordAudit('INVESTIGATION_STARTED', `Compiled forensic case file for target ${verdict.target} (Threat: ${verdict.threatLevel})`);
    showToast(`Forensic case file recorded for ${verdict.target}`, 'success');
  };

  const handleNavigate = (screen: ScreenType) => {
    setCurrentScreen(screen);
    setIsMobileSidebarOpen(false);
  };

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-[#080b11] text-slate-100 antialiased font-sans">
      {/* Toast Notification Banner */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 bg-[#0a1120]/95 border border-cyan-500/50 text-slate-100 px-4 py-3 rounded-xl shadow-2xl backdrop-blur-md font-mono text-xs animate-in fade-in slide-in-from-bottom-2">
          {toast.type === 'auth' ? (
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
          ) : toast.type === 'target' ? (
            <Crosshair className="w-4 h-4 text-cyan-400 shrink-0" />
          ) : (
            <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
          )}
          <span>{toast.message}</span>
        </div>
      )}

      {/* Top System Header */}
      <Header 
        currentScreen={currentScreen} 
        onNavigate={handleNavigate}
        currentUser={currentUser}
        onOpenAuthModal={handleOpenAuth}
        onLogout={handleLogout}
        activeTarget={activeTarget}
        targets={targets}
        onSelectActiveTarget={handleSelectActiveTarget}
        onOpenAddTargetModal={() => setIsTargetModalOpen(true)}
        onToggleMobileSidebar={() => setIsMobileSidebarOpen(prev => !prev)}
        isMobileSidebarOpen={isMobileSidebarOpen}
        onOpenCommandPalette={() => setIsCommandPaletteOpen(true)}
        onOpenSystemStatus={() => setIsSystemStatusOpen(true)}
        onOpenAuditLog={() => setIsAuditLogOpen(true)}
        onClearActiveTarget={() => setActiveTarget(null)}
      />

      {/* Main App Workspace */}
      <div className="flex-1 flex overflow-hidden">
        {/* Navigation Sidebar */}
        <Sidebar 
          currentScreen={currentScreen} 
          onNavigate={handleNavigate} 
          isMobileOpen={isMobileSidebarOpen}
          onCloseMobile={() => setIsMobileSidebarOpen(false)}
          onOpenSystemStatus={() => setIsSystemStatusOpen(true)}
          onOpenAuditLog={() => setIsAuditLogOpen(true)}
        />

        {/* Dynamic Screen View */}
        <main className="flex-1 flex overflow-hidden bg-[#080b11]">
          {currentScreen === 'copilot' && (
            <CopilotScreen 
              onNavigate={handleNavigate}
              activeTarget={activeTarget}
              onOpenAddTargetModal={() => setIsTargetModalOpen(true)}
              onSaveTarget={handleAddTarget}
              onSaveIOC={handleSaveIOC}
              onSaveCase={handleSaveCase}
              onRecordAudit={handleRecordAudit}
              onClearActiveTarget={() => setActiveTarget(null)}
            />
          )}

          {currentScreen === 'ioc-manager' && (
            <IOCManagerScreen 
              onNavigate={handleNavigate} 
            />
          )}

          {currentScreen === 'security-intel' && (
            <SecurityIntelligenceScreen 
              onNavigate={handleNavigate} 
            />
          )}

          {currentScreen === 'target-inventory' && (
            <TargetInventoryScreen 
              targets={targets}
              activeTarget={activeTarget}
              onSelectActiveTarget={handleSelectActiveTarget}
              onOpenAddModal={() => setIsTargetModalOpen(true)}
              onDeleteTarget={handleDeleteTarget}
              onClearAllTargets={handleClearAllTargets}
              onLoadSampleTargets={handleLoadSampleTargets}
              onNavigate={handleNavigate}
            />
          )}

          {currentScreen === 'threat-intel' && (
            <ThreatIntelScreen 
              onNavigate={handleNavigate} 
            />
          )}

          {currentScreen === 'investigations' && (
            <InvestigationsScreen 
              onNavigate={handleNavigate} 
            />
          )}

          {currentScreen === 'agent-workflows' && (
            <AgentWorkflowsScreen 
              onNavigate={handleNavigate} 
            />
          )}

          {currentScreen === 'rag-core' && (
            <RAGCoreScreen 
              onNavigate={handleNavigate} 
            />
          )}
        </main>
      </div>

      {/* Global Command Palette (Ctrl+K / Cmd+K) */}
      <CommandPalette 
        isOpen={isCommandPaletteOpen}
        onClose={() => setIsCommandPaletteOpen(false)}
        onNavigate={handleNavigate}
        targets={targets}
        onSelectTarget={handleSelectActiveTarget}
        onOpenAddTargetModal={() => setIsTargetModalOpen(true)}
        onOpenSystemStatus={() => setIsSystemStatusOpen(true)}
        onOpenAuditLog={() => setIsAuditLogOpen(true)}
      />

      {/* System Status & Connector Health Modal */}
      <SystemStatusModal 
        isOpen={isSystemStatusOpen}
        onClose={() => setIsSystemStatusOpen(false)}
      />

      {/* Security Audit Log Modal */}
      <AuditLogModal 
        isOpen={isAuditLogOpen}
        onClose={() => setIsAuditLogOpen(false)}
        auditLogs={auditLogs}
      />

      {/* Auth Modal (Login / Signup) */}
      <AuthModal 
        isOpen={isAuthModalOpen}
        initialMode={authModalMode}
        onClose={() => setIsAuthModalOpen(false)}
        onAuthenticate={handleAuthenticate}
      />

      {/* Target Input Modal (User IP & Target Inputs with duplicate detection) */}
      <TargetInputModal 
        isOpen={isTargetModalOpen}
        onClose={() => setIsTargetModalOpen(false)}
        onAddTarget={handleAddTarget}
        onAddBulkTargets={handleAddBulkTargets}
        currentUser={currentUser?.name || 'SecOps Analyst'}
        existingTargets={targets}
      />
    </div>
  );
}
