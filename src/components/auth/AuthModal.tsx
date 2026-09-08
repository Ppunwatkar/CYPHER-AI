import React, { useState } from 'react';
import { 
  Lock, 
  ShieldCheck, 
  User, 
  Mail, 
  Key, 
  Building, 
  Fingerprint, 
  CheckCircle2, 
  X, 
  Sparkles, 
  ArrowRight,
  ShieldAlert,
  Eye,
  EyeOff
} from 'lucide-react';
import { UserProfile } from '../../types';
import { DEFAULT_USERS } from '../../data/mockData';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAuthenticate: (user: UserProfile) => void;
  initialMode?: 'login' | 'signup';
}

export const AuthModal: React.FC<AuthModalProps> = ({
  isOpen,
  onClose,
  onAuthenticate,
  initialMode = 'login'
}) => {
  const [mode, setMode] = useState<'login' | 'signup'>(initialMode);
  
  // Login fields
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [fido2Enabled, setFido2Enabled] = useState(true);
  const [rememberMe, setRememberMe] = useState(true);

  // Signup fields
  const [name, setName] = useState('');
  const [signupEmail, setSignupEmail] = useState('');
  const [organization, setOrganization] = useState('');
  const [role, setRole] = useState('Incident Responder');
  const [clearance, setClearance] = useState<UserProfile['clearanceLevel']>('TLP:RED');
  const [signupPassword, setSignupPassword] = useState('');

  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleQuickLogin = (user: UserProfile) => {
    setIsLoading(true);
    setErrorMessage(null);
    setTimeout(() => {
      onAuthenticate(user);
      setIsLoading(false);
      onClose();
    }, 450);
  };

  const handleLoginSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (!loginEmail.trim() || !loginPassword.trim()) {
      setErrorMessage('Please enter your operational email and password.');
      return;
    }

    setIsLoading(true);
    setTimeout(() => {
      // Find matching default user or create session
      const matched = DEFAULT_USERS.find(u => u.email.toLowerCase() === loginEmail.toLowerCase());
      const authenticatedUser: UserProfile = matched || {
        id: `user-${Date.now()}`,
        name: loginEmail.split('@')[0].replace('.', ' ').toUpperCase(),
        email: loginEmail,
        role: 'Authenticated Analyst',
        organization: 'Enterprise Cyber Defense',
        clearanceLevel: 'TLP:AMBER',
        avatarInitials: loginEmail.slice(0, 2).toUpperCase(),
        sessionToken: `CIPHER-AUTH-${Math.floor(1000 + Math.random() * 9000)}-TK`,
        createdAt: new Date().toISOString().split('T')[0]
      };

      onAuthenticate(authenticatedUser);
      setIsLoading(false);
      onClose();
    }, 550);
  };

  const handleSignupSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (!name.trim() || !signupEmail.trim() || !signupPassword.trim()) {
      setErrorMessage('Please fill in all mandatory identity fields.');
      return;
    }

    setIsLoading(true);
    setTimeout(() => {
      const initials = name.split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase() || 'AN';
      const newUser: UserProfile = {
        id: `user-${Date.now()}`,
        name: name.trim(),
        email: signupEmail.trim(),
        role: role,
        organization: organization.trim() || 'Global SOC Sentinel Unit',
        clearanceLevel: clearance,
        avatarInitials: initials,
        sessionToken: `CIPHER-SEC-${Math.floor(10000 + Math.random() * 90000)}`,
        createdAt: new Date().toISOString().split('T')[0]
      };

      onAuthenticate(newUser);
      setIsLoading(false);
      onClose();
    }, 600);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-md flex items-center justify-center p-4">
      <div className="w-full max-w-lg bg-[#090d15] border border-slate-700/80 rounded-2xl shadow-2xl overflow-hidden font-mono text-xs animate-in fade-in zoom-in-95 duration-200 flex flex-col max-h-[92vh]">
        
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-800 bg-[#0c111c] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.2)]">
              <Lock className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
                  CIPHER AI Authentication Gate
                </h2>
                <span className="text-[9px] px-1.5 py-0.2 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                  FIDO2 / PKI
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-sans mt-0.5">
                Zero-Trust verified access for SecOps analysts, threat hunters, and administrators
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
        <div className="flex border-b border-slate-800 bg-slate-950/60 p-1.5 text-xs">
          <button
            onClick={() => { setMode('login'); setErrorMessage(null); }}
            className={`flex-1 py-2 rounded-lg font-semibold flex items-center justify-center gap-2 transition-all ${
              mode === 'login' 
                ? 'bg-slate-900 text-cyan-300 border border-slate-700/80 shadow-sm' 
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Fingerprint className="w-3.5 h-3.5" />
            <span>Sign In (Analyst Login)</span>
          </button>
          <button
            onClick={() => { setMode('signup'); setErrorMessage(null); }}
            className={`flex-1 py-2 rounded-lg font-semibold flex items-center justify-center gap-2 transition-all ${
              mode === 'signup' 
                ? 'bg-slate-900 text-cyan-300 border border-slate-700/80 shadow-sm' 
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Sign Up (Register Analyst)</span>
          </button>
        </div>

        {/* Form Body */}
        <div className="p-6 space-y-5 max-h-[75vh] overflow-y-auto">
          {errorMessage && (
            <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-500/40 text-rose-300 flex items-center gap-2 text-xs">
              <ShieldAlert className="w-4 h-4 shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}

          {mode === 'login' ? (
            /* ================= LOGIN MODE ================= */
            <div className="space-y-4">
              {/* Quick Login Presets */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-[11px] text-slate-400">
                  <span className="uppercase tracking-wider">Demo Workspace Presets (1-Click)</span>
                  <span className="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 text-[9px] font-semibold">DEMO WORKSPACE</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2">
                  {DEFAULT_USERS.map(user => (
                    <button
                      key={user.id}
                      type="button"
                      onClick={() => handleQuickLogin(user)}
                      className="p-2.5 rounded-xl bg-slate-900/90 hover:bg-slate-800/90 border border-slate-800 hover:border-cyan-500/40 text-left transition-all group flex flex-col justify-between"
                    >
                      <div className="flex items-center gap-2">
                        <div className="w-6 h-6 rounded-md bg-cyan-950 border border-cyan-500/30 text-cyan-300 flex items-center justify-center text-[10px] font-bold">
                          {user.avatarInitials}
                        </div>
                        <span className="font-semibold text-slate-200 text-xs truncate group-hover:text-cyan-300">
                          {user.name.split(' ')[0]}
                        </span>
                      </div>
                      <div className="text-[10px] text-slate-400 truncate mt-1">
                        {user.role}
                      </div>
                      <div className="text-[9px] text-amber-400/90 font-mono mt-0.5">
                        {user.clearanceLevel}
                      </div>
                    </button>
                  ))}
                </div>
              </div>

              <div className="relative flex items-center my-3">
                <div className="flex-grow border-t border-slate-800"></div>
                <span className="flex-shrink mx-3 text-[10px] text-slate-500 uppercase">Or Operational Sign In</span>
                <div className="flex-grow border-t border-slate-800"></div>
              </div>

              <form onSubmit={handleLoginSubmit} className="space-y-3.5">
                <div>
                  <label className="block text-slate-400 mb-1 text-[11px]">
                    Operational Email / Analyst Handle
                  </label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
                    <input
                      type="email"
                      value={loginEmail}
                      onChange={(e) => setLoginEmail(e.target.value)}
                      placeholder="e.g. sarah.chen@sentinel-defense.internal"
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-3 py-2 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 text-[11px]">
                    Zero-Trust Access Passphrase
                  </label>
                  <div className="relative">
                    <Key className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
                    <input
                      type={showPassword ? 'text' : 'password'}
                      value={loginPassword}
                      onChange={(e) => setLoginPassword(e.target.value)}
                      placeholder="••••••••••••••••"
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-10 py-2 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300"
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* 2FA Toggle & Remember Me */}
                <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-2">
                  <label className="flex items-center justify-between cursor-pointer">
                    <div className="flex items-center gap-2">
                      <Fingerprint className="w-3.5 h-3.5 text-cyan-400" />
                      <div className="flex items-center gap-1.5">
                        <span className="text-slate-300 text-[11px]">Security Key / WebAuthn</span>
                        <span className="text-[9px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700">COMING SOON</span>
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      checked={fido2Enabled}
                      disabled
                      onChange={(e) => setFido2Enabled(e.target.checked)}
                      className="rounded border-slate-700 text-cyan-500 focus:ring-0 w-3.5 h-3.5 opacity-50 cursor-not-allowed"
                    />
                  </label>
                  <label className="flex items-center justify-between cursor-pointer">
                    <span className="text-slate-400 text-[10px]">Persist SecOps session token locally</span>
                    <input
                      type="checkbox"
                      checked={rememberMe}
                      onChange={(e) => setRememberMe(e.target.checked)}
                      className="rounded border-slate-700 text-cyan-500 focus:ring-0 w-3.5 h-3.5"
                    />
                  </label>
                </div>

                <button
                  type="submit"
                  disabled={isLoading}
                  className="w-full py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-semibold flex items-center justify-center gap-2 transition-all shadow-lg disabled:opacity-50"
                >
                  {isLoading ? (
                    <span>Verifying Cryptographic Tokens...</span>
                  ) : (
                    <>
                      <span>Authorize Analyst Session</span>
                      <ArrowRight className="w-4 h-4" />
                    </>
                  )}
                </button>
              </form>
            </div>
          ) : (
            /* ================= SIGNUP MODE ================= */
            <form onSubmit={handleSignupSubmit} className="space-y-3.5">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1 text-[11px]">
                    Analyst Full Name *
                  </label>
                  <div className="relative">
                    <User className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
                    <input
                      type="text"
                      required
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="e.g. Alex Rivera"
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-3 py-2 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 text-[11px]">
                    Work / Defense Email *
                  </label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
                    <input
                      type="email"
                      required
                      value={signupEmail}
                      onChange={(e) => setSignupEmail(e.target.value)}
                      placeholder="alex.r@soc.defense.net"
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-3 py-2 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1 text-[11px]">
                    Organization / Defense Unit
                  </label>
                  <div className="relative">
                    <Building className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
                    <input
                      type="text"
                      value={organization}
                      onChange={(e) => setOrganization(e.target.value)}
                      placeholder="e.g. Cyber Command Taskforce"
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-3 py-2 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 text-[11px]">
                    Operational Role
                  </label>
                  <select
                    value={role}
                    onChange={(e) => setRole(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="Security Analyst">Security Analyst</option>
                    <option value="Threat Hunter">Threat Hunter</option>
                    <option value="Incident Responder">Incident Responder</option>
                    <option value="Security Engineer">Security Engineer</option>
                    <option value="CISO">CISO</option>
                    <option value="Administrator">Administrator</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1 text-[11px]">
                    Workspace Classification Tier
                  </label>
                  <select
                    value={clearance}
                    onChange={(e) => setClearance(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-amber-300 focus:outline-none focus:border-cyan-500 font-semibold"
                  >
                    <option value="TLP:RED">TLP:RED (Strictly Restricted)</option>
                    <option value="TLP:AMBER">TLP:AMBER (Limited Disclosure)</option>
                    <option value="TLP:GREEN">TLP:GREEN (Community Shareable)</option>
                    <option value="TLP:CLEAR">TLP:CLEAR (Unrestricted / Public)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 text-[11px]">
                    Passphrase *
                  </label>
                  <div className="relative">
                    <Key className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
                    <input
                      type={showPassword ? 'text' : 'password'}
                      required
                      value={signupPassword}
                      onChange={(e) => setSignupPassword(e.target.value)}
                      placeholder="Minimum 8 characters"
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-10 py-2 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300"
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="w-full mt-2 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-semibold flex items-center justify-center gap-2 transition-all shadow-lg disabled:opacity-50"
              >
                {isLoading ? (
                  <span>Generating PKI Certificate & Provisioning...</span>
                ) : (
                  <>
                    <ShieldCheck className="w-4 h-4" />
                    <span>Create Analyst Account & Issue Token</span>
                  </>
                )}
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};
