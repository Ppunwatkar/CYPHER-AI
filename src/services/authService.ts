/**
 * CIPHER AI - Client Authentication Service
 * Communicates with FastAPI /api/v1/auth endpoints using secure HttpOnly cookies.
 */

import { UserProfile } from '../types';

export interface RegisterPayload {
  email: string;
  password: string;
  display_name: string;
  organization_name?: string;
  role_name?: string;
  clearance_level?: string;
}

export interface LoginPayload {
  email: string;
  password: string;
}

function mapClearanceToBackend(frontClearance?: string): string {
  switch (frontClearance) {
    case 'TOP SECRET // TS-SCI':
      return 'TOP_SECRET';
    case 'TLP:RED':
      return 'SECRET';
    case 'TLP:AMBER':
      return 'CONFIDENTIAL';
    case 'TLP:GREEN':
      return 'RESTRICTED';
    case 'TLP:CLEAR':
      return 'UNCLASSIFIED';
    default:
      return 'UNCLASSIFIED';
  }
}

export function mapUserAuthResponseToUserProfile(authUser: any): UserProfile {
  const initials = authUser.display_name
    ? authUser.display_name
        .split(' ')
        .map((n: string) => n[0])
        .join('')
        .slice(0, 2)
        .toUpperCase()
    : authUser.email.slice(0, 2).toUpperCase();

  // Map backend clearance to frontend visual indicator
  let clearance: UserProfile['clearanceLevel'] = 'TLP:AMBER';
  if (authUser.clearance_level === 'TOP_SECRET') {
    clearance = 'TOP SECRET // TS-SCI';
  } else if (authUser.clearance_level === 'SECRET') {
    clearance = 'TLP:RED';
  } else if (authUser.clearance_level === 'CONFIDENTIAL') {
    clearance = 'TLP:AMBER';
  } else if (authUser.clearance_level === 'RESTRICTED') {
    clearance = 'TLP:GREEN';
  } else if (authUser.clearance_level === 'UNCLASSIFIED') {
    clearance = 'TLP:CLEAR';
  }

  return {
    id: authUser.id,
    name: authUser.display_name,
    email: authUser.email,
    role: authUser.roles && authUser.roles.length > 0 ? authUser.roles[0] : 'Security Analyst',
    organization: authUser.organization_name || 'Enterprise SOC',
    clearanceLevel: clearance,
    avatarInitials: initials || 'AN',
    sessionToken: 'CIPHER-HTTPONLY-SESSION',
    createdAt: typeof authUser.created_at === 'string'
      ? authUser.created_at.split('T')[0]
      : new Date().toISOString().split('T')[0],
  };
}

export const authService = {
  async register(payload: RegisterPayload): Promise<UserProfile> {
    const res = await fetch('/api/v1/auth/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
      },
      credentials: 'include',
      body: JSON.stringify({
        ...payload,
        clearance_level: mapClearanceToBackend(payload.clearance_level),
      }),
    });

    const data = await res.json();
    if (!res.ok) {
      const msg = data.error?.message || data.detail || 'Registration failed.';
      throw new Error(msg);
    }
    return mapUserAuthResponseToUserProfile(data);
  },

  async login(payload: LoginPayload): Promise<UserProfile> {
    const res = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
      },
      credentials: 'include',
      body: JSON.stringify(payload),
    });

    const data = await res.json();
    if (!res.ok) {
      const msg = data.error?.message || data.detail || 'Invalid email or password.';
      throw new Error(msg);
    }
    return mapUserAuthResponseToUserProfile(data);
  },

  async logout(): Promise<void> {
    try {
      await fetch('/api/v1/auth/logout', {
        method: 'POST',
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        credentials: 'include',
      });
    } catch (e) {
      console.warn('Logout network error:', e);
    }
  },

  async getMe(): Promise<UserProfile | null> {
    try {
      const res = await fetch('/api/v1/auth/me', {
        method: 'GET',
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        credentials: 'include',
      });
      if (!res.ok) {
        return null;
      }
      const data = await res.json();
      return mapUserAuthResponseToUserProfile(data);
    } catch {
      return null;
    }
  },

  async refresh(): Promise<UserProfile | null> {
    try {
      const res = await fetch('/api/v1/auth/refresh', {
        method: 'POST',
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        credentials: 'include',
      });
      if (!res.ok) {
        return null;
      }
      const data = await res.json();
      return mapUserAuthResponseToUserProfile(data);
    } catch {
      return null;
    }
  },
};
