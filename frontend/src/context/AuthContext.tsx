import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { authApi, AuthUser, UNAUTHORIZED_EVENT } from '../lib/authApi';

interface AuthContextValue {
  user: AuthUser | null;
  /** True until the first "who am I" answer arrives */
  loading: boolean;
  /** Set when the first check failed for a non-auth reason (e.g. the server is unreachable) */
  checkFailed: boolean;
  isAdmin: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  retry: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [checkFailed, setCheckFailed] = useState(false);

  const check = useCallback(async () => {
    setLoading(true);
    setCheckFailed(false);
    try {
      setUser(await authApi.me());
    } catch {
      setUser(null);
      setCheckFailed(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void check();
  }, [check]);

  // Any /api/ 401 (session expired, logged out elsewhere) returns the user to the login page
  useEffect(() => {
    const onUnauthorized = () => setUser(null);
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    setUser(await authApi.login(username, password));
    setCheckFailed(false);
  }, []);

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } finally {
      setUser(null);
    }
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      loading,
      checkFailed,
      isAdmin: user?.role === 'admin',
      login,
      logout,
      retry: () => void check(),
    }),
    [user, loading, checkFailed, login, logout, check],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used inside <AuthProvider>');
  }
  return ctx;
}
