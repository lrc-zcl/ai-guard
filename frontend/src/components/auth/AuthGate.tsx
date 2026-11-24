import React from 'react';
import { useTranslation } from 'react-i18next';
import { Loader2 } from 'lucide-react';
import { Button } from '../ui/button';
import { AuthProvider, useAuth } from '../../context/AuthContext';
import LoginPage from './LoginPage';

const GateContent: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { t } = useTranslation();
  const { user, loading, checkFailed, retry } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-100">
        <Loader2 className="w-6 h-6 text-gray-400 animate-spin" />
      </div>
    );
  }

  // The server could not be reached: show a retry instead of a misleading login form
  if (!user && checkFailed) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-4 bg-gray-100">
        <p className="text-sm text-gray-600">{t('auth.networkError')}</p>
        <Button variant="outline" onClick={retry}>
          {t('common.refresh')}
        </Button>
      </div>
    );
  }

  if (!user) {
    return <LoginPage />;
  }

  return <>{children}</>;
};

/**
 * Requires a logged-in session before rendering the wrapped routes.
 * The session lives in an HttpOnly cookie, so the web UI never handles an API key.
 */
const AuthGate: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <AuthProvider>
    <GateContent>{children}</GateContent>
  </AuthProvider>
);

export default AuthGate;
