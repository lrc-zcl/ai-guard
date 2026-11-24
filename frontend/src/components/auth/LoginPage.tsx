import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Loader2, Lock, User } from 'lucide-react';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { useAuth } from '../../context/AuthContext';
import { AuthError } from '../../lib/authApi';
import LanguageSwitcher from '../LanguageSwitcher';

const LoginPage: React.FC = () => {
  const { t } = useTranslation();
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const baseUrl = import.meta.env.BASE_URL || '/';
  const logoSrc = `${baseUrl.replace(/\/$/, '')}/images/logo.png`;

  const errorMessage = (err: unknown): string => {
    if (err instanceof AuthError) {
      switch (err.code) {
        case 'invalid_credentials':
          return t('auth.invalidCredentials');
        case 'too_many_attempts':
          return t('auth.tooManyAttempts');
        case 'network':
          return t('auth.networkError');
      }
    }
    return t('auth.loginFailed');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (submitting) return;
    if (!username.trim() || !password) {
      setError(t('auth.required'));
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await login(username.trim(), password);
    } catch (err) {
      setError(errorMessage(err));
      setPassword('');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-100 flex flex-col items-center justify-center px-4">
      <div className="absolute top-4 right-4">
        <LanguageSwitcher />
      </div>

      <div className="w-full max-w-sm bg-white rounded-xl shadow-sm border border-gray-200 p-8">
        <div className="flex flex-col items-center mb-6">
          <img src={logoSrc} alt="A.I.G" className="w-12 h-12 mb-3" />
          <h1 className="text-xl font-semibold text-gray-900">AI-Infra-Guard</h1>
          <p className="text-sm text-gray-500 mt-1">{t('auth.subtitle')}</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4" noValidate>
          <div>
            <label htmlFor="aig-username" className="block text-sm font-medium text-gray-700 mb-1">
              {t('auth.username')}
            </label>
            <div className="relative">
              <User className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <Input
                id="aig-username"
                autoFocus
                autoComplete="username"
                value={username}
                onChange={e => setUsername(e.target.value)}
                className="pl-9"
                disabled={submitting}
              />
            </div>
          </div>

          <div>
            <label htmlFor="aig-password" className="block text-sm font-medium text-gray-700 mb-1">
              {t('auth.password')}
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <Input
                id="aig-password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="pl-9"
                disabled={submitting}
              />
            </div>
          </div>

          {error && (
            <p role="alert" className="text-sm text-red-600 bg-red-50 border border-red-100 rounded-md px-3 py-2">
              {error}
            </p>
          )}

          <Button type="submit" className="w-full" disabled={submitting}>
            {submitting && <Loader2 className="w-4 h-4 animate-spin" />}
            {submitting ? t('auth.loggingIn') : t('auth.login')}
          </Button>
        </form>
      </div>
    </div>
  );
};

export default LoginPage;
