import React, { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { AlertTriangle, Check, Copy, KeyRound, Loader2, Plus, Trash2 } from 'lucide-react';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '../ui/alert-dialog';
import { ApiKeyItem, AuthError, authApi } from '../../lib/authApi';

const DAY_MS = 24 * 60 * 60 * 1000;
const CUSTOM = 'custom';
const EXPIRY_PRESETS = [7, 30, 90, 180, 365];

/** yyyy-MM-dd for the <input type="date"> min attribute */
function toDateInputValue(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

type KeyStatus = 'active' | 'expired' | 'revoked';

function keyStatus(key: ApiKeyItem, now: number): KeyStatus {
  if (key.revoked) return 'revoked';
  if (key.expires_at <= now) return 'expired';
  return 'active';
}

const STATUS_STYLE: Record<KeyStatus, string> = {
  active: 'bg-green-100 text-green-700',
  expired: 'bg-gray-100 text-gray-600',
  revoked: 'bg-red-100 text-red-700',
};

const ApiKeyManagement: React.FC = () => {
  const { t } = useTranslation();
  const [keys, setKeys] = useState<ApiKeyItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadFailed, setLoadFailed] = useState(false);

  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState('');
  const [preset, setPreset] = useState<string>('30');
  const [customDate, setCustomDate] = useState('');
  const [creating, setCreating] = useState(false);

  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<ApiKeyItem | null>(null);

  const loadKeys = useCallback(async () => {
    setLoading(true);
    setLoadFailed(false);
    try {
      setKeys(await authApi.listApiKeys());
    } catch {
      setLoadFailed(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadKeys();
  }, [loadKeys]);

  const resolveExpiry = (): number | null => {
    if (preset !== CUSTOM) {
      return Date.now() + Number(preset) * DAY_MS;
    }
    if (!customDate) return null;
    // Valid through the end of the chosen day, in the browser's time zone
    const end = new Date(`${customDate}T23:59:59`).getTime();
    return Number.isNaN(end) ? null : end;
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (creating) return;
    const trimmed = name.trim();
    if (!trimmed) {
      toast.error(t('apiKeys.nameRequired'));
      return;
    }
    const expiresAt = resolveExpiry();
    if (expiresAt === null || expiresAt <= Date.now()) {
      toast.error(t('apiKeys.expiryInvalid'));
      return;
    }

    setCreating(true);
    try {
      const created = await authApi.createApiKey({ name: trimmed, expires_at: expiresAt });
      setCreatedKey(created.api_key);
      setCopied(false);
      setShowForm(false);
      setName('');
      setCustomDate('');
      setPreset('30');
      await loadKeys();
    } catch (err) {
      const code = err instanceof AuthError ? err.code : 'unknown';
      toast.error(
        code === 'invalid_name'
          ? t('apiKeys.nameRequired')
          : code === 'invalid_expiry'
            ? t('apiKeys.expiryInvalid')
            : t('apiKeys.createFailed'),
      );
    } finally {
      setCreating(false);
    }
  };

  const handleCopy = async () => {
    if (!createdKey) return;
    try {
      await navigator.clipboard.writeText(createdKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API is unavailable on plain http: the key stays selectable in the box
      toast.error(t('apiKeys.copyFailed'));
    }
  };

  const handleRevoke = async () => {
    if (!revokeTarget) return;
    const target = revokeTarget;
    setRevokeTarget(null);
    try {
      await authApi.revokeApiKey(target.id);
      toast.success(t('apiKeys.revoked'));
      await loadKeys();
    } catch {
      toast.error(t('apiKeys.revokeFailed'));
    }
  };

  const formatTime = (ms: number) => new Date(ms).toLocaleString();
  const now = Date.now();

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-5">
      {/* Intro + create button */}
      <div className="flex items-start justify-between gap-4">
        <p className="text-sm text-gray-600 leading-relaxed">{t('apiKeys.intro')}</p>
        {!showForm && (
          <Button onClick={() => setShowForm(true)} className="flex-shrink-0">
            <Plus className="w-4 h-4" />
            {t('apiKeys.create')}
          </Button>
        )}
      </div>

      {/* Create form */}
      {showForm && (
        <form onSubmit={handleCreate} className="border border-gray-200 rounded-lg p-4 space-y-4 bg-gray-50">
          <div>
            <label htmlFor="aig-key-name" className="block text-sm font-medium text-gray-700 mb-1">
              {t('apiKeys.name')}
            </label>
            <Input
              id="aig-key-name"
              autoFocus
              maxLength={128}
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder={t('apiKeys.namePlaceholder')}
              disabled={creating}
              className="bg-white"
            />
          </div>

          <div>
            <span className="block text-sm font-medium text-gray-700 mb-1">{t('apiKeys.expiry')}</span>
            <div className="flex flex-wrap items-center gap-2">
              {EXPIRY_PRESETS.map(days => (
                <button
                  key={days}
                  type="button"
                  onClick={() => setPreset(String(days))}
                  disabled={creating}
                  className={`px-3 py-1.5 rounded-md text-sm border transition-colors ${
                    preset === String(days)
                      ? 'bg-zinc-900 text-white border-zinc-900'
                      : 'bg-white text-gray-700 border-gray-200 hover:bg-gray-100'
                  }`}
                >
                  {t('apiKeys.days', { n: days })}
                </button>
              ))}
              <button
                type="button"
                onClick={() => setPreset(CUSTOM)}
                disabled={creating}
                className={`px-3 py-1.5 rounded-md text-sm border transition-colors ${
                  preset === CUSTOM
                    ? 'bg-zinc-900 text-white border-zinc-900'
                    : 'bg-white text-gray-700 border-gray-200 hover:bg-gray-100'
                }`}
              >
                {t('apiKeys.customDate')}
              </button>
              {preset === CUSTOM && (
                <Input
                  type="date"
                  value={customDate}
                  min={toDateInputValue(Date.now() + DAY_MS)}
                  onChange={e => setCustomDate(e.target.value)}
                  disabled={creating}
                  className="w-44 bg-white"
                />
              )}
            </div>
          </div>

          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={() => setShowForm(false)} disabled={creating}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={creating}>
              {creating && <Loader2 className="w-4 h-4 animate-spin" />}
              {t('apiKeys.createConfirm')}
            </Button>
          </div>
        </form>
      )}

      {/* Newly created key: the plaintext is only shown here, once */}
      {createdKey && (
        <div className="border border-amber-300 bg-amber-50 rounded-lg p-4 space-y-3">
          <div className="flex items-center gap-2 text-amber-800 text-sm font-medium">
            <AlertTriangle className="w-4 h-4" />
            {t('apiKeys.copyNow')}
          </div>
          <div className="flex items-center gap-2">
            <code
              data-testid="new-api-key"
              className="flex-1 min-w-0 break-all select-all bg-white border border-amber-200 rounded-md px-3 py-2 text-sm font-mono"
            >
              {createdKey}
            </code>
            <Button type="button" variant="outline" onClick={handleCopy} className="flex-shrink-0">
              {copied ? <Check className="w-4 h-4 text-green-600" /> : <Copy className="w-4 h-4" />}
              {copied ? t('apiKeys.copied') : t('apiKeys.copy')}
            </Button>
          </div>
          <p className="text-xs text-gray-600">{t('apiKeys.usageHint')}</p>
          <pre className="text-xs bg-white border border-amber-200 rounded-md p-3 overflow-x-auto">
{`curl -H "X-API-Key: ${createdKey}" ${window.location.origin}/api/v1/app/taskapi/status/<task-id>`}
          </pre>
          <div className="flex justify-end">
            <Button type="button" variant="ghost" size="sm" onClick={() => setCreatedKey(null)}>
              {t('apiKeys.savedIt')}
            </Button>
          </div>
        </div>
      )}

      {/* List */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-12 text-gray-400">
            <Loader2 className="w-5 h-5 animate-spin" />
          </div>
        ) : loadFailed ? (
          <div className="flex flex-col items-center gap-3 py-12 text-sm text-gray-500">
            {t('apiKeys.loadFailed')}
            <Button variant="outline" size="sm" onClick={loadKeys}>
              {t('common.refresh')}
            </Button>
          </div>
        ) : keys.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-12 text-sm text-gray-400">
            <KeyRound className="w-8 h-8" />
            {t('apiKeys.empty')}
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-gray-500 text-left">
              <tr>
                <th className="px-4 py-2 font-medium">{t('apiKeys.name')}</th>
                <th className="px-4 py-2 font-medium">{t('apiKeys.key')}</th>
                <th className="px-4 py-2 font-medium">{t('apiKeys.expiresAt')}</th>
                <th className="px-4 py-2 font-medium">{t('apiKeys.lastUsed')}</th>
                <th className="px-4 py-2 font-medium">{t('apiKeys.status')}</th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {keys.map(key => {
                const status = keyStatus(key, now);
                return (
                  <tr key={key.id} className="hover:bg-gray-50/60">
                    <td className="px-4 py-3 font-medium text-gray-800 max-w-[160px] truncate" title={key.name}>
                      {key.name}
                    </td>
                    <td className="px-4 py-3 font-mono text-gray-500">{key.prefix}…</td>
                    <td className="px-4 py-3 text-gray-600 whitespace-nowrap">{formatTime(key.expires_at)}</td>
                    <td className="px-4 py-3 text-gray-600 whitespace-nowrap">
                      {key.last_used_at ? formatTime(key.last_used_at) : t('apiKeys.neverUsed')}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded-full text-xs ${STATUS_STYLE[status]}`}>
                        {t(`apiKeys.status_${status}`)}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      {status === 'active' && (
                        <Button
                          variant="outline"
                          size="icon"
                          className="text-red-600 hover:text-red-700"
                          title={t('apiKeys.revoke')}
                          aria-label={t('apiKeys.revoke')}
                          onClick={() => setRevokeTarget(key)}
                        >
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Revoke confirmation */}
      <AlertDialog open={revokeTarget !== null} onOpenChange={open => !open && setRevokeTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('apiKeys.revokeTitle')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('apiKeys.revokeDescription', { name: revokeTarget?.name ?? '' })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction onClick={handleRevoke} className="bg-red-600 hover:bg-red-700">
              {t('apiKeys.revoke')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
};

export default ApiKeyManagement;
