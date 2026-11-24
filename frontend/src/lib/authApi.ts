/**
 * Authentication API.
 *
 * The web UI authenticates with an HttpOnly session cookie set by the login endpoint
 * (the browser sends it automatically, including for EventSource and <img>), so no
 * API key is needed in the browser. API keys are only for external API callers.
 */

const AUTH_BASE_URL = '/api/v1/auth';

/** Fired when an /api/ request comes back 401, i.e. the session is missing or expired. */
export const UNAUTHORIZED_EVENT = 'aig:unauthorized';

export interface AuthUser {
  username: string;
  role: string;
}

export interface ApiKeyItem {
  id: string;
  name: string;
  /** Leading characters of the key, only for recognising it in the list */
  prefix: string;
  created_by: string;
  created_at: number;
  expires_at: number;
  revoked: boolean;
  /** 0 means never used */
  last_used_at: number;
}

export interface CreateApiKeyRequest {
  name: string;
  /** Expiry as a Unix millisecond timestamp */
  expires_at: number;
}

export interface CreatedApiKey {
  /** Plaintext key. The server returns it only once; it cannot be retrieved later. */
  api_key: string;
  key: ApiKeyItem;
}

export type AuthErrorCode =
  | 'invalid_credentials'
  | 'too_many_attempts'
  | 'forbidden'
  | 'invalid_name'
  | 'invalid_expiry'
  | 'network'
  | 'unknown';

export class AuthError extends Error {
  code: AuthErrorCode;
  constructor(code: AuthErrorCode, message?: string) {
    super(message || code);
    this.code = code;
  }
}

interface Envelope<T> {
  status: number;
  message?: string;
  code?: string;
  data?: T;
}

async function parseEnvelope<T>(response: Response): Promise<Envelope<T>> {
  try {
    return (await response.json()) as Envelope<T>;
  } catch {
    return { status: response.status, message: response.statusText };
  }
}

function toAuthError(response: Response, body: Envelope<unknown>): AuthError {
  if (response.status === 429) return new AuthError('too_many_attempts', body.message);
  if (response.status === 403) return new AuthError('forbidden', body.message);
  const known: AuthErrorCode[] = ['invalid_credentials', 'invalid_name', 'invalid_expiry'];
  if (body.code && (known as string[]).includes(body.code)) {
    return new AuthError(body.code as AuthErrorCode, body.message);
  }
  return new AuthError('unknown', body.message);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${AUTH_BASE_URL}${path}`, {
      credentials: 'same-origin',
      ...init,
      headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) },
    });
  } catch {
    throw new AuthError('network');
  }
  const body = await parseEnvelope<T>(response);
  if (!response.ok || (typeof body.status === 'number' && body.status !== 0)) {
    throw toAuthError(response, body);
  }
  return body.data as T;
}

export const authApi = {
  /** Returns the current login, or null when not logged in. */
  async me(): Promise<AuthUser | null> {
    let response: Response;
    try {
      response = await fetch(`${AUTH_BASE_URL}/me`, { credentials: 'same-origin' });
    } catch {
      throw new AuthError('network');
    }
    if (response.status === 401) return null;
    const body = await parseEnvelope<AuthUser>(response);
    if (!response.ok || !body.data) throw toAuthError(response, body);
    return { username: body.data.username, role: body.data.role };
  },

  login(username: string, password: string): Promise<AuthUser> {
    return request<AuthUser>('/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
  },

  async logout(): Promise<void> {
    await request<unknown>('/logout', { method: 'POST' });
  },

  async listApiKeys(): Promise<ApiKeyItem[]> {
    const data = await request<{ items: ApiKeyItem[] }>('/api-keys');
    return data.items || [];
  },

  createApiKey(payload: CreateApiKeyRequest): Promise<CreatedApiKey> {
    return request<CreatedApiKey>('/api-keys', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async revokeApiKey(id: string): Promise<void> {
    await request<unknown>(`/api-keys/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },
};

let interceptorInstalled = false;

/**
 * Wraps window.fetch so that a 401 from any /api/ endpoint (session expired or logged out in
 * another tab) sends the user back to the login page, without touching every call site.
 * The login and "who am I" calls are excluded: a 401 there is an expected answer.
 */
export function installAuthInterceptor(): void {
  if (interceptorInstalled || typeof window === 'undefined') return;
  interceptorInstalled = true;

  const originalFetch = window.fetch.bind(window);
  window.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const response = await originalFetch(input, init);
    if (response.status === 401) {
      try {
        const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        const { pathname } = new URL(raw, window.location.origin);
        const excluded = pathname === `${AUTH_BASE_URL}/login` || pathname === `${AUTH_BASE_URL}/me`;
        if (pathname.startsWith('/api/') && !excluded) {
          window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
        }
      } catch {
        // Unparseable URL: not ours to handle
      }
    }
    return response;
  };
}
