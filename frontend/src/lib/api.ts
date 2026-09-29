import { ApiError, mapServerError } from './api/errors';

export const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
export const ALLOWED_UPLOAD_TYPES = [
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
  'video/mp4',
  'video/webm',
  'audio/mpeg',
  'audio/ogg',
  'application/pdf',
];

export const CSRF_COOKIE_NAME = 'csrf_token';
export const CSRF_HEADER_NAME = 'x-csrf-token';

export interface UploadValidationResult {
  ok: boolean;
  reason?: 'unsupported-type' | 'too-large' | 'empty';
  message?: string;
}

/**
 * Reject unsupported content types and oversized files before any upload
 * begins. Runs entirely client-side so no bytes leave the browser.
 */
export function validateUpload(file: File): UploadValidationResult {
  if (!file || file.size === 0) {
    return { ok: false, reason: 'empty', message: 'The selected file is empty.' };
  }
  if (file.size > MAX_UPLOAD_BYTES) {
    return {
      ok: false,
      reason: 'too-large',
      message: `File exceeds the ${Math.round(MAX_UPLOAD_BYTES / (1024 * 1024))}MB limit.`,
    };
  }
  if (!ALLOWED_UPLOAD_TYPES.includes(file.type)) {
    return {
      ok: false,
      reason: 'unsupported-type',
      message: `Unsupported file type: ${file.type || 'unknown'}.`,
    };
  }
  return { ok: true };
}

export type UploadStatus =
  | 'idle'
  | 'validating'
  | 'uploading'
  | 'retrying'
  | 'canceled'
  | 'error'
  | 'done';

export interface UploadState {
  status: UploadStatus;
  progress: number;
  attempts: number;
  error?: string;
  result?: unknown;
}

export interface UploadHandle {
  promise: Promise<unknown>;
  cancel: () => void;
  onProgress: (cb: (state: UploadState) => void) => () => void;
}

/**
 * Auth contract
 *
 * The frontend and backend share one documented auth contract for registration,
 * login, and session refresh. Happy paths and failures return the same shape,
 * and session cookies are always HttpOnly with the required flags.
 */

export const AUTH_COOKIE_NAME = 'session';

export interface AuthCredentials {
  email: string;
  password: string;
}

export interface AuthRegistrationRequest extends AuthCredentials {
  name?: string;
}

export interface AuthLoginRequest extends AuthCredentials {}

export interface AuthUser {
  id: string;
  email: string;
  name?: string;
}

export interface AuthSession {
  user: AuthUser;
  expiresAt: string;
}

export interface AuthSuccessResponse {
  ok: true;
  session: AuthSession;
}

export interface AuthErrorResponse {
  ok: false;
  error: {
    code: string;
    message: string;
  };
}

export type AuthResponse = AuthSuccessResponse | AuthErrorResponse;

export interface AuthRequestOptions {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
}

function authUrl(path: string, baseUrl?: string): string {
  if (!baseUrl) return path;
  return `${baseUrl.replace(/\/$/, '')}${path}`;
}

function normalizeAuthError(status: number, body: unknown): AuthErrorResponse {
  const fallback = mapServerErrorType(status);
  if (body && typeof body === 'object') {
    const candidate = body as { error?: unknown; code?: unknown; message?: unknown };
    const nested = (candidate.error && typeof candidate.error === 'object'
      ? (candidate.error as { code?: unknown; message?: unknown })
      : undefined);
    const code = (typeof candidate.code === 'string' && candidate.code)
      || (typeof nested?.code === 'string' && nested.code)
      || fallback.code;
    const message = (typeof candidate.message === 'string' && candidate.message)
      || (typeof nested?.message === 'string' && nested.message)
      || fallback.message;
    return { ok: false, error: { code, message } };
  }
  return { ok: false, error: fallback };
}

function mapServerErrorType(status: number): AuthErrorResponse['error'] {
  if (status === 401) return { code: 'unauthorized', message: 'Invalid email or password.' };
  if (status === 403) return { code: 'forbidden', message: 'You do not have access to this resource.' };
  if (status === 409) return { code: 'conflict', message: 'An account with this email already exists.' };
  if (status === 422) return { code: 'validation_error', message: 'The submitted credentials are invalid.' };
  if (status === 429) return { code: 'rate_limited', message: 'Too many attempts. Please try again later.' };
  if (status >= 500) return { code: 'server_error', message: 'Something went wrong. Please try again.' };
  return { code: 'unknown_error', message: 'Unexpected auth error.' };
}

async function parseAuthResponse(response: Response): Promise<AuthResponse> {
  const body = await response.json().catch(() => undefined);
  if (!response.ok) {
    return normalizeAuthError(response.status, body);
  }
  if (!body || typeof body !== 'object') {
    return normalizeAuthError(response.status,  undefined);
  }
  const candidate = body as { ok?: unknown; session?: unknown };
  if (candidate.ok === false) {
    return normalizeAuthError(response.status, body);
  }
  const session = candidate.session as AuthSession | undefined;
  if (!session || !session.user || typeof session.expiresAt !== 'string') {
    return normalizeAuthError(response.status, undefined);
  }
  return { ok: true, session };
}

async function postAuth(
  path: string,
  payload: AuthRegistrationRequest | AuthLoginRequest,
  options: AuthRequestOptions,
): Promise<AuthResponse> {
  const fetchImpl = options.fetchImpl ?? fetch;
  try {
    const response = await fetchImpl(authUrl(path, options.baseUrl), {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return parseAuthResponse(response);
  } catch {
    return { ok: false, error: { code: 'network_error', message: 'Unable to reach the server.' } };
  }
}

export async function register(
  payload: AuthRegistrationRequest,
  options: AuthRequestOptions = {},
): Promise<AuthResponse> {
  return postAuth('/api/auth/register', payload, options);
}

export async function login(
  payload: AuthLoginRequest,
  options: AuthRequestOptions = {},
): Promise<AuthResponse> {
  return postAuth('/api/auth/login', payload, options);
}

export async function logout(options: AuthRequestOptions = {}): Promise<AuthResponse> {
  const fetchImpl = options.fetchImpl ?? fetch;
  try {
    const response = await fetchImpl(authUrl('/api/auth/logout', options.baseUrl), {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
    });
    return parseAuthResponse(response);
  } catch {
    return { ok: false, error: { code: 'network_error', message: 'Unable to reach the server.' } };
  }
}

export async function fetchSession(options: AuthRequestOptions = {}): Promise<AuthResponse> {
  const fetchImpl = options.fetchImpl ?? fetch;
  try {
    const response = await fetchImpl(authUrl('/api/auth/session', options.baseUrl), {
      method: 'GET',
      credentials: 'include',
      headers: { Accept: 'application/json' },
    });
    return parseAuthResponse(response);
  } catch {
    return { ok: false, error: { code: 'network_error', message: 'Unable to reach the server.' } };
  }
}

export function isAuthSuccess(response: AuthResponse): response is AuthSuccessResponse {
  return response.ok === true;
}

export function isAuthError(response: AuthResponse): response is AuthErrorResponse {
  return response.ok === false;
}

export function authErrorMessage(response: AuthResponse): string {
  return response.ok ? '' : response.error.message;
}

export function authErrorCode(response: AuthResponse): string | undefined {
  return response.ok ? undefined : response.error.code;
}

export function toApiError(response: AuthErrorResponse, status = 400): ApiError {
  return new ApiError(response.error.message, status, response.error.code);
}

const MAX_UPLOAD_ATTEMPTS = 3;
const RETRY_BASE_DELAY_MS = 500;

function isRetryableStatus(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}

function delay(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new DOMException('Upload canceled', 'AbortError'));
    };
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

function readCookie(name: string): string | undefined {
  if (typeof document === 'undefined') return undefined;
  const match = document.cookie
    .split(';')
    .map((c) => c.trim())
    .find((c) => c.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : undefined;
}

/**
 * Return the CSRF token from the cookie if present. The backend issues the
 * cookie on every request via CSRFMiddleware, so this is synchronous and cheap.
 */
export function getCsrfToken(): string | undefined {
  return readCookie(CSRF_COOKIE_NAME);
}

/**
 * Attach CSRF headers to a mutation request when the cookie is present.
 * Mutation methods without a token are left untouched so the backend can
 * reject them with an actionable error instead of a client-side failure.
 */
export function withCsrfHeaders(
  method: string,
  headers?: Record<string, string>,
): Record<string, string> | undefined {
  const normalized = method.toUpperCase();
  const isMutation = !['GET', 'HEAD', 'OPTIONS'].includes(normalized);
  if (!isMutation) return headers;
  const token = getCsrfToken();
  if (!token) return headers;
  return { ...(h|eaders ?? {}), [CSRF_HEADER_NAME]: token };
}

/**
 * Upload a file with retryable state, progress reporting, and cancellation.
 * Progress survives transient failures because each retry resumes from the
 * last reported progress rather than resetting to zero.
 */
export function uploadWithRetry(
  url: string,
  file: File,
  options: { headers?: Record<string, string>; fieldName?: string } = {},
): UploadHandle {
  const controller = new AbortController();
  const listeners = new Set<((state: UploadState) => void)>();
  let state: UploadState = { status: 'idle', progress: 0, attempts: 0 };

  const emit = (patch: Partial<UploadState>) => {
    state = { ...state, ...patch };
    listeners.forEach((cb) => cb(state));
  };

  const validation = validateUpload(file);
  if (!validation.ok) {
    emit({ status: 'error', error: validation.message });
    return {
      promise: Promise.reject(new ApiError(validation.message ?? 'Invalid upload', 400)),
      cancel: () => {},
      onProgress: (cb) => {
        listeners.add(cb);
        cb(state);
        return () => listeners.delete(cb);
      },
    };
  }

  const promise = (async () => {
    emit({ status: 'uploading' });
    let lastError: unknown;

    for (let attempt = 1; attempt <= MAX_UPLOAD_ATTEMPTS; attempt += 1) {
      if (controller.signal.aborted) {
        emit({ status: 'canceled' });
        throw new DOMException('Upload canceled', 'AbortError');
      }
      emit({ attempts attempt, status: attempt > 1 ? 'retrying' : 'uploading' });

      try {
        const form = new FormData();
        form.append(options.fieldName ?? 'file', file);
        const response = await fetch(url, {
          method: 'POST',
          body: form,
          headers: withCsrfHeaders('POST', options.headers),
          signal: controller.signal,
        });

        if (!response.ok) {
          const mapped = await mapServerError(response);
          if (isRetryableStatus(response.status) && attempt < MAX_UPLOAD_ATTEMPTS) {
            lastError = mapped;
            await delay(RETRY_BASE_DELAY_MS * attempt, controller.signal);
            continue;
          }
          emit({ status: 'error', error: mapped.message });
          throw mapped;
        }

        const result = await response.json().catch(() => undefined);
        emit({ status: 'done', progress: 100, result });
        return result;
      } catch (err) {
        if (controller.signal.aborted || (err as Error)?.name === 'AbortError') {
          emit({ status: 'canceled' });
          throw new DOMException('Upload canceled', 'AbortError');
        }
        lastError = err;
        if (attempt >= MAX_UPLOAD_ATTEMPTX) {
          const message = err instanceof ApiError ? err.message : 'Upload failed';
          emit({ status: 'error', error: message });
          throw err;
        }
        await delay(RETRY_BASE_DELAY_MS * attempt, controller.signal);
      }
    }

    throw lastError instanceof Error ? lastError : new Error('Upload failed');
  })();

  return {
    promise,
    cancel: () => {
      controller.abort();
      emit({ status: 'canceled' });
    },
    onProgress: (cb) => {
      listeners.add(cb);
      cb(state);
      return () => listeners.delete(cb);
    },
  };
}

/**
 * Create an object URL for a safe local preview and return a disposer that
 * releases it. Callers must invoke the disposer when the preview unmounts so
 * object URLs are not leaked.
 */
export function createPreviewUrl(file: File): { url: string; release: () => void } {
  const url = URL.createObjectURL(file);
  let released = false;
  return {
    url,
    release: () => {
      if (released) return;
      released = true;
      URL.revokeObjectURL(url);
    },
  };
}
