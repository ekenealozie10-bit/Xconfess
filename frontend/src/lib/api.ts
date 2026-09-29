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
  const listeners = new Set<(state: UploadState) => void>();
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
