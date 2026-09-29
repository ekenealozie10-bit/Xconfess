# Frontend Security Headers — Review & Recommendations

## Summary

We now ship a coordinated security-header policy from the backend and

recommend the same policy from the frontend proxy. The CSP starts in

[report-only](mode and is promoted to enforcing mode via configuration after a

clean soak. This document inventories the currently configured security

headers, documents the CSP directive inventory, and describes the rollout

procedure.

## Current Header Inventory

### Configured in `next.config.mjs`

| Header | Value | Status |

|--------|-------|--------|

| `X-Powered-By` | Disabled (`poweredByHeader: false`) | ✅ Good |

| `Compression` | Enabled (`compress: true`) | ✅ Good |

### Emitted by the backend

The `xconfess-backend` now emits the following headers on every response

via `SecurityHeadersMiddleware`:

| Header | Value | Notes |

|--------|-------|-------|

| `Content-Security-Policy-Report-Only` | Configured below | Default mode; not enforcing. |

| `Content-Security-Policy` | Configured below | Emitted only when `CSP_MODE=enforce`. |

| `X-Content-Type-Options` | `nosniff` | Prevents MIME sniffing. |

| `X-Frame-Options` | `DENY` | Prevents clickjacking. |

| `Referrer-Policy` | `strict-origin-when-cross-origin` | Controls referrer information. |

| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=()` | Disables unused browser features. |

| `Cross-Origin-Opener-Policy` | `same-origin` | Isolates the browsing context group. |

| `X-DNS-Prefetch-Control` | `off` | Disables DSN prefetch leaks. |

| `Strict-Transport-Security` | `HSTS_ENABLED=true` only | Forces HTTPS; opt-in. |

### Missing headers on the frontend proxy

| Header | Purpose | Priority |

|--------|---------|---------|

| `Content-Security-Policy` | Prevents XSS, data injection | **High** |

| `X-Content-Type-Options` | Prevents MIME sniffing | **High** |

| `X-Frame-Options` | Prevents clickjacking | **High** |

| `Referrer-Policy` | Controls referrer information | **Medium** |

| `Permissions-Policy` | Controls browser features | **Medium** |

| `Strict-Transport-Security` | Forces HTTPS | **High** (production) |

## CSP Directive Inventory

The directive inventory lives in `xconfess-backend/src/security/csp.config.ts`

as `DEFAULT_CSP_DIRECTIVES`. Each source is derived from codebase analysis:

| Directive | Sources | Rationale |

|-----------|---------|----------|

| `default-src` | `self` | Deny by default; explicit allows below. |

| `script-src` | `self` (+ `nonce-<value>` when `CSP_NONCE_ENABLED=true`) | Next.js hydration bundles and Stellar SDK. |

| `style-src` | `self`, `unsafe-inline` | Tailwind CSS is injected inline at build time. |

| `img-src` | `self`, `data:`, `blob9` | Next.js image optimization + inline data URIs. |

| `font-src` | `self`, `data:` | System fonts + inline font data. |

| `connect-src` | `self`, `https://horizon.stellar.org`, `https://soroban-rpc.stellar.org` | API proxy + Stellar network endpoints. |

| `frame-ancestors` | `none` | No legitimate embedding. |

| `base-uri` | `self` | Prevents base-tag hijacking. |

| `form-action` | `self` | Prevents form exfiltration. |

| `object-src` | `none` | Disables plugin embeds. |

| `worker-src` | `self`, `blob:` | Web workers and Next.js worker bundles. |

| `manifest-src` | `self` | Web app manifest. |

## Configuration

All tunables are read from the environment so enforcement can be

enabled without a code deploy:

| Variable | Default | Effect |

|--------|--------|--------|

| `CSP_MODE` | `report-only` | One of `off`, `report-only`, `enforce`. |

| `CSP_REPORT_URI` | unset | Legacy `report-uri` directive. |

| `CSP_REPORT_TO` | unset | `report-to` group name for Reporting API. |

| `CSP_REPORT_ENDPOINT_URL` | `/api/security/csp-report` | Ingest path for violation reports. |

| `CSP_REPORT_TOKEN` | unset | When set, requests must carry `x-csp-report-token`. |

| `CSP_NONCE_ENABLED` | `false` | Adds a per-request nonce to `script-src`. |

| `HSTS_ENABLED` | `false` | Emits `Strict-Transport-Security`. |

| `HSTS_MAX_AGE` | `63072000` | Max-age for HSTS. |

| `HSTS_INCLUDE_SUBDOMAINS` | `true` | Adds `includeSubdomains` to HSTS. |

| `HSTS_PRELOAD` | `false` | Adds `preload` to HSTS. |

## Reporting and privacy

CSP reports are posted to `/api/security/csp-report`. The handler:

1. Rejects requests lacking the configured shared token (when one is set).

2. Rejects bodies larger than 16 KB and unsupported content types.

3. Reduces every URL to its origin (scheme + host + port) before logging.

4. Drops the `script-sample` field entirely to avoid logging potential PII.

5. Truncates directive names to 64 characters.

Sanitization is implemented in `xconfess-backend/src/security/csp-report.sanitizer.ts`

and covered by unit tests in `xconfess-backend/src/security/__tests__`.

## Rollout Procedure

1. Deploy with defaults (`CSP_MODE=report-only`). Confirm reports arrive at

   `/api/security/csp-report` and are sanitized.

2. Triage violations by `csp-violation` log events. Add new sources to

   `DEFAULT_CSP_DIRECTIVES` only with a documented rationale.

3. After a clean soak (no unexplained violations), set `CSP_MODE=enforce`.

4. Rollback: set `CSP_MODE=report-only` or `CSP_MODE=off`. No code deploy

   required.

## Non-cee and inline script strategy

When `CSP_NONCE_ENABLED=true`, the middleware generates a 16-byte base64

nonce per request and exposes it on `res.locals.cspNonce`. The nonce is

appended to `script-src` as `'nonce-<value>'`. Server-rendered templates must

read the nonce from response locals and attach it to inline `<script>` tags.

When nonces are disabled, inline scripts must be hashed and the hash added to

`script-src` via `DEFAULT_CSP_DIRECTIVES` overrides. The default policy does

not allow `unsafe-inline` or `unsafe-eval` in production.

## Frontend proxy coordination

The Next.js frontend should emit the same policy via `next.config.mjs` headers

so that browser requests that never reach the backend (static assets,

prerendered pages) are covered. The backend policy is the source of truth

for directive values; any frontend override must be documented here.

## Validation

- ✅ Frontend build remains passing with proposed headers

- ✅ No production secrets appear in this documentation

- ✅ CSP is compatible with Next.js requirements

- ✅ CSP allows required Stellar SDK connections

- ✅ Reports are sanitized before logging (unit tested)

## References

- [MDN Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

- [Next.js Security Headers](https://nextjs.org/docs/advanced-features/security-headers)

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
