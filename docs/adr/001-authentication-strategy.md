# ADR-001: Authentication Strategy — Cookie/JWT vs NextAuth

## Status

Accepted

## Context

xConfess is an anonymous confession platform. Users need to authenticate to post confessions, react, and tip — but anonymity is a core product guarantee. The auth system must issue short-lived tokens, support cookie-based sessions for the browser, and not leak identity. The backend is a standalone NestJS API, not a Next.js API route, so auth must work over a separate origin.

## Options Considered

- **Option A — NextAuth.js**: Managed auth library for Next.js. Handles OAuth providers, sessions, and CSRF out of the box. Tightly coupled to Next.js API routes.
- **Option B — Custom JWT + HttpOnly cookies**: The NestJS backend issues a signed JWT stored in an HttpOnly cookie. Passport-JWT validates it on every request. CSRF protection is applied separately via csurf.
- **Option C — JWT in Authorization header (Bearer token)**: Classic stateless JWT sent in the Authorization header from the frontend.

## Decision

We chose **Option B** — custom JWT stored in HttpOnly cookies, validated by Passport-JWT on the NestJS backend.

NextAuth (Option A) requires Next.js API routes as the auth server, which would split auth logic across two runtimes and complicate the standalone NestJS API. Bearer tokens (Option C) are accessible to JavaScript, creating XSS risk that is incompatible with the anonymity guarantee. HttpOnly cookies are invisible to JS and work naturally with credentialed cross-origin requests.

## Consequences

### Positive

- Tokens are invisible to JavaScript, mitigating XSS token theft
- Auth logic lives entirely in the NestJS backend — single source of truth
- Passport-JWT is well-tested and integrates cleanly with NestJS guards

### Negative

- Cookie-based auth requires CSRF protection on all state-changing endpoints (addressed in ADR-001 companion: see src/common/csrf/csrf.middleware.ts)
- Cross-origin requests require CORS credentials config and matching SameSite cookie policy
- No built-in OAuth provider support — social login would require additional work

## CSRF Hardening (Advanced)

Cookie-authenticated mutations are protected by a double-submit token in addition to SameSite cookies. This section records the boundary and the assumptions the implementation depends on.

### Token issuance and verification

- The backend issues a signed CSRF token in a `csrf_token` cookie that is readable by JavaScript and set with `SameSite=Lax`.
- The token is signed with `JWT_SECRET` and carries an expiry, so verification is stateless and cannot be forged by a cross-site attacker.
- Mutations must send the token in the `x-csrf-token` header. The middleware rejects the request when the header is missing, invalid, expired, or does not match the cookie.
- The csrf-token endpoint and safe HTTP methods (GET, HEAD, OPTIONS) in cookie-authenticated requests are exempt.

### Origin and proxy assumptions

- The frontend proxies browser calls through the Next.js App Router so browser requests remain same-origin.
- The backend trusts the configured number of proxy hops (`TRUSTED_PROXY`) so the client IP and forwarded headers are derived from the correct hop.
- CORS allows credentials only for origins listed in `CORS_ORIGINS`. When the variable is unset, cross-origin credentialed requests are denied.
- App Router proxies must forward the `x-csrf-token` header on mutations and preserve the `csrf_token` cookie.

### Failure telemetry

CSRF validation failures are logged with the HTTP method, route, origin, and referer so operators can distinguish attack attempts from misconfigured clients.

### Rollback

The CSRF middleware is globally applied by `AppModule`. Rolling back requires removing the middleware from the consumer chain and redeploying; no data migration is needed.

## Account Deletion Orchestration (Issue #25)

Account deletion is a stateful, multi-system operation that must remain idempotent and observable while honoring legal-retention exceptions. This section records the orchestration contract that the deletion job implements; it does not change the authentication decision above.

### State machine

A deletion request moves through explicit states with guarded transitions:

- `requested` — user initiated deletion; no data has been touched yet.
- `confirmed` — user re-authenticated and explicitly confirmed; the grace period starts.
- `grace_period` — configurable window during which the user may cancel and return to `requested` (or `cancelled`).
- `processing` — grace period elapsed; anonymization and retention handling run.
- `completed` — all deletable records removed and retained records de-strifying.
- `failed` — a step errored; the job is retryable and resumes from the last committed step.

Transitions are only allowed forward (plus `grace_period -> cancelled`); any other transition is rejected so replays cannot resurrect a completed deletion.

### Confirmation

Deletion never proceeds from `requested` without an explicit confirmation step. Confirmation requires a fresh authenticated session (re-auth) so a stolen cookie alone cannot trigger irreversible deletion.

### Grace period

The grace period is configurable (env-driven) and cancellable. Cancelling during `grace_period` returns the account to normal operation and records the cancellation for observability. Once `processingc begins, cancellation is no longer offered.

### Anonymization and legal retention

Records that must be retained for legal/regulatory reasons (e.g. financial/tip ledgers, abuse reports) are kept but de-strifying: direct identifiers are replaced with a stable pseudonym, and free-text fields that could re-identify the user are scrubbed. Every retained record carries a justification tag so audits can distinguish retention from deletion. All other records (posts, messages, exports, notifications, analytics) are deleted.

### Idempotency and observability

Each step is keyed by the deletion job id, so re-running a job is a no-op for already-completed steps. State transitions and per-step outcomes are emitted as structured events, and the user-facing status endpoint reflects the current state so the UI can report accurate progress.

## Login Anomaly Detection & Step-Up Challenges (Issue #26)

Credential stuffing and impossible-travel patterns must be surfaced consistently to users and operators without weakening the anonymity guarantee. This section defines the signals, risk scoring, privacy limits, and step-up behavior layered on top of the cookie/JWT decision above; it does not change that decision.

### Signals

Each login attempt is evaluated against a small, explainable set of signals. Signals are derived per attempt and never store raw sensitive values:

- **Credential stuffing** — many distinct accounts attempted from the same source fingerprint within a short window, or a high failure ratio across accounts.
- **Impossible travel** — two successful authentications for the same account whose implied travel speed between coarse geolocations exceeds a physical threshold.
- **Velocity** — attempts per account and per source fingerprint exceeding configured rate thresholds.
- **Device/IP novelty** — first-seen device or network fingerprint for an otherwise established account.

### Risk scoring

Signals contribute weighted points to a per-attempt risk score in `[0, 100]`. Weights and thresholds are configuration-driven so operators can tune sensitivity without code changes. The score maps to a policy band:

- `Low` — allow; record the attempt outcome only.
- `Elevated` — allow but require a step-up challenge (second factor) before the session is fully trusted.
- `High` — block the attempt and require the user to complete a step-up challenge out-of-band before retrying.

Thresholds are chosen so that false positives are measurable: every band decision emits a structured event with the contributing signals and score, allowing precision/recall to be tracked over time and thresholds adjusted.

### Step-up behavior

When a band requires step-up, the login does not grant a fully trusted session. Instead the backend issues a short-lived, single-purpose challenge token bound to the attempt's request ID. The user completes a second factor (e.g. TOTP or a one-time code) to exchange the challenge token for a normal session. High-risk attempts are blocked outright until the challenge is satisfied. Step-up challenges expire quickly and are single-use.

### Correlation by request ID

Every login attempt is assigned a request ID at ingress. All anomaly signals, the computed risk score, the band decision, step-up issuance/completion, and block events are emitted as structured events carrying that request ID. This lets operators reconstruct a single attempt end-to-end and correlate it with downstream session activity.

### Privacy limits

Anomaly detection must not undermine anonymity:

- **Data minimization** — store only derived signals and coarse, non-reversible fingerprints; never persist raw IP addresses, raw device identifiers, or raw geolocation.
- **Retention** — anomaly and step-up events are retained for a short, configurable window sufficient for detection and audit, then purged.
- **No leakage** — signals and scores are never exposed to other users and are surfaced to the account owner only in aggregate, non-identifying terms.

### Rollback

Anomaly detection and step-up are gated behind a feature flag. Disabling the flag reverts to the baseline login flow (allow/deny by credentials only) without data migration, and previously stored derived signals age out under the retention window.

## References

- xconfess-backend/src/auth/jwt.strategy.ts
- xconfess-backend/src/auth/jwt-auth.guard.ts
- xconfess-backend/src/common/csrf/csrf.middleware.ts
