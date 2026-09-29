# Account Recovery Guide

This guide helps users recover from common wallet and network connection issues when using Xconfess.

## Problem

You may have connected the wrong wallet or the wrong network to Xconfess. This can cause:
- Inability to access your account
- Missing data or balances
- Transaction failures
- Login loops or unexpected errors

## Recovery Steps

### Wrong Wallet Connected

1. Click the wallet icon in the top right corner of the interface
2. Click **"Disconnect"** to disconnect the current wallet
3. Click **"Connect Wallet"**
4. Select the correct wallet from the list
5. Approve the connection request in your wallet extension

### Wrong Network Connected

1. Open your wallet extension (e.g., MetaMask, Phantom, etc.)
2. Switch to the correct network (e.g., Ethereum Mainnet, BSC Mainnet, testnet, etc.)
3. Refresh the Xconfess page
4. Your data should now appear correctly

### Both Wallet and Network Are Wrong

1. Disconnect the current wallet (see steps above)
2. Connect the correct wallet
3. Ensure the wallet is on the correct network
4. Refresh the page
5. Verify your account data loads properly

### Still Having Issues?

- Clear your browser cache and cookies
- Try a different browser or private/incognito window
- Restart your wallet extension
- Ensure your wallet is unlocked
- Check that your wallet supports the required network
- Contact support if the problem persists

## Common Failure Modes

- **Network mismatch**: You're on testnet but the app expects mainnet (or vice versa)
- **Wallet not supported**: The wallet you're using isn't supported by Xconfess
- **Session expired**: Your session has timed out and requires re-authentication
- **Browser extension conflict**: Multiple wallet extensions are interfering with each other
- **Cached connection**: The app is reading a stale connection from local storage
- **Account lock**: Too many failed attempts temporarily locked the account

## Prevention

To avoid these issues in the future:

- **Always double-check the network** before connecting your wallet
- **Use the same wallet consistently** to avoid data fragmentation
- **Keep your wallet software updated** to the latest version
- **Disconnect when not actively using** the application
- **Bookmark the official Xconfess site** to avoid phishing sites
- **Verify the network icon** in your wallet before approving transactions
- **Clear cache periodically** if you experience strange behavior

## Account Merge and Anonymous Identity Transfer

If you used Xconfess anonymously (without connecting a wallet) and later connect an authenticated account, you may want to merge the two identities so that your anonymous activity is owned by your authenticated account. Merging is explicit, confirmed, and reversible where possible.

### What Can Be Merged

The merge workflow covers the following record types. Each is handled with its own conflict rules:

- **Usernames**: The authenticated account's username wins. If the anonymous identity has a username that is not taken, it is retained as an alias.
- **Messages**: Messages authored by the anonymous identity are reassigned to the authenticated account. Duplicate messages (same content, same counterparty, within the merge window) are collapsed to a single record.
- **Drafts**: Drafts are reassigned. If both identities have a draft with the same identifier, the authenticated account's draft is kept and the anonymous draft is retained as a conflict record for review.
- **Tips**: Tips sent or received by the anonymous identity are reassigned. Tips are never duplicated; if a tip already exists under the authenticated account, the anonymous tip is discarded and the conflict is logged.
- **Anchors**: On-chain anchors are immutable. The anonymous identity's anchors are re-pointed to the authenticated account in the local index only; the chain record is never rewritten.

### Conflict Handling

Conflicts are surfaced before any data is moved. The merge preview lists every conflict with:

- The record type and identifier
- The authenticated account's value and the anonymous identity's value
- The proposed resolution (keep authenticated, keep anonymous, or retain both)

You must explicitly confirm the resolution for each conflict class before the merge proceeds. Unresolved conflicts block the merge.

### Confirmation and Rollback

1. Start the merge from **Settings → Account → Merge anonymous activity**.
2. Review the preview and resolve each conflict class.
3. Confirm the merge. The confirmation is recorded with a merge request ID.
4. The merge runs as an atomic job where possible. Record types that cannot be moved atomically (for example, on-chain anchors) are processed in a separate, idempotent step.
5. If the job fails partway through, it can be retried from its last recorded state. A rollback restores the pre-merge ownership for all record types that were moved in the failed run.

### Authorization

- Only the authenticated account that initiated the merge can confirm it.
- A merge attempt from an identity that does not own the anonymous session fails with a generic authorization error and is logged.
- Merge attempts are rate-limited per account and per source.
- Anonymous sessions that have already been merged cannot be merged again; a second attempt fails and is logged.

### Audit Evidence

Every merge records audit evidence that is retained for the configured retention window:

- The merge request ID
- The initiating account and the anonymous session identifier (hashed)
- The conflict resolutions chosen
- The record types moved, skipped, or rolled back
- The outcome of each step (success, failure, retry)

Audit records never contain raw credentials or full identifiers; identifiers are hashed or truncated.

### If a Merge Goes Wrong

1. Open **Settings → Account → Merge history** and locate the merge request ID.
2. If the merge is still processing, wait for it to finish or fail.
3. If the merge failed, retry it from the last recorded state.
4. If the merge completed but the result is wrong, request a rollback and reference the merge request ID.
5. Contact support with the merge request ID if you cannot resolve the issue yourself.

## Identity Enumeration Resistance

Registration, login, recovery, and profile endpoints must not reveal whether a given identity (username, email, or wallet address) exists. An attacker who can distinguish "identity exists" from "identity does not exist" can build a list of valid accounts and target them. Xconfess normalizes externally visible behavior across these endpoints so that existing and non-existing identities are indistinguishable to a caller.

### Externally Visible Behavior

For every identity-bearing endpoint, the response for an existing identity and a non-existing identity must match on all of the following:

- **Status code**: The same HTTP status is returned in both cases (for example, `200` for login and recovery initiation, `202` for registration, `401` for authentication failures).
- **Merge endpoints**: Merge initiation, preview, confirmation, and rollback return the same status and body whether or not the referenced anonymous session exists, so that merge endpoints cannot be used to enumerate anonymous sessions.
- **Response body**: The same shape and the same generic message are returned. Messages never say "user not found", "email already registered", or "incorrect password"; they use a single neutral message such as "If an account exists, we've sent instructions."
- **Headers**: Response headers (including `Content-Length`, `Content-Type`, and any rate-limit headers) are identical in both cases. Rate-limit headers reflect the caller's budget, not the identity's existence.
- **Timing budget**: The endpoint performs the same work (including a dummy hash or lookup) in both cases so that response time does not leak existence. Measured latency for existing and non-existing identities must stay within a configured timing budget.

### Endpoint Notes

- **Registration**: Submitting an already-registered identity returns the same success response as a new registration. The user is notified out-of-band (for example, by email) that the identity is already registered, so the caller cannot tell the difference.
- **Login**: A wrong password and an unknown identity return the same status, body, and timing. Failed attempts are counted against the caller's rate-limit budget regardless of whether the identity exists.
- **Recovery**: Requesting recovery for an unknown identity returns the same response as for a known one. Recovery instructions are only sent when the identity exists, but the caller cannot observe that difference.
- **Profile**: Profile lookups that are not authorized to view an identity return the same response whether or not the identity exists, so that profile endpoints cannot be used as an existence oracle.

### Internal Logs

Operators still need to diagnose issues, so internal logs record the outcome of each attempt (for example, `identity_exists=true|false`, `reason=unknown_identity|bad_password`) alongside the request ID. These logs are never returned to the caller and never contain raw credentials. Where an identifier must appear in a log, it is hashed or truncated so that logs remain useful without exposing raw identifiers.

### Testing

Enumeration tests exercise each identity-bearing endpoint with an existing identity and a non-existing identity and assert that the two responses match on status, body, headers, and timing budget. Tests cover failure paths (wrong password, unknown identity, unauthorized profile access) and assert that internal logs record the outcome without exposing raw identifiers. Timing assertions use a configured budget rather than an exact value so that they remain stable across environments.

## Login Anomaly Detection and Step-Up Challenges

Xconfess continuously evaluates login attempts for signs of credential stuffing and impossible-travel patterns. When an attempt looks suspicious, the user is asked for a second factor (a step-up challenge) or the attempt is blocked, depending on the computed risk.

### Anomaly Signals

Each login attempt is scored using the following signals. Signals are derived from the attempt itself and from recent history; raw sensitive values are never stored.

- **Credential stuffing**: Many distinct accounts are attempted from the same source in a short window, or a single account is attempted from many sources.
- **Impossible travel**: Two successful or attempted logins for the same account originate from locations that cannot be reached in the elapsed time.
- **Velocity**: The number of attempts for an account or source exceeds a configured threshold within a rolling window.
- **Device novelty**: The attempt comes from a device fingerprint not previously associated with the account.
- **IP novelty**: The attempt comes from an IP address or network not previously associated with the account.

### Risk Scoring

Signals are combined into a single risk score per attempt. Each signal contributes a weighted amount, and the total maps to a risk band:

- **Low**: The attempt proceeds normally.
- **Medium**: The attempt proceeds but is flagged for operator review and contributes to future scoring.
- **High**: The attempt requires a step-up challenge (a second factor) before it can proceed.
- **Critical**: The attempt is blocked outright and the account owner is notified.

Thresholds and weights are configurable per deployment so operators can tune sensitivity without code changes.

### Step-Up Behavior

- **High risk**: The user must complete a second factor (for example, a one-time code or an additional wallet signature) before the session is established. If the challenge fails or expires, the attempt is treated as blocked.
- **Critical risk**: The attempt is rejected immediately. The user is shown a clear message and, where appropriate, a recovery path.
- **Medium risk**: The attempt succeeds, but the event is recorded for review and raises the account's baseline risk for subsequent attempts.

### Correlation by Request ID

Every login attempt, anomaly signal, risk decision, and step-up challenge is correlated by a single request ID. This ID is attached to all related events so that operators can trace a full attempt end to end, and so that support can reference a specific attempt without exposing sensitive data.

### Privacy Limits

Anomaly detection is designed to minimize the data it retains:

- **Data minimization**: Only the signals needed for scoring are derived. Raw credentials, full IP addresses, and precise locations are not stored; they are hashed or truncated where a stable identifier is required.
- **Retention**: Derived signals and risk events are retained only for the configured retention window, after which they are deleted or aggregated.
- **No raw sensitive data leakage**: Logs and operator views never contain raw credentials, full IP addresses, or precise location data. Events reference the request ID and the derived signal values only.
- **False-positive measurement**: Risk decisions are recorded with their outcome so that false positives can be measured and thresholds tuned over time.

### If You Are Challenged or Blocked

If a login is challenged or blocked, you can recover as follows:

1. Complete the step-up challenge if one is presented.
2. If the attempt was blocked, wait for the configured cooldown and try again from a network and device you normally use.
3. If you believe the block is a false positive, contact support and reference the request ID shown in the error message.
4. If you suspect your account is under attack, change your credentials and review connected wallets.

## Account Deletion Orchestration

Account deletion is a stateful, multi-step process. It spans posts, messages, exports, notifications, analytics, and chain references, each with different retention requirements. The orchestration job tracks an explicit state so that deletion is idempotent and observable, and so that user-facing status is always accurate.

### Deletion States

A deletion request moves through the following states:

- **requested**: The user has asked to delete their account. No data has been removed yet.
- **confirmed**: The user has explicitly confirmed the deletion request.
- **grace_period**: A configurable waiting window during which the user can cancel the deletion.
- **processing**: The orchestration job is actively deleting or anonymizing records across all subsystems.
- **completed**: All deletable records have been removed or anonymized and the account is closed.
- **failed**: The job encountered an error and stopped. The job can be retried safely.

### Confirmation

Deletion never proceeds without explicit user confirmation. A request in the `requested` state does not remove any data. Only after the user confirms does the job transition to `confirmed` and then to `grace_period`.

### Grace Period

After confirmation, the job enters a configurable grace period. During this window the user can cancel the deletion, which returns the account to normal operation. The grace period length is configurable per deployment so that operators can tune it to their retention and support policies.

### Anonymization Rules

Records that must be retained for legal or operational reasons are de-identified rather than deleted. Identifiers are replaced with irreversible hashes or removed entirely, and references to the account are rewritten so that no retained record can be linked back to the user. Records that are not required for legal or operational reasons are deleted outright.

### Idempotency and Retries

Each step of the orchestration job is idempotent. If the job fails partway through, it can be retried from its last recorded state without duplicating work or leaving the account in an inconsistent state. The job records its progress so that operators can see exactly which subsystems have been processed.

### User-Facing Status

The user can always see the current state of their deletion request. Status is derived from the orchestration state, so it is accurate even if the job is retried or delayed. If the job fails, the user is shown that the request is still in progress and that no data has been lost.
