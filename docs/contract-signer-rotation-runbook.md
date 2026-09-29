# Contract Signer Key Rotation Runbook

**Scope:** xConfess Soroban smart contracts<br>
**Audience:** Core maintainers with contract admin access  
**Related issues:** #117 (emergency pause guard), #123 (admin role transfer timelock), #144 (governance quorum)

---

## Part 1 — routine Signer Rotation

Use this flow for **planned** key rotations (scheduled maintenance, key age policy, personnel change).

### Pre-rotation checklist

- [ ] Confirm the new key pair has been generated on an air-gapped machine
- [ ] Store the new secret key in the team vault (e.g. 1Password / HashiCorp Vault)
- [ ] Obtain quorum sign-off from at least the number of signers required by governance policy
- [ ] Schedule a maintenance window if the contract will be paused during rotation
- [ ] Notify on-call team at least 24 h in advance

### Step 1 — Generate and verify the new keypair

```bash
# Generate new keypair (air-gapped preferred)
stellar keys generate --network testnet new-admin

# Print public key for verification
stellar keys address new-admin
```

Record the new public key and share it with the team for quorum approval.

### Step 2 — Pause the contract (recommended)

```bash
# Pause to prevent state changes during key handoff
stellar contract invoke \
  --id $CONTRACT_ID \
  --source-account $CURRENT_ADMIN_KEY \
  --network mainnet \
  - pause --reason "Planned admin key rotation — maintenance window"
```

Verify the pause:

```bash
stellar contract invoke \
  --id $CONTRACT_ID \
  --network mainnet \
  - is_paused
# Expected: true
```

### Step 3 — Initiate the admin role transfer (timelock)

The contract enforces a timelock before the transfer takes effect (ADR #123):

```bash
stellar contract invoke \
  --id $CONTRACT_ID \
  --source-account $CURRENT_ADMIN_KEY \
  --network mainnet \
  - propose_admin_transfer --new_admin $NEW_ADMIN_PUBLIC_KEY
```

Note the `transfer_id` and the `earliest_executable_at` timestamp returned.

### Step 4 — Wait for timelock to elapse

The timelock period is defined in the contract configuration. Do not proceed until `earliest_executable_at` has passed. Confirm on-chain:

```bash
stellar contract invoke \
  --id $CONTRACT_ID \
  --network mainnet \
  - pending_admin_transfer
# Confirm new_admin and earliest_executable_at
```

### Step 5 — Execute the transfer with quorum approval

Collect the required number of signatures from current quorum signers, then execute:

```bash
stellar contract invoke \
  --id $CONTRACT_ID \
  --source-account $QUORUM_SIGNER_KEY \
  --network mainnet \
  - execute_admin_transfer --transfer_id $TRANSFER_ID
```

### Step 6 — Verify and unpause

```bash
# Confirm the new admin is active
stellar contract invoke \
  --id $CONTRACT_ID \
  --network mainnet \
  - admin
# Expected: $NEW_ADMIN_PUBLIC_KEY

# Unpause the contract
stellar contract invoke \
  --id $CONTRACT_ID \
  --source-account $NEW_ADMIN_KEY \
  --network mainnet \
  - unpause --reason "Key rotation complete"

# Verify
stellar contract invoke --id $CONTRACT_ID --network mainnet - is_paused
# Expected: false
```

### Post-rotation checklist

- [ ] Revoke the old key from the team vault
- [ ] Update `deployments/` manifest with new admin public key
- [ ] Run smoke tests against the live contract
- [ ] Log the rotation in the audit trail (date, operator, reason)
- [ ] Close the maintenance window notification

---

## Part 2 — Emergency Break-Glass Response (Compromised Key)

Use this flow when a signer key is believed to be **compromised or exposed**.

> **Treat this as a P0 incident.** Start the response immediately; do not wait for a maintenance window.

### Step 1 — Stop, contain, and assess

1. **Do not use the compromised key** for any further operations.
2. Revoke the compromised key from all vaults and secret managers immediately.
3. Determine the blast radius:
   - Check on-chain history for unexpected admin or governance actions in the last 24 h.
   - Check off-chain infrastructure for signs of credential use (logs, CI secrets, API calls).
4. Page the on-call team via the incident channel.

### Step 2 — Pause the contract using a different key

If the compromised key was the primary admin, use a quorum of governance signers to pause:

```bash
stellar contract invoke \
  --id $CONTRACT_ID \
  --source-account $QUORUM_SIGNER_KEY \
  --network mainnet \
  - emergency_pause --reason "Suspected key compromise — P0 incident"
```

If the contract is already paused (attacker triggered it), verify pause state and proceed.

### Step 3 — Rotate to a new key

Follow **Part 1, Steps 1–6** using an emergency key pre-generated and stored in the break-glass vault. If no break-glass key exists, generate one now and proceed with quorum transfer.

### Step 4 — Audit all recent on-chain actions

```bash
# List recent governance and admin events (adjust block range as needed)
stellar events \
  --contract-id $CONTRACT_ID \
  --start-ledger $INCIDENT_START_LEDGER \
  --network mainnet
```

Identify and document any unauthorised actions. If irreversible damage was done (e.g. funds moved), escalate to the legal/security team.

### Step 5 — Recover and validate

1. Restore the contract to normal operation only after confirming the new key is in place and the old key is fully revoked.
2. Run the full test suite against the live contract.
3. Unpause when satisfied:

```bash
stellar contract invoke \
  --id $CONTRACT_ID \
  --source-account $NEW_ADMIN_KEY \
  --network mainnet \
  - unpause --reason "Break-glass rotation complete — incident $INCIDENT_ID"
```

### Step 6 — Post-incident communication and verification

- [ ] Notify all stakeholders (community, partners, auditors) via official channels
- [ ] Publish a post-mortem within 72 h (root cause, timeline, remediation)
- [ ] Update the break-glass vault with the new key
- [ ] Schedule a retrospective to review detection time and response quality
- [ ] File the incident in the audit trail with full timeline

---

## Part 3 — Application Secret Key Versioning and Rotation (Zero-Downtime)

This part covers **off-chain application secrets** (encryption keys, signing secrets) used by the backend to protect data at rest and sign tokens. Rotation must preserve access to data encrypted with previous key versions.

### Key versioning model

Every secret is stored as a **versioned entry** in the secret manager:

- Key name: `<purpose>/v<N>` (e.g. `data-encryption/v3`, `token-signing/v7`)
- Active pointer: `<purpose>/active` → current version name
- Previous versions remain readable until explicitly retired.

Ciphertext and signed tokens must embed the key version so the reader can select the correct key:

- Encrypted blobs: prefix `enc:v<N>:<payload>`
- Signed tokens: `v<N>.<base64url(payload)>.<base64url(sig)>`

The active version is used for **new writes**. Reads accept the active version and any version still listed in the rotation manifest.

### Rotation manifest

Maintain a committed manifest at `config/secret-rotation.json`:

```json
{
  "data-encryption": {
    "active": "v3",
    "readable": ["v3", "v2"],
    "retired": ["v1"]
  },
  "token-signing": {
    "active": "v7",
    "readable": ["v7", "v6"],
    "retired": []
  }
}
```

Rules:

- New writes always use `active`.
- Readers accept `active` and every version in `readable`.
- A version moves to `retired` only after a backfill has re-encrypted/re-signed all data and a grace period has elapsed.
- Unknown versions must fail closed (see Failure handling).

### Dual-read / single-write migration

1. **Prepare** — add the new key as `<purpose>/v<N+1>` in the secret manager. Do not change `active` yet.
2. **Enable dual read** — add the new version to `readable` in the manifest and deploy. At this point readers can handle both old and new ciphertext, but writes still emit the old version.
3. **Flip writes** — set `active` to the new version and deploy. New writes now emit `<purpose>/v<N+1>`; readers still accept the old version.
4. **Backfill** — re-encrypt records or re-sign tokens in place using a batched migration job. The job must be idompotent and resumable.
5. **Retire** — once the backfill reports zero remaining objects on the old version and the grace period has elapsed, move the old version to `retired` and remove it from the vault.

### Rollback

At any point before step 5 the rotation can be rolled back without data loss:

1. Revert `active` to the previous version in the manifest and deploy.
2. Keep the new version in `readable` so any data already written with it remains readable.
3. Re-run the backfill only after the new key is re-activated.

If a rotation is interrupted mid-flip (e.g. deploy fails after manifest update), the system must still read both versions: `runbook/secret-rotation-recovery.md` describes the recovery procedure.

### Operator runbook — application secret rotation

1. **Pre-flight** — confirm the new key exists in the vault and the manifest is valid:

```bash
npm run secret-scan
npm run audit:ci
```

2. **Add new version** — update the manifest `readable` list and deploy. Verify with `npm run backend:test`.
3. **Flip active** — update `active` and deploy. Monitor decryption/signature errors for at least one reporting interval.
4. **Backfill** — run the migration job in batches. Record completion in the audit trail.
5. **Retire** — move the old version to `retired`, remove from the vault, and re-run `npm run secret-scan && npm run audit:ci && npm run backend:test`.

### Failure handling

- **Unknown key version** — decryption or signature verification must return a typed error (e.g. `UNKNOWN_KEY_VERSION`) and must not fall back to the active key. This prevents silent data corruption.
- **Missing key** — if the vault lookup fails, fail closed and alert; do not return plaintext or a default key.
- **Interrupted rotation** — if the manifest and deployed code disagree, the reader must honour the union of both manifests until reconciled.
- **Rollback** — reverting `active` must not invalidate data already written with the new version.

### Tests required

- New writes emit the active version.
- Reads succeed for all versions in `readable`.
- Reads fail with `UNKNOWN_KEY_VERSION` for versions not in `readable` or `retired`.
- Rotation interrupted between manifest update and deploy still reads both versions.
- Rollback of `active` keeps new-version data readable.
- Authorization: only operators with the `secrets:rotate` scope can mutate the manifest.
- Privacy: key material must never appear in logs, traces, or error messages.

---

## Drills

Run a tabletop drill at least once per quarter:

1. Simulate a planned rotation using the testnet contract.
2. Simulate a compromised-key scenario: pause the testnet contract, perform break-glass rotation, unpause.
3. Simulate an application secret rotation including an interrupted flip and rollback.
4. Record drill date, participants, and any gaps found in this runbook.

---

## References

- `maintainer/issues/117-feat-contract-emergency-pause-guard.md`
- `maintainer/issues/123-feat-contract-admin-role-transfer-timelock.md`
- `maintainer/issues/144-feat-contract-governance-quorum-critical-actions.md`
- `xconfess-contract/README.md`
