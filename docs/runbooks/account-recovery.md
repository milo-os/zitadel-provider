# Account Recovery — Configuration and Verification

How to turn on passkey account recovery, and how to prove each half works before
trusting it. Recovery mints a Zitadel passkey **registration code** and mails it to a
user's verified address; the code authorises enrolling one passkey and nothing else.

Two triggers produce the same mail from the same builder:

| Trigger | Surface | Switch |
|---|---|---|
| Self-serve (`/recover` in auth-ui) | `POST /v1/email/recovery` on the authn-webhook | `--account-recovery-template` (empty = route not registered) |
| Support (staff-portal) | `create identity.miloapis.com/v1alpha1 PasskeyRegistrationLink` on the apiserver | `--recovery-links-enabled` (false = create returns 503) |

See also [components/passkey-authentication.md](../components/passkey-authentication.md)
for the enrollment architecture these share.

## The code is a bearer credential

Whoever holds it can enroll a passkey on that account. It therefore appears in exactly
one place: the `Code` variable of the notification `Email`. It is never an object name,
a label, an annotation, a log field, or an error message. If you are adding to this
path, the tests that pin the property are `TestBuild_NameIsDeterministicAndCodeFree`,
`TestAccountRecovery_CodeNeverLandsInObjectName`,
`TestAccountRecovery_CreateFailureDoesNotEchoCode`,
`TestCreate_CodeNeverLeavesTheEmail` and
`TestCreate_EmailCreateFailureDoesNotEchoCode`.

There is **no recall**. Zitadel's v2 API cannot revoke an issued registration code; the
expiry is the only mitigation. Support must know this before pressing the button.

## Flags

Infra never sets container args — it sets env vars, and this repo's bundle declares each
flag as `--flag=$(ENV)`. The env names below are what an overlay patches.

### authn-webhook (self-serve)

`config/base/services/authn-webhook/authn-webhook.yaml`

| Flag | Env | Default | Notes |
|---|---|---|---|
| `--account-recovery-template` | `ACCOUNT_RECOVERY_TEMPLATE` | `""` | Empty leaves the route unregistered. Setting it makes `--client-ca-file` mandatory. |
| `--account-recovery-support-template` | `ACCOUNT_RECOVERY_SUPPORT_TEMPLATE` | `""` | The "Datum Support sent this" copy. |
| `--account-recovery-allowed-origins` | `ACCOUNT_RECOVERY_ALLOWED_ORIGINS` | `""` | returnTo allowlist. **Empty rejects everything** — a missing value must never read as "allow any host". |
| `--account-recovery-expiry-minutes` | `ACCOUNT_RECOVERY_EXPIRY_MINUTES` | `60` | A copy of Zitadel's `PasswordlessInitCode` lifetime. If that changes and this does not, the mail starts lying. |

`--notification-namespace` and the `--email-verification-user-lookup-*` retry flags are
shared with verification; recovery adds no duplicates of them.

**mTLS is enforced at startup, not at request time.** Setting the recovery template
without `--client-ca-file` makes the process refuse to boot, because controller-runtime
only requires client certs when a CA is configured — without it the endpoint would mail
a working code to any caller that can reach the Service.

### apiserver (support backstop)

`config/base/services/apiserver/deployment.yaml`

| Flag | Env | Default | Notes |
|---|---|---|---|
| `--recovery-links-enabled` | `RECOVERY_LINKS_ENABLED` | `false` | The infra-owned switch. While false the create returns 503, so the milo role that authorises it can ship dormant. |
| `--account-recovery-support-template` | `ACCOUNT_RECOVERY_SUPPORT_TEMPLATE` | `""` | |
| `--account-recovery-complete-url` | `ACCOUNT_RECOVERY_COMPLETE_URL` | `""` | Where the mailed link lands. Parsed at startup — a malformed value fails the boot, not a support engineer's first request. |
| `--account-recovery-expiry-minutes` | `ACCOUNT_RECOVERY_EXPIRY_MINUTES` | `60` | |
| `--notification-namespace` | `NOTIFICATION_NAMESPACE` | `milo-system` | |

Authorization is **not** Kubernetes RBAC. milo's apiserver authorizes through OpenFGA fed
by milo `Role` / `ProtectedResource` / `PolicyBinding` objects; the create issues a
SubjectAccessReview for `create identity.miloapis.com/passkeyregistrationlinks` on the
target user, with `iam.miloapis.com/parent-type: User` and `parent-name: <user>` extras.

## Verifying the support path

The create refuses in a fixed order, so each check can be exercised on its own.

**1. Flag off returns 503.** With `--recovery-links-enabled=false` (the default):

```sh
kubectl create -f - <<'EOF'
apiVersion: identity.miloapis.com/v1alpha1
kind: PasskeyRegistrationLink
spec:
  userRef: { name: "<zitadel-user-id>" }
  requestedBy: "<your milo user name>"
  reason: "runbook check"
EOF
```

Expect `503 Service Unavailable`, `recovery links are disabled`. **No code is minted** —
confirm no new `Email` exists with the `identity.miloapis.com/user` label for that user.

**2. Flag on, unverified user returns 400.** Point at a user whose milo `User` has no
`EmailVerified=True` condition:

```sh
kubectl get user <zitadel-user-id> -o jsonpath='{.status.conditions[?(@.type=="EmailVerified")]}'
```

Expect `400`, message `the user's email address is not verified; ask them to sign up
again to receive a verification link`. Again no code, no `Email`.

**3. Happy path.** Against a verified user, the create returns the object with
`status.emailName` and `status.expiresAt`, and the `Email` exists:

```sh
kubectl get emails -n milo-system \
  -l identity.miloapis.com/recovery-requested-by=support \
  -o custom-columns=NAME:.metadata.name,USER:.metadata.labels['identity\.miloapis\.com/user'],REQUESTER:.metadata.annotations['identity\.miloapis\.com/recovery-requester']
```

That label/annotation set **is** the audit record: the apiserver is virtual and persists
no `PasskeyRegistrationLink`, so the `Email` is the only durable trace of who asked and
why. staff-portal's "recovery links sent" history is this list.

## Verifying the EmailVerified writer (C11)

milo's waitlist controller gates the welcome and rejection mail on the `EmailVerified`
condition, and **only this component writes it** — from three places, so a miss
self-heals:

| Writer | When |
|---|---|
| `create-user-account` | At provisioning, from `GetUserByID.IsEmailVerified`. Best effort: a Zitadel error never fails the ack. |
| `POST /v1/actions/email-verified` | On `user.human.email.verified` (True) and `user.human.email.changed` (False). |
| `UserSweeper` | Every sweep (10 min), from `ListHumanUsers().IsEmailVerified`. |

The sweeper **diffs before writing**: it compares the desired condition against the
`User` already in its List cache and issues a status update only on mismatch. Without
that, a 10-minute sweep would add one write per human user, 144 times a day. The
regression guard is the spec `diffs against a single List instead of per-user Gets`,
whose fixture is deliberately in the agreed state.

Watch `zitadel_provider_user_sweep_email_verified_updates_total`. It should spike once
on the first sweep after deploy — that pass is the backfill for every existing account —
then sit near zero. A counter that keeps climbing means events are being missed, or two
writers disagree.

**Deploy order matters:** zitadel-provider must ship and complete one sweep before milo's
reader does, or an unwelcomed user looks like a bug rather than a pending backfill.

### W0-C9b spot-check — `users/status` write authority

The sweeper and the actions receiver write a **status subresource** on the core control
plane. `config/rbac/role.yaml` now declares `users/status` (get/update/patch), but that
ClusterRole governs the *local* cluster only. Both writer paths actually reach the core
control plane over mTLS certs issued with `csi.cert-manager.io/organizations: system:masters`
— the controller via `milo-control-plane-certs`, the actions receiver via
`zitadel-actions-server-client-cert`. If the core apiserver honours `system:masters`, no
grant is needed.

**This has not been confirmed against a live cluster.** Confirm it once on staging before
trusting the writer, by watching for the write rather than by reading policy:

```sh
# 1. Pick a user and record the current condition.
kubectl get user <id> -o jsonpath='{.status.conditions[?(@.type=="EmailVerified")].status}'

# 2. Force a disagreement, then wait one sweep interval (10 min).
#    Any of these works: flip the address in Zitadel, or delete the condition.

# 3. The condition should be rewritten, and the counter should move.
kubectl get user <id> -o jsonpath='{.status.conditions[?(@.type=="EmailVerified")]}'
kubectl -n <ns> exec deploy/<controller> -- \
  wget -qO- localhost:8443/metrics | grep user_sweep_email_verified_updates_total
```

A `403` in the controller log naming `users/status` means the certs are *not* being
treated as `system:masters` and a milo-side grant is required. Silence plus a moved
counter means the path is authorized.

## The C9 gauge

`zitadel_provider_verified_no_credential_accounts` counts accounts with a **verified
address and nothing that can sign in** — no passkey, no password, no IdP link. `otpEmail`
deliberately does not count: it is enrolled on every Phase B account and is not a login
method, so counting it would hide exactly the class this measures.

These accounts are **counted, never collected**. Recovery makes them reachable, and
deleting a verified account would race the mail that turns it back into a working one.

Computed in the abandoned-account GC sweep, one `ListAuthMethodTypes` RPC per verified
user per GC interval (6h). **Revisit trigger: 50.** Above that, reopen the retention
predicate with a separate, longer window — do not repurpose the 30-day unverified cutoff.

An RPC failure increments `zitadel_provider_abandoned_gc_errors_total` and skips that user:
an unreadable method list is not evidence that there are none.
