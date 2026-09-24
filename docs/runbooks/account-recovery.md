# Account Recovery — Configuration and Verification

How to turn on passkey account recovery, and how to prove each half works before
trusting it. Recovery mints a Zitadel passkey **registration code** and mails it to a
user's verified address; the code authorises enrolling one passkey and nothing else.

Two triggers produce the same mail from the same builder:

| Trigger | Surface | Switch |
|---|---|---|
| Self-serve (`/recover` in auth-ui) | `POST /v1/email/recovery` on the authn-webhook — `requestedBy` accepts **only** `"self"` | `--account-recovery-template` (empty = route not registered) |
| Support (staff-portal) | `create identity.miloapis.com/v1alpha1 PasskeyRegistrationLink` on the apiserver | `--recovery-links-enabled` (false = create returns 503) |

See also [components/passkey-authentication.md](../components/passkey-authentication.md)
for the enrollment architecture these share.

## The code is a bearer credential

Whoever holds it can enroll a passkey on that account. It appears in exactly **two**
places: the `Code` variable of the notification `Email`, and the **fragment** of that
Email's `ActionUrl` variable — the part after `#`, which browsers never send to a
server. It is never an object name, a label, an annotation, a log field, an error
message, an API response, or the **query string** of that URL.

The fragment is the whole point of the second location. In the query, the code was
written verbatim into the landing host's access logs, its ingress or CDN logs and its
APM — systems retained longer, replicated wider and access-controlled far more loosely
than anything meant to hold secrets, and often shipped to a third party. Because there
is no revocation (below), every one of those copies was a working passkey-enrollment
credential until expiry. In the fragment it reaches only the browser the user opened
the link in, and it is bounded further by single-use redemption at the landing page.

If you are adding to this path, the tests that pin the property are:

| Test | Pins |
|---|---|
| `TestBuild_NameIsDeterministicAndCodeFree` | not in the object name |
| `TestAccountRecovery_CodeNeverLandsInObjectName` | not in the object name |
| `TestActionURL_CodeTravelsInTheFragment` | not in the URL query; is in the fragment |
| `TestActionURL_FragmentIsEscaped` | the fragment round-trips through `URLSearchParams` |
| `TestBuild_ActionURLQueryNeverCarriesTheCode` | the assembled Email's `ActionUrl` query is clean |
| `TestAccountRecovery_ResponseNeverCarriesTheCode` | not in the webhook's HTTP response |
| `TestAccountRecovery_RejectsCallerSuppliedCode` | a caller cannot supply one |
| `TestAccountRecovery_CreateFailureDoesNotEchoCode` | not in an error path |
| `TestCreate_CodeNeverLeavesTheEmail` | not in the returned object |
| `TestCreate_EmailCreateFailureDoesNotEchoCode` | not in an error path |

**Do not add a log line, an audit forward, a support-tool link or a retry queue that
carries the whole `ActionUrl`.** The `Code` variable is obviously a credential; the
link is the one that does not look like one.

There is **no recall**. Zitadel's v2 API cannot revoke an issued registration code; the
expiry is the only mitigation. Support must know this before pressing the button.

## The self-serve request contract

`POST /v1/email/recovery` takes `{"userId", "returnTo", "requestedBy":"self"}` and
answers `200 {"codeId":"..."}`.

- The **webhook mints the code**, by calling Zitadel's `CreatePasskeyRegistrationLink`.
  A request carrying `codeId` or `code` is rejected with `400`. Relaying a
  caller-supplied code could not be checked against `userId`, and any random string was
  a fresh `codeId` — which defeated the Email dedupe and bypassed Zitadel's own
  throttle on minting.
- `requestedBy` accepts **only** `"self"`. `"support"` is `400`: that trigger is the
  apiserver create, which carries a SubjectAccessReview, a mandatory reason and a named
  requester, and this endpoint has none of them.
- The response carries the `codeId` and **never the code**. The caller asked for a mail
  to be sent, not for the credential.

## The webhook's two Zitadel credentials

The authn-webhook holds **two** Zitadel keys, for two different callers. They are not
interchangeable, and Zitadel will not tell you when you have swapped them.

| Flag | Key type | `type` in the JSON | Carries | Used for |
|---|---|---|---|---|
| `--zitadel-private-key` | Application key | `application` | `clientId`, `appId`, `keyId` | Token introspection, i.e. the TokenReview path |
| `--zitadel-service-account-key` | Service account key | `serviceaccount` | `userId`, `keyId` | Calling the Zitadel API. Today only account recovery, which mints the registration code |

The introspector reads `clientId` and `keyId` off its key and introspects tokens with
them. The recovery client goes through `zitadel.NewSDK`, which builds a JWT-profile
token source: that assertion is minted **for a service user**, so it needs that user's
`userId`. An application key has none, and no flag value can conjure one.

Point `--zitadel-service-account-key` at an application key and the token exchange
answers:

```
HTTP 500 {"error":"server_error","error_description":"Errors.Internal"}
```

That message names neither the key, the flag, nor the mistake. The webhook now reads
the key's `type` and `userId` before it calls Zitadel and refuses a mismatch itself,
naming both secrets and both flags.

The two keys live in different secrets. `iam-admin` holds a service account key, and
the CI overlay mounts it. `zitadel-machine-auth-api-key` holds the application key, and
that is what staging mounts for introspection. **The base bundle mounts neither** —
`volumeMounts` and `volumes` are empty there, as they are for every other service in
this repo. An overlay that switches recovery on has to add a volume for the service
account key secret and point `ZITADEL_SERVICE_ACCOUNT_KEY_PATH` at the mounted file.

### Recovery degrades; it does not take the webhook down

This webhook's first job is answering `/apis/authentication.k8s.io/v1/tokenreviews` for
the cluster. Recovery is a mail feature that happens to share the process, and it now
fails on its own. If the recovery client cannot be built, the webhook logs why, leaves
`/v1/email/recovery` unregistered, and goes on serving TokenReview and email
verification.

Four failures degrade this way: `--zitadel-service-account-key` empty while a recovery
template is set, the key file missing or unreadable, a key file that is not a service
account key, and `zitadel.NewSDK` returning an error. Each logs at error level and
names the flag to fix. Correct the flag and restart to get recovery back.

The line to alert on — self-serve recovery is off, everything else is healthy:

```
Account recovery endpoint disabled; its Zitadel client could not be built.
```

On 2026-09-22 none of this was true. Infra set `ACCOUNT_RECOVERY_TEMPLATE`, the
recovery client was built from the introspection key, the error came straight back out
of startup, and cluster authentication was down for about 9.5 minutes because of a mail
feature that never worked in the first place.

Setting either mail template without `--client-ca-file` is **still a hard startup
failure**, and deliberately so. A mail endpoint that anyone who can reach the Service
can call is worse than no mail endpoint.

## Flags

Infra never sets container args — it sets env vars, and this repo's bundle declares each
flag as `--flag=$(ENV)`. The env names below are what an overlay patches.

### authn-webhook (self-serve)

`config/base/services/authn-webhook/authn-webhook.yaml`

| Flag | Env | Default | Notes |
|---|---|---|---|
| `--account-recovery-template` | `ACCOUNT_RECOVERY_TEMPLATE` | `""` | Empty leaves the route unregistered. Setting it makes `--client-ca-file` mandatory. |
| `--account-recovery-allowed-origins` | `ACCOUNT_RECOVERY_ALLOWED_ORIGINS` | `""` | returnTo allowlist. **Empty rejects everything** — a missing value must never read as "allow any host". |
| `--account-recovery-expiry-minutes` | `ACCOUNT_RECOVERY_EXPIRY_MINUTES` | `60` | A copy of Zitadel's `PasswordlessInitCode` lifetime. If that changes and this does not, the mail starts lying. |
| `--account-recovery-cooldown` | `ACCOUNT_RECOVERY_COOLDOWN` | `2m` | Minimum gap between recovery mails for one user. `0` disables the cooldown. |
| `--account-recovery-max-per-hour` | `ACCOUNT_RECOVERY_MAX_PER_HOUR` | `5` | Recovery mails per user per hour. `0` disables the cap. |
| `--zitadel-service-account-key` | `ZITADEL_SERVICE_ACCOUNT_KEY_PATH` | `""` | The Zitadel **service account** key used to mint the registration code. **Not** `--zitadel-private-key`, which is the application key for introspection. Empty, or wrong, disables recovery and logs; it does not stop the server. The base mounts no secret for it. |
| `--mail-webhook-allowed-client-names` | `MAIL_WEBHOOK_ALLOWED_CLIENT_NAMES` | `""` | Client certificate CNs and/or URI SANs allowed to reach **both** mail endpoints. **Empty accepts any client the CA signed** and logs a startup warning. **Set this in production.** |

`--notification-namespace` and the `--email-verification-user-lookup-*` retry flags are
shared with verification; recovery adds no duplicates of them.

**mTLS is enforced at startup, not at request time.** Setting either mail template
without `--client-ca-file` makes the process refuse to boot, because controller-runtime
only requires client certs when a CA is configured — without it the endpoint would mail
a working code to any caller that can reach the Service.

**The CA proves the chain, not the identity.** `RequireAndVerifyClientCert` establishes
only that the caller holds a certificate this CA signed. Where one CA issues certs to
many workloads, that is *every* workload. `--mail-webhook-allowed-client-names` pins
which one is meant, by leaf certificate CN or URI SAN, matched exactly — `auth-ui` does
not admit `auth-ui-staging`. Leaving it empty is supported and is the shipped default,
but it logs

```
WARNING: mail endpoints accept any client signed by the CA; set --mail-webhook-allowed-client-names to pin the caller
```

at startup. **Treat that warning as a production blocker.** Every mail-endpoint request
logs the caller it resolved (`caller=<CN>`, else the first URI SAN, else `none`) on both
the accepted and the rejected path, so an incident review can name the workload rather
than only the CA.

**Rotating or revoking the client CA needs a rolling restart.** controller-runtime's
certwatcher watches the *serving* certificate; the client CA bundle is read once at
process start. Replacing the CA secret — or removing a compromised intermediate from it
— changes nothing for a running pod. Restart the Deployment and confirm the old client
is refused before calling the revocation done.

### apiserver (support backstop)

`config/base/services/apiserver/deployment.yaml`

| Flag | Env | Default | Notes |
|---|---|---|---|
| `--recovery-links-enabled` | `RECOVERY_LINKS_ENABLED` | `false` | The infra-owned switch. While false the create returns 503, so the milo role that authorises it can ship dormant. |
| `--account-recovery-support-template` | `ACCOUNT_RECOVERY_SUPPORT_TEMPLATE` | `""` | |
| `--account-recovery-complete-url` | `ACCOUNT_RECOVERY_COMPLETE_URL` | `""` | Where the mailed link lands. Parsed at startup — a malformed value fails the boot, not a support engineer's first request. |
| `--account-recovery-expiry-minutes` | `ACCOUNT_RECOVERY_EXPIRY_MINUTES` | `60` | |
| `--account-recovery-cooldown` | `ACCOUNT_RECOVERY_COOLDOWN` | `2m` | Minimum gap between support links for one user. `0` disables the cooldown. |
| `--account-recovery-max-per-hour` | `ACCOUNT_RECOVERY_MAX_PER_HOUR` | `5` | Support links per user per hour. `0` disables the cap. |
| `--notification-namespace` | `NOTIFICATION_NAMESPACE` | `milo-system` | |

With `--recovery-links-enabled=true`, both `--account-recovery-support-template` and an
absolute `--account-recovery-complete-url` become mandatory — the process refuses to
boot without them. Enabled with neither, the first support request would mint a live,
unrevocable code and then fail to build a usable mail, with no way to recall it.

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

**2. Flag on, unverified user returns 400.** Point at a user whose milo `User` has
`status.emailVerification` set to anything but `Verified` (an unset field counts):

```sh
kubectl get user <zitadel-user-id> -o jsonpath='{.status.emailVerification}'
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

## The per-user mail budget

Recovery is pre-authentication — the premise is a user who cannot authenticate — so the
requester can never be bound to the account. Any suggestion of the form "check `userId`
against the caller" is unimplementable here. The two controls that *do* apply to
unauthenticated recovery are the origin allowlist and a per-user budget.

The budget is `--account-recovery-cooldown` (default 2m) plus
`--account-recovery-max-per-hour` (default 5), enforced on **both** triggers. The source
of truth is the `Email` objects themselves, matched on the
`identity.miloapis.com/user` and `identity.miloapis.com/recovery-requested-by` labels —
not in-process state, because the webhook runs with replicas and a counter would reset
on every rollout.

**The budget is per user AND per trigger.** A self-serve flood spends only the
self-serve budget; it cannot deny support the backstop that exists precisely for when
self-serve has failed the user. Support is separately gated by a SubjectAccessReview,
so its own cap is a sanity bound on a stuck staff-portal retry loop rather than a
control against an attacker.

| Trigger | Over budget | Body |
|---|---|---|
| Self-serve | `429` | `try again later` — nothing else |
| Support | `429 TooManyRequests` | names the user and the constraint |

The self-serve refusal is deliberately bare. That endpoint is reachable with any
`userId`, so "you were mailed 40 seconds ago" would confirm the account exists and leak
its recovery activity.

**Both triggers fail closed.** If the `Email` list cannot be read, the request is
refused (`500`) rather than waved through: an unreadable list is not evidence that
nothing was sent, and the other behaviour would hand an attacker the bypass.

To check the budget by hand:

```sh
kubectl get emails -n milo-system \
  -l identity.miloapis.com/user=<zitadel-user-id> \
  --sort-by=.metadata.creationTimestamp \
  -o custom-columns=NAME:.metadata.name,BY:.metadata.labels['identity\.miloapis\.com/recovery-requested-by'],CREATED:.metadata.creationTimestamp
```

Deleting these objects resets the budget for that user, which is the manual override
when a genuine user has locked themselves out of recovery.

## Verifying the emailVerification writer (C11)

milo's waitlist controller gates the welcome and rejection mail on the
`status.emailVerification` field, and **only this component writes it** — from three
places, so a miss self-heals. An empty field means this provider has not synced the
user yet, and readers must treat it as unproven:

| Writer | When |
|---|---|
| `create-user-account` | At provisioning, from `GetUserByID.IsEmailVerified`. Best effort: a Zitadel error never fails the ack. |
| `POST /v1/actions/email-verified` | On `user.human.email.verified` (`Verified`) and `user.human.email.changed` (`Unverified`). |
| `UserSweeper` | Every sweep (10 min), from `ListHumanUsers().IsEmailVerified`. |

The sweeper **diffs before writing**: it compares the desired state against the
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
# 1. Pick a user and record the current value.
kubectl get user <id> -o jsonpath='{.status.emailVerification}'

# 2. Force a disagreement, then wait one sweep interval (10 min).
#    Any of these works: flip the address in Zitadel, or clear the field.

# 3. The field should be rewritten, and the counter should move.
kubectl get user <id> -o jsonpath='{.status.emailVerification}'
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
