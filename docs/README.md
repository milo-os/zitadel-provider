# zitadel-provider Documentation

zitadel-provider is the only platform component that speaks the Zitadel API. Everything else
on the platform — Milo, the portal, auth-ui — reaches Zitadel state through this component or
not at all.

## Where to start

New to this component? Read [architecture.md](architecture.md) first. It explains that the
binary ships **four independent runtimes**, which is the single most important thing to
understand before reading anything else here — most confusion about this repo comes from
assuming it is one process.

## Layout

| Path | Contains |
|---|---|
| [architecture.md](architecture.md) | The four runtimes, what each does, and how they relate |
| [components/](components/) | Feature-level docs: how a user-facing capability works end to end |
| [runbooks/](runbooks/) | Operational and testing guides — how to exercise a thing locally |

### Components

| Doc | Covers |
|---|---|
| [passkey-authentication.md](components/passkey-authentication.md) | Passkey enrollment, login, the read-only `Passkey` kind, and the suspicious-login exemption |
| [suspicious-login-detection.md](components/suspicious-login-detection.md) | New-device/IP/fingerprint detection on `oidc_session.added` and its notification email |

### Runbooks

| Doc | Covers |
|---|---|
| [passkey-local-testing.md](runbooks/passkey-local-testing.md) | End-to-end passkey testing against a local stack |
| [identity-api-tests.md](runbooks/identity-api-tests.md) | Exercising the aggregated apiserver's identity kinds |
| [account-recovery.md](runbooks/account-recovery.md) | Recovery flags, verifying both triggers, the `emailVerification` writer, and the C9 gauge |

## Conventions

- **Component docs describe what exists.** If a capability is designed but not shipped, it
  does not get a component doc until the code lands. Docs that describe intent rather than
  behaviour rot silently and mislead exactly the people who trust them most.
- **Runbooks are reproducible.** A runbook that cannot be followed start to finish on a clean
  machine is a bug report, not documentation.
