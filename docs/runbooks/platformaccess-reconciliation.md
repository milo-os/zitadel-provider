# PlatformAccess / Zitadel User State Reconciliation

This document explains how the `PlatformAccessController` keeps a user's active/inactive
state in Zitadel aligned with the `PlatformAccess` resource's `spec.state`, and a bug that
could put that reconciliation into a permanent failure loop.

## How it works

`PlatformAccessController.ensureZitadelUserState` maps `spec.state` to an `expectActive`
boolean (only `Suspended` maps to `expectActive: false`) and then calls the Zitadel
`reactivate` or `deactivate` endpoint to align the user's state.

Zitadel only accepts these calls from specific source states:

- `reactivate` succeeds only when the user is currently `USER_STATE_INACTIVE`.
- `deactivate` succeeds only when the user is currently `USER_STATE_ACTIVE`.

## The bug

The original implementation treated "not active" as synonymous with "inactive":

```go
if expectActive {
    return r.Zitadel.ReactivateUser(ctx, userName)
}
return r.Zitadel.DeactivateUser(ctx, userName)
```

Zitadel's user state enum has more values than `ACTIVE`/`INACTIVE` — notably
`USER_STATE_INITIAL`, which a user sits in until they finish setting up credentials.

With the addition of **passkey authentication**, users can now remain in `INITIAL` for
longer than before: passkey registration is a separate step from account creation, so
there's a real window where a `PlatformAccess` wants a user active (e.g. `Approved`,
`Pending`) but the Zitadel user hasn't finished onboarding and is still `INITIAL`, not
`INACTIVE`.

When that happened, the controller called `ReactivateUser` on a user that wasn't
`INACTIVE`, and Zitadel rejected it:

```
{"code":9, "message":"User is not inactive (COMMAND-s5qqcz97hf)"}
```

### Why this wasn't "stuck", but was still broken

`Reconcile` returning a non-nil error causes controller-runtime to requeue
automatically with exponential backoff — so the controller *was* retrying. The issue
was that every retry hit the exact same precondition failure, since the Zitadel user's
state doesn't change on its own as a result of the failed call. The result was a
continuous stream of identical 400 errors and a `PlatformAccess` status stuck at
`ZitadelReady=False, Reason=SyncFailed` even though nothing about the retries could
ever fix it — only the user completing their own onboarding (or an admin intervening)
would change the underlying Zitadel state.

## The fix

`ensureZitadelUserState` now checks the actual source state before calling
`reactivate`/`deactivate`, and returns a `waitingForUserState` signal instead of
calling an API it knows will fail:

- Only calls `ReactivateUser` when the user is `INACTIVE`.
- Only calls `DeactivateUser` when the user is `ACTIVE`.
- Otherwise, it defers and reports `waitingForUserState: true`.

`Reconcile` uses that signal to:

- Requeue explicitly after 30s (`ctrl.Result{RequeueAfter: 30 * time.Second}`), so it
  keeps checking without needing an error to trigger backoff.
- Set `ZitadelReadyCondition` to `False` with `Reason: WaitingForUserState` — distinct
  from both `SyncFailed` and a successful sync — so `stateChanged()` keeps considering
  the object unreconciled and doesn't drop it after a single skipped attempt.

This turns a repeating hard failure into an accurate "waiting" status that keeps
polling and self-resolves once the user's Zitadel state allows the transition.
