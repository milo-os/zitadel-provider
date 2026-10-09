# Suspicious Login Detection

When a user signs in, Zitadel fires an `oidc_session.added` event to the actions server. The server compares the new session's IP address, browser and device, and browser fingerprint against the user's other live sessions. If any of those values have never been seen before, the login is flagged as suspicious and the user receives an email notification.

## How it works

1. Zitadel delivers the `oidc_session.added` event to `POST /v1/actions/session-added`.
2. The handler reads the current session's IP, user-agent description, and fingerprint ID from the event payload.
3. It calls the Zitadel API to list all existing sessions for that user, then removes the current session from the list. Zitadel deletes a session when the user signs out, so this list holds live sessions only. If no other live session is left, the check is skipped.
4. If the IP, the browser and device, or the fingerprint has not appeared in any previous session, `isSuspiciousLogin` returns true. The user-agent is reduced to its browser and device family (for example `Chrome on Mac`) before comparing, because the raw string carries the browser version and changes on every browser update.
5. `handleSuspiciousLogin` resolves a human-readable location (via `geolocateIP` on the GraphQL gateway) and parses the user-agent into browser/OS strings (via `parseUserAgent` on the GraphQL gateway). Both calls fall back gracefully if the gateway is unreachable.
6. An `Email` resource (`notification.miloapis.com/v1alpha1`) is created in the `milo-system` namespace, referencing the `emailtemplates.notification.miloapis.com-usersuspiciousemailtemplate` template. The notification system delivers it to the user.

## Zitadel configuration

This component requires **Zitadel Actions v2** to be configured with:

- **Target** — type `REST Webhook`, endpoint `https://localhost:8888/v1/actions/session-added`
- **Action** — type `Events`, condition `oidc_session.added`, referencing the target above

The endpoint uses `localhost` because the actions server runs as a sidecar container in the same Zitadel pod and only listens on `127.0.0.1:8888`.

## Dependencies

| Dependency | Purpose |
|---|---|
| Zitadel API (machine account) | List sessions for a user |
| GraphQL gateway (`graphql-gateway.graphql-gateway.svc.cluster.local:4000`) | Geolocation and user-agent parsing |
| `datum-control-plane-trust-bundle` | CA cert for TLS to the GraphQL gateway |
| `notification.miloapis.com` Email CRD | Deliver the alert email |
