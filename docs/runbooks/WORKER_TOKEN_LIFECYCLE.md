# Worker-token lifecycle: EC2 and private RDS

## Decision and boundaries

Run cleanup inside existing backend containers, not EventBridge or a scheduled
ECS task. Every replica supervises a loop approximately every 60 seconds; a
PostgreSQL transaction advisory lock allows one sweep at a time. Each sweep
expires at most 500 eligible tokens and commits canonical audit records and its
heartbeat atomically. Retries back off to five minutes. Authorization rejects
expired tokens independently of cleanup availability.

The application retains tenant RLS. A dedicated NONLOGIN, NOBYPASSRLS maintenance
owner has narrowly scoped token-expiration and audit permissions. Application
credentials can execute only the maintenance API, not change its control tables,
read other tenants' tokens, or assume the maintenance role. Bootstrap/migration
credentials are operator-only and must never be placed in runtime containers.

## EC2/RDS deployment prerequisites

1. Keep RDS non-public in private subnets. Permit database ingress on 5432 only
   from the backend security group; separately review authorized operator and
   monitoring access. Do not expose PostgreSQL to the internet.
2. Enforce TLS on RDS. Set application `DATABASE_URL` to use
   `sslmode=verify-full&sslrootcert=/run/certs/rds-ca.pem`, with the trusted RDS CA
   bundle mounted read-only. Use the actual RDS hostname, not an unverified alias.
3. Run `python scripts/verify_ec2_rds.py` from the candidate backend environment.
   It checks verified-TLS configuration, negotiated SSL and runtime role flags.
   It does not prove subnet/security-group configuration: review that separately.
4. Provision an independent, random worker key of at least 32 bytes using the
   existing secrets delivery mechanism. Configure `WORKER_TOKEN_HMAC_KEY_V1` and
   `WORKER_TOKEN_HMAC_ACTIVE_VERSION=v1`; never reuse JWT/API/envelope secrets.
5. Set `WORKER_TOKEN_ISSUANCE_PAUSED=true` and `WORKER_CLEANUP_ENABLED=true`.
   Install and test independent monitoring below before declaring rollout ready.

The repository's existing ECS deployment support is retained, including a
one-time candidate preflight task. It is not a scheduled cleanup service. Its
existing database URL policy is not evidence of EC2 `verify-full` compliance.

## One-time cutover (operator-controlled)

Run commands from `backend/` in the candidate image. Obtain operator-only
`BOOTSTRAP_DATABASE_URL` through approved secret delivery; do not paste it into
logs. Keep the previous fleet accepting existing tokens until the drain finishes.

1. Pause issuance across all producer configurations. Run the established
   bootstrap `prepare`, migration to revision `043` using the migration role,
   and bootstrap `finalize-backend` using the operator role. Revision 043 also
   installs a database write barrier, blocking old binaries from issuing SHA
   tokens. Do not switch authentication to the candidate yet.
2. Run `python scripts/worker_token_cutover.py pause`. It waits for in-flight
   issuers' database locks and records the start using database time.
3. Wait **32 minutes**: 30-minute maximum token lifetime plus two minutes of clock
   allowance. Use `python scripts/worker_token_cutover.py status` to check both
   elapsed time and remaining active, unexpired legacy tokens. Do not alter
   timestamps or bulk revoke tokens to bypass this gate.
4. Run `python scripts/worker_token_cutover.py activate`. It refuses activation
   unless both gates pass. Fresh installations also start paused and follow the
   gate; no implicit fresh-database bypass exists.
5. In an isolated operator preflight environment using the candidate image,
   supply its configured worker keys and an all-tenant operator `DATABASE_URL`;
   run `python scripts/verify_worker_lifecycle.py`. It checks activation evidence,
   absence of valid legacy tokens, and availability of active/referenced keys.
   It does not verify key equality across replicas: secret version inventory is
   a separate deployment check. Never supply this operator URL to the API.
6. Switch all authentication consumers to the candidate, then set runtime
   `WORKER_TOKEN_ISSUANCE_PAUSED=false`. Confirm issuance, authorized use,
   cross-tenant denial, expiry denial, canonical audit and heartbeat progress.

Migration/preflight in the automated deployment intentionally fails closed until
the operator drain and activation are complete. Resume deployment after the
gate passes; do not remove the preflight to make first deployment succeed.

## Independent heartbeat monitoring: mandatory operational gate

The heartbeat is durable in RDS; logging from inside a backend container alone
cannot detect loss of the entire fleet. Run
`python scripts/check_worker_cleanup.py` every 60 seconds from an **existing
monitoring host outside the backend fleet**, with a dedicated monitor credential
granted schema USAGE and EXECUTE only on
`worker_maintenance.cleanup_health()`. Grant no table access, maintenance-role
membership, cleanup execution or administrator privileges to that credential.
Use verified TLS for its database connection too.

The command exits nonzero for missing/stale (>5-minute) heartbeat or database
failure. Connect that result to an owned alert receiver. For an existing
Prometheus installation, `--prometheus` emits aggregate health and observation
timestamps; publish this output atomically through the installation's textfile
collector, including output from unsuccessful checks. Load
`infra/observability/worker-cleanup-alerts.yml`. Monitor absence/staleness of the
monitor itself as well as cleanup health. Do not run the monitor only inside the
same containers it observes.

These repository files do **not** provision a monitor, collector, alert receiver
or notification routing. Before rollout approval, record the monitor owner,
receiver, scrape wiring and an actual delivered alert from stopping all cleanup
replicas, plus a monitor-stop alert and successful recovery. Reuse existing
monitoring infrastructure; no separate scheduled AWS cleanup resource is needed.

## Recovery and rotation

- Database failures retry with bounded backoff. A failed transaction cannot
  publish a successful heartbeat or partial expiration/audit outcome.
- Shutdown signals the loop; database statement/lock/connect timeouts bound work.
- Pause issuance if a key/configuration problem is found. Retain all key versions
  referenced by valid tokens and distribute identical values to every consumer.
- Roll back only to an HMAC-capable image preserving the database barrier and
  configured keys. Never restore SHA acceptance or downgrade revision 043.
- Cleanup scheduling is continuous; the 32-minute drain is a separate one-time
  credential transition, not a cleanup interval or alert threshold.
