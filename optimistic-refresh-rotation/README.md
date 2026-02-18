# Optimistic Refresh Token Rotation with Speculative Access Token Issuance

## Architecture
- Flask API in `backend/app.py`
- PostgreSQL as source of truth for provisional and final auth state
- SQLAlchemy models auto-created on startup
- In-process background verification thread consumes queued verification tasks

## Optimistic Flow
1. Client calls `POST /auth/optimistic-login` and immediately marks the user as authenticated locally.
2. API stores a `pending` session/attempt row and enqueues async verification.
3. Verification updates the row to `active` or `rolled_back`.
4. Client polls `GET /auth/session` or calls `POST /auth/verify` for state reconciliation.

## Frontend Optimistic State Model
- `localAuth.phase`: `optimistic_pending | active | rolled_back`
- `localAuth.sessionId`: provisional session identifier
- `localAuth.rollbackReason`: nullable server reason
- Reconciliation rules:
  - `pending` => keep optimistic UI and poll
  - `active` => commit durable authenticated state
  - `rolled_back` => clear tokens/session and navigate to recovery UI

## Failure Modes
- Duplicate verification calls
- Retry storms from flaky networks
- Expired verification artifacts
- Invalid credentials/assertions/tokens

## Rollback Strategy
- Server status transitions are monotonic: `pending -> active|rolled_back`
- `POST /auth/verify` is idempotent and safe under retries
- `GET /auth/session` always returns authoritative status for page-refresh recovery

## Latency Considerations
- Client can render authenticated shell instantly while verification is pending
- Verification can complete after request lifecycle through worker thread
- Poll interval should be tuned to avoid DB hot loops

## Security Risks
- Optimistic state can temporarily expose privileged UI before verification result
- APIs must still guard protected data by authoritative server status checks
- Rollback must revoke provisional client state immediately
- Replay prevention depends on one-time tokens/consumption flags in DB

## Run Locally
```bash
cp .env.example .env
docker compose up --build
```

## API Contract
### POST /auth/optimistic-login
Request shape depends on this variant.
Response example:
```json
{"session_id":"b9d7...","status":"pending","optimistic":true}
```

### POST /auth/verify
```json
{"session_id":"b9d7..."}
```
Response:
```json
{"status":"active","attempts":1,"rollback_reason":null}
```

### GET /auth/session?session_id=<id>
Response:
```json
{"session_id":"b9d7...","status":"pending"}
```

## Variant-Specific Request Examples
See endpoint handlers in `backend/app.py` for exact required fields for this variant.
