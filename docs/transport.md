# Core Transport

Core provides a production-ready HTTP transport shared by all service clients.

## Connection Pool

```go
transport := &http.Transport{
    MaxIdleConns:        100,
    MaxIdleConnsPerHost: 10,
    MaxConnsPerHost:     0,              // unlimited
    IdleConnTimeout:     90 * time.Second,
    TLSHandshakeTimeout: 10 * time.Second,
    DisableKeepAlives:   false,
}
```

- Connections reused across concurrent requests
- Per-host idle limit prevents resource exhaustion
- Keep-alive avoids TLS handshake overhead on repeated calls
- All service clients share this pool

## Retry Logic

Implemented as a `RoundTripper` wrapper above the transport:

| Condition             | Behavior                                   |
| --------------------- | ------------------------------------------ |
| 429 Too Many Requests | Respect `Retry-After`, backoff, retry      |
| 5xx Server Error      | Exponential backoff, retry up to N times   |
| Network error         | Retry with backoff                         |
| 401 Unauthorized      | Reactive refresh, retry once               |
| 4xx (except 401, 429) | No retry — return error immediately        |

Service clients never implement their own retry.

## Response Handling (2xx)

| Status         | Meaning           | Handling                           |
| -------------- | ----------------- | ---------------------------------- |
| 200 OK         | Success with body | Parse body, return result          |
| 201 Created    | Resource created  | Parse body (created resource)      |
| 202 Accepted   | Async processing  | Return success, no body guaranteed |
| 204 No Content | Success, no body  | Return nil, do NOT parse body      |

## Concurrency Safety

- `*http.Client` is safe for concurrent use
- Token refresh serialized (mutex) — concurrent requests wait
- Connection pool handles concurrent requests without per-request setup
- Service clients usable concurrently without additional sync

## Configuration

```go
session, _ := core.Login(ctx, host, user, pass,
    core.WithMaxRetries(3),
    core.WithRetryBackoff(time.Second),
    core.WithMaxIdleConns(100),
    core.WithIdleTimeout(90 * time.Second),
)
```

## Per-Service Transport Wrapping

```text
Shared http.Transport (TCP/TLS pool)
     ↑           ↑           ↑
┌─────────┐ ┌─────────┐ ┌─────────┐
│ Drive   │ │ Mail    │ │ Lumo    │
│ Token:A │ │ Token:B │ │ Token:C │
│ UA:Drive│ │ UA:Mail │ │ UA:Lumo │
└─────────┘ └─────────┘ └─────────┘
```

Each service has its own `RoundTripper` that injects service-specific
headers (User-Agent, auth token) while sharing the underlying TCP pool.

The Proton API gates available endpoints by User-Agent string — a
Calendar User-Agent cannot call Drive endpoints.
