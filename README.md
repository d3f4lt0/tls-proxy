```
 ████████╗██╗     ███████╗      ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗
    ██╔══╝██║     ██╔════╝      ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝
    ██║   ██║     ███████╗█████╗██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝ 
    ██║   ██║     ╚════██║╚════╝██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝  
    ██║   ███████╗███████║      ██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║   
    ╚═╝   ╚══════╝╚══════╝      ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝  
```
<div align="center">

> *you can't unsee what's inside the wire.*

</div>

> **MITM TLS interception proxy in Go** — dynamic CA, per-host certificate issuance, traffic inspection, and a composable tamper engine.

![Go](https://img.shields.io/badge/Go-1.22-00ADD8?style=flat-square&logo=go)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![CI](https://img.shields.io/github/actions/workflow/status/d3f4lt0/tls-proxy/ci.yml?style=flat-square&label=CI)

**Author:** [d3f4lt0](https://github.com/d3f4lt0)

---

## What This Is

A transparent MITM proxy that intercepts both plain HTTP and HTTPS traffic. It generates its own root CA on startup, issues per-host leaf certificates on demand, decrypts TLS sessions, and exposes every request/response pair to a structured inspection and tamper pipeline.

Built as a hands-on exploration of Go's `crypto/tls` internals, certificate chains, and the CONNECT proxy protocol — the same mechanics that power corporate DLP gateways, security scanners, and pentest tooling.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Client (browser / curl / app)                                   │
│  → set proxy: http://localhost:8080                              │
└───────────────────────────┬──────────────────────────────────────┘
                            │ HTTP CONNECT tunnel
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│  tls-proxy                                                       │
│                                                                  │
│  ┌─────────────┐    ┌──────────────┐    ┌────────────────────┐  │
│  │  Dynamic CA │───▶│  MITM Engine │───▶│  Tamper Engine     │  │
│  │             │    │              │    │  (hook pipeline)   │  │
│  │ • Root cert │    │ • Terminate  │    │                    │  │
│  │ • Per-host  │    │   client TLS │    │  OnRequest hooks   │  │
│  │   leaf cert │    │ • Re-encrypt │    │  OnResponse hooks  │  │
│  │ • LRU cache │    │   upstream   │    │  host glob match   │  │
│  └─────────────┘    └──────┬───────┘    └────────────────────┘  │
│                            │                                     │
│                     ┌──────▼───────┐                            │
│                     │  Inspector   │                             │
│                     │  • req/resp  │                             │
│                     │  • timing    │                             │
│                     │  • color log │                             │
│                     └─────────────┘                             │
└───────────────────────────┬──────────────────────────────────────┘
                            │ re-encrypted TLS
                            ▼
                    ┌───────────────┐
                    │  Target server│
                    └───────────────┘
```

---

## Quick Start

```bash
# Build
go build -o tls-proxy ./cmd/tls-proxy

# Run (generates ca.crt in current directory)
./tls-proxy -addr :8080

# Verbose mode (dump headers + bodies)
./tls-proxy -addr :8080 -v

# Passthrough mode (tunnel without interception)
./tls-proxy -addr :8080 -passthrough
```

Then configure your client to use `http://localhost:8080` as an HTTP/HTTPS proxy.

---

## Install the Root CA

On startup, `ca.crt` is written to the current directory. Install it in your trust store to avoid TLS warnings:

```bash
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt

# Linux (Debian/Ubuntu)
sudo cp ca.crt /usr/local/share/ca-certificates/tls-proxy.crt && sudo update-ca-certificates

# curl / one-shot
curl -x http://localhost:8080 --cacert ca.crt https://example.com
```

---

## Sample Output

```
  [#0001] 13:42:07.114  GET  https://example.com/  200  87ms
  [#0002] 13:42:07.882  GET  https://example.com/favicon.ico  404  12ms
  [#0003] 13:42:09.001  POST https://api.example.com/v1/data  201  203ms
```

Verbose mode (`-v`) additionally dumps all request/response headers and truncated body previews.

---

## Tamper Engine

Wire up request/response hooks programmatically:

```go
engine := tamper.New()

// Inject a header into every request
engine.Add(tamper.AddRequestHeader("*", "X-Forwarded-For", "1.2.3.4"))

// Rewrite response bodies matching a host glob
engine.Add(tamper.ReplaceResponseBody("*.example.com", "staging", "production"))

// Custom hook with full access to req/resp
engine.Add(&tamper.Rule{
    HostGlob: "api.target.com",
    Methods:  []string{"POST"},
    OnRequest: func(req *http.Request) error {
        req.Header.Set("Authorization", "Bearer <token>")
        return nil
    },
})
```

---

## Project Layout

```
tls-proxy/
├── cmd/tls-proxy/      ← CLI entrypoint, flags, wiring
├── internal/
│   ├── ca/             ← Dynamic CA: root cert + per-host leaf issuance + cache
│   ├── proxy/          ← MITM engine: HTTP + CONNECT handler, TLS termination
│   ├── inspector/      ← Traffic capture, timing, colored terminal output
│   └── tamper/         ← Rule pipeline: host glob + method match + hooks
└── .github/workflows/  ← CI: build + test + cross-platform release binaries
```

---

## Use Cases

- **Pentest / red team** — intercept and modify traffic from target apps
- **WAF research** — inspect what headers/signals enterprise proxies add
- **API debugging** — see exactly what your HTTPS clients send
- **Security tooling** — foundation for custom traffic analysis pipelines
- **Protocol learning** — study the TLS CONNECT proxy flow hands-on

---

## Related Projects

| Project | What it does |
|---|---|
| [`http2-inspector`](https://github.com/d3f4lt0/http2-inspector) | Frame-level HTTP/2 protocol tracer |
| [`fingerprint-audit`](https://github.com/d3f4lt0/fingerprint-audit) | Browser fingerprint diagnostic suite |
| [`anti-bot-engine`](https://github.com/d3f4lt0/anti-bot-engine) | Go middleware: rate limiting + entropy detection + honeypots |
| [`quantum-stealth-kernel`](https://github.com/d3f4lt0/quantum-stealth-kernel) | JA3/TLS impersonation + CDP fingerprint neutralization |

---

## License

MIT
