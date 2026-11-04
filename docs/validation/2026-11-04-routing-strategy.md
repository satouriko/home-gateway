# Network routing strategy validation — 2026-11-04

The routing reviewer reads the current approved preferences on every evaluation. The default strategy requires persistent severe current-path degradation, collected public-service availability knowledge and an actual route-direction conflict. A faster alternative alone does not authorize a change. Public-source collection verifies provenance and literal quotations; interpretation of regional service policy remains the AI's responsibility.

## Implemented behavior

- Connection/failure observations retain the actual TCP/UDP destination port, route and failure timestamp. Ordinary later activity cannot refresh an old failure. Endpoint records are bounded and distinguish sampled counters from complete traffic accounting.
- HTTP rejection cannot qualify an alternative route: two-path comparisons may truthfully establish transport/HTTP reachability for 4xx/5xx, but any alternative business rejection blocks automatic adoption. Post-change HTTP acceptance also requires an actual 2xx/3xx response and an explicit endpoint acceptance receipt; 403/429/5xx or missing status triggers rollback. Application acceptance remains unverified.
- Local HTTP CONNECT acceptance is not target TCP success. The pinned Mihomo implementation acknowledges CONNECT before outbound dialing. A loopback accepting proxy with no target dial is covered by tests: TCP/unknown observations remain unknown (zero successful and zero failed target samples), cannot authorize routing, and do not trigger an invented HTTP443 probe. Actual TLS/HTTP exchanges provide their own stage evidence. Explicit HTTP200 content rejection also blocks eligibility and commit.
- Protected comparisons use the observed endpoint. TCP, TLS and HTTP response evidence are separate; unsupported UDP/QUIC stays unknown. HTTP errors do not become transport failures or logged-in application success. Structured region rejection is recorded separately, without response bodies.
- Cached comparisons retain one identity. New rounds must be independent and fresh, with matching policy, node, DNS and configuration identities, positive controls and attribution to the gateway probe's own socket.
- Automatic rules are exact domains. Explicit user suffix preferences and routing modes take precedence; survival/control domains cannot be automatically rewritten. Rules and managed exact DNS selections change together.
- Private source/comparison/knowledge records use file locking, atomic replacement, expiry, source-quote checks and a 2 MiB storage ceiling. They are runtime evidence, excluded from public backup.
- Changes re-evaluate current strategy and policy under the root transaction lock. Only an exact map delta is derived. The adapter must arm durable recovery before reloading, verify the actual exact rule and relevant transport stage plus controls, and checkpoint only its own transaction. Failure rolls back or leaves recovery armed.

## Verification

Executed from the isolated network worktree:

```sh
PYTHONPATH=src/operator python3 -m unittest discover -s tests/operator -q
python3 -m compileall -q src/operator tests/operator
git diff --check
```

All 268 Python tests passed. Added regressions include real compare_endpoint-to-EvidenceStore-to-public-source-requirement review chains rejecting 401/403/404/429/503 alternatives, preserving a successful 200 alternative, and post-reload HTTP rejection rollback. Other regressions cover actual endpoint/path timestamps, bounded storage, exact rules/DNS, HTTP business rejection, source quotation forgery, cached round identity, public-policy conflicts, unknown knowledge, stale/changed evidence, explicit user intent, the current runtime strategy, lock-before-read, stale-policy rejection and failed reload/rule/control rollback.

A read-only live probe loaded candidate code in memory and used the gateway's existing configured listener. Baidu matched GeoSite `cn` through DIRECT and Google matched the proxy rule set; both returned HTTP 200. Controller metadata identified each probe's own socket. No household configuration or client network setting changed and no forwarding service restarted. Exact DOMAIN attribution has positive/negative fixture coverage; no temporary production rule was installed.

## Integration boundary

Broker request validation, DSH tool schemas/workflow, incident lifecycle, backup allowlists, offline adapter wiring and final production deployment belong to the coordinated integration change. These modules do not themselves expose a new model privilege or declare a real application restored. Successful route verification covers the exact rule and observed transport stage; application acceptance and incident closure require their own evidence.
