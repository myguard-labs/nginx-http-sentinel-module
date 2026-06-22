# nginx-http-sentinel-module

`ngx_http_sentinel_module` — a single access-phase **client-reputation + tarpit**
engine for nginx / angie. Fuses three defenses that all share one shape
("score the client, then act"):

1. **CrowdSec reputation** — consume crowd-sourced + local-WAF ban decisions
   (out of band; never blocks the request path).
2. **AI-scraper / bad-bot tarpit** — when the score is bad, serve a cheap,
   bounded garbage drip instead of a clean 403, starving LLM scrapers and
   hostile crawlers.
3. **JA4+ fingerprinting** — JA4 (TLS, from `ssl-fingerprint`) + JA4H (HTTP
   header order, computed here) feed the score and survive TLS randomization
   that defeats JA3/IP alone.

> **Status: planning / Phase 0.** No module code yet. The full phased build plan
> is in [TODO.md](TODO.md); the locked design decisions and safety rules are in
> [DESIGN.md](DESIGN.md). Read those before writing code.

## Why one module

All three are the same pipeline at one decision point (`PREACCESS`):

```
ClientHello/TCP ──ssl-fingerprint──► $ssl_ja4
request ──► [sentinel] ─► score = w1·crowdsec(ip,ja4)
                                 + w2·ja4_blocklist
                                 + w3·bot/UA signal
                                 + JA4H(headers, computed here)
            verdict:  low → allow
                      mid → challenge (js-challenge / captcha)
                      hi  → tarpit (bounded drip)
                      max → 403
```

## Design pillars (see DESIGN.md)

- **No network in the request path** — per-request is a pure shared-memory
  lookup. Reputation data is loaded out of band. No added latency, no
  slowloris-against-yourself.
- **Fail-open by default** — a lookup/zone error logs and allows; `closed` is
  opt-in.
- **Bounded tarpit** — global concurrent-connection cap, tiny timers, fixed
  buffers, hard max lifetime. Never a self-DoS.
- **Reuses the existing stack** — `ssl-fingerprint`, `keyval`, `bot-verifier`,
  `user-agent`, `js-challenge` / `captcha`.
- Zero new SSL patch: JA4 reuses `ssl-fingerprint`; JA4H is pure-HTTP and
  computed in-module.

## See also

- Sibling own-modules: `nginx-autocert-module`, `nginx-error-abuse-module`
  (tarpit prior-art + CI harness template), `nginx-strip-filter-module`,
  `nginx-cache-turbo-module`, `nginx-label-autoconf-module`.
- Ships in the deb.myguard.nl nginx/angie build (`/opt/packages`).

## License

MIT — see [LICENSE](LICENSE).
