# Demo server

A small web sandbox for `draft-zink-xboundary-ai-text-watermark-verification-00`.
Standard-library Python; it imports and reuses `../tools/watermark_dns_tool.py`,
`../tools/tzsataitw.py`, and (when `reedsolo` is installed) `../tools/fairoze.py`,
and shells out to `openssl` and `dig`.

```
python3 server.py                      # http://127.0.0.1:8080
python3 server.py --host 0.0.0.0 --port 8080 --keys ./keys
```

## What the page does

| Tab | |
|---|---|
| **Watermark text** | sign pasted text with a demo key (`keys/`); the algorithm is fixed by the key's DNS `a=` tag (`tzsataitw-1` zero-width, `tzsataitw-2` look-alike letters). Picking the `fairoze-1` key instead serves one of the pre-generated `samples/fairoze-1/` texts — the demo can't run that generator (needs a GPU) |
| **Verify text** | detect the channel, recover the signature, fetch `p=` from DNS, run whichever detector each record's `a=` names, report `VALID` / `NOT VERIFIED` / `REJECTED (a= mismatch)` / `INVALID`. `fairoze-1` marks carry no locator, so they need a domain named explicitly |
| **Build a DNS record** | generate a key pair + the `_watermark-text` TXT record; download the private key (not stored server-side) |
| **Validate a domain** | crawl a domain's selectors, lint each, fetch and check every `d=` document |

## Before you expose it publicly

- **Demo keys only.** `keys/` must hold dedicated throwaway keys — see `keys/README.md`.
  Anyone who reaches the server can sign text as those domains.
- **Put it behind TLS** (nginx / caddy). The server speaks plain HTTP.
- Built-in guards: 60 requests/min per IP, 100 KB text cap, 250 KB body cap.
  `d=` fetches are HTTPS-only, public-IP-only, 64 KB / 5 s; redirects are followed
  (up to 5) with the HTTPS + public-IP checks re-run on every hop.
- `openssl` and `dig` must be on `PATH`. `fairoze-1` verification also needs
  `reedsolo` (`pip install -r ../tools/requirements.txt`); without it that one
  tab path is disabled and everything else still works.

Nothing is persisted — refresh and the session is gone.
