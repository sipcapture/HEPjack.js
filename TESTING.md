# HEPjack testing guide

HEPjack is experimental. This document captures how to validate TLS SIP
interception and HEP export before running it on production systems.

**Do not test on production.** Use a lab Homer instance and a disposable SIP
stack.

## Prerequisites

- A [Homer](https://github.com/sipcapture/homer) capture node (Docker or bare
  metal) listening for HEP on UDP (default port `9060`).
- A SIP proxy or B2BUA with **TLS** enabled on SIP (or TLS WebSocket where
  applicable), using OpenSSL/`libssl` in the same process you attach to.
- Node.js 16+ on a **desktop or server** OS supported by the `frida` npm
  package (see [README](README.md#installation)).
- HEPjack installed from this repository (`npm install`).

## Quick start

Attach to the process name or PID of your TLS-enabled SIP application:

```bash
node hepjack.js -S <homer-host> -P 9060 -p <process-name-or-pid>
```

Example from early testing (FreeSWITCH):

```bash
node hepjack.js -S my.homer.ip -P 9060 -p freeswitch
```

Enable verbose logging while debugging (Frida traffic and parse attempts):

```bash
node hepjack.js -v -S 127.0.0.1 -P 9060 -p kamailio
```

Non-SIP payloads are dropped by default in this phase; use `-v` if Homer stays
quiet but you expect SIP on the TLS socket.

## What to verify

1. **Attach** — HEPjack prints that it attached and loaded the Frida script
   without errors.
2. **HEP flow** — Homer (or `heplify-server`) receives HEP3 packets when you
   place TLS SIP calls through the target.
3. **Completeness** — SIP methods, headers, and bodies in Homer match what you
   expect from the call scenario (INVITE/200/ACK/BYE, registrations, etc.).
4. **Correlation** — Optional `-X` / `-R` flags populate `correlation_id` when
   you need a custom SIP header or a literal log marker (for example
   `Call-ID: `) before the value on the same line.

## Platform checklist

Report results on [issue #2](https://github.com/sipcapture/HEPjack.js/issues/2)
with Homer version, SIP product version, TLS setup notes, and whether HEP
arrived complete.

| Platform              | Status        | Notes |
|-----------------------|---------------|-------|
| FreeSWITCH            | Tested        | See issue #2 |
| Asterisk              | Needs testing | |
| OpenSIPS              | Needs testing | |
| Kamailio              | Needs testing | |
| Other TLS proxy/B2BUA | Needs testing | |

## Reporting

Post on issue #2 with:

- Homer version and how it was deployed
- SIP product, version, and TLS configuration (port, cert source)
- HEPjack command line used
- Whether HEP arrived, and any gaps (missing messages, truncated bodies,
  one-way audio signaling only, etc.)

Maintainers can help with install or attach problems in that thread.
