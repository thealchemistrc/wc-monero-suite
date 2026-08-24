# WC Monero Suite — accept Monero in WooCommerce, self-custodial

**Two WordPress plugins plus a small Python daemon that accept Monero (XMR) in
WooCommerce — a cheap always-on device watches the wallet, so your web server
never touches a wallet key.**

| Component | Path | Runs on | Role |
|---|---|---|---|
| **1. WooCommerce Monero Gateway** | `wc-monero-gateway/` | WordPress | Checkout, address pool, reservations, order status, live progress page |
| **2. Monero Push Companion** | `wc-monero-push/` | WordPress | Receives encrypted+signed pushes from your device, applies them to orders |
| **3. Device daemon** | `daemon/xmr-pushd.py` | any always-on host next to `monero-wallet-rpc` | Watches the wallet, generates subaddresses, pushes updates |

The plugins detect each other and integrate automatically. Both also work standalone.
The core design rule: **the server never talks to the wallet.** Spend keys never
exist on the web server — not even in scanner mode, where at most the *view* key is used.

```
┌──────────────────────────┐   encrypted + signed POSTs           ┌──────────────────────────┐
│  Your device             │ ──────────────────────────────────▶ │  WordPress               │
│  xmr-pushd.py            │   {addresses} {confirmation} {log}   │  wc-monero-push          │
│  monero-wallet-rpc       │ ◀──── authenticated status blob ──── │  wc-monero-gateway       │
└──────────────────────────┘   (GET ?<status_param>=<blob>)       └──────────────────────────┘
```

---

## Table of contents

- [Why](#why)
- [How to use](#how-to-use)
  - [Step 0 — Install the two plugins](#step-0--install-the-two-plugins)
  - [Route A — Push mode (recommended)](#route-a--push-mode-recommended)
  - [Route B — Scanner mode (no device needed)](#route-b--scanner-mode-no-device-needed)
  - [Route C — Manual / Auto / Hybrid](#route-c--manual--auto--hybrid)
  - [Testing before real money](#testing-before-real-money)
- [What the customer sees](#what-the-customer-sees)
- [Payment modes compared](#payment-modes-compared)
- [How a payment flows end-to-end](#how-a-payment-flows-end-to-end)
- [Settings reference](#settings-reference)
- [Security model](#security-model)
- [Daily operation](#daily-operation)
- [Troubleshooting](#troubleshooting)
- [Developer notes](#developer-notes)
- [Repository layout](#repository-layout)
- [FAQ](#faq)
- [Security policy](#security-policy)
- [Credits & license](#credits--license)

---

## Why

Accepting Monero on WordPress usually means one of:

- running `monero-wallet-rpc` **on the web server** (bad: spend keys + attack surface
  exposed to the most internet-facing box you own), or
- polling a third-party API (bad: custody/privacy), or
- checking payments by hand (bad: doesn't scale).

This suite takes a different route: an always-on device you already own runs
`monero-wallet-rpc` plus a tiny stdlib-only Python daemon. The daemon *watches*
the wallet and *pushes* facts (fresh addresses, incoming payments) up to the
store over HTTPS. The store stays stateless with respect to keys and never
initiates wallet calls. If you don't want a dedicated device either, the built-in
[scanner mode](#route-b--scanner-mode-no-device-needed) verifies payments in pure
PHP using only the private *view* key and a public node.

Zero third-party APIs, zero custody, zero fees beyond the network's.
The push mode works entirely over ordinary web traffic, no port forwarding needed and can run on low-end hardware, unlike other solutions.

---

## How to use

### Step 0 — Install the two plugins

WordPress only scans **one folder level** inside `wp-content/plugins/`, so copy
each plugin folder individually:

```bash
git clone <this-repo>
cp -r <repo>/wc-monero-gateway  wp-content/plugins/
cp -r <repo>/wc-monero-push     wp-content/plugins/
```

(or zip each folder and upload via wp-admin → Plugins → Add New).

Then activate both in **wp-admin → Plugins**:

- *WooCommerce Monero Gateway*
- *Monero Push Companion* — only needed for push/pairing features

Activation creates the shared reservations table and schedules housekeeping cron.

### Route A — Push mode (recommended)

**1. Point the gateway at Push.**
Go to **WooCommerce → Settings → Payments → Monero (XMR)**:

- tick *Enable Monero payments*
- set **Address source = `Push`**
- set confirmation thresholds (`conf_processing`, default 1) and reservation hours
- Save.

**2. Create the shared secret.**
Go to **Settings → Monero Push**:

- click **Generate new key**
- click **Save Changes**
- click **Reveal**, copy the 64-character hex value.

**3. Set up the device** (any host that stays on: an old Android phone in Termux,
a laptop, a VPS, a Raspberry Pi):

1. Get `monero-wallet-rpc` running there and synced.
2. Copy `daemon/xmr-pushd.py` and `daemon/xmr-pushd.conf.example` onto it;
   rename the latter to `xmr-pushd.conf`.
3. Edit `xmr-pushd.conf`: paste the secret into `shared_secret_hex`, set
   `wp_url` to your store URL, point `wallet_rpc_url` at your local RPC
   (default `http://127.0.0.1:18089/json_rpc`), set `network`.
4. Run it:

   ```bash
   python3 xmr-pushd.py --debug      # stdlib-only - no pip dependencies
   ```

   Keep it alive with `daemon/xmr-push-start.sh` (tmux; auto-acquires the
   Termux wake-lock when available).

The daemon generates address batches automatically whenever the pool runs low,
and pushes every incoming payment within seconds of block inclusion.

**4. Verify.**
Back on **Settings → Monero Push**, open the **Debug log** panel at the bottom.
Healthy traffic shows `addresses` merges and later `confirm` events — never
`decrypt_fail`, `bad_timestamp`, or `sig_fail`. Then place a test order and
watch it advance from on-hold to Processing.


<b>**Alternative: pairing without copying secrets**</b>

On the same settings page, start a pairing session (you get three BIP39-derived
code words). Your `xmr-pushd.conf` only needs `wp_url` set for this (no secret required yet).
 
1. Go to **Settings → Monero Push** → start a pairing session. WordPress shows
   **three code words** plus the ready-made command.
2. On the device, run exactly what it says:
 
   ```bash
   python3 xmr-pushd.py --pair <word1> <word2> <word3>
   ```
 
   (the words identify the session; the store URL comes from your conf)
3. The device connects and both screens now display three **SAS words**.
   Compare them out loud or over a video call — never just trust the channel
   you typed the code words through.
4. Words match → click **Confirm** on the admin page. The device's signing key
   is authorized and the derived shared secret installs itself on both ends.
 
Pairing endpoints are rate-limited; unsigned pushes are rejected once any
device is authorized.

### Route B — Scanner mode (no device needed)

Give WordPress your **primary address + private view key** and a `monerod`
endpoint; the plugin derives a fresh subaddress per order and verifies payments
itself in pure PHP.

1. **WooCommerce → Settings → Payments → Monero (XMR)** → Address source = `Scanner`.
2. Fill in scanner daemon URL, primary address, private view key. Save — the URL
   is normalized automatically and credentials are self-checked (`verify_keys`);
   mismatches raise loud admin alerts instead of failing silently.
3. Needs PHP GMP (or BCMath), cURL, and a full (**non-pruned**) node.

Full guide: [`SCANNER-SETUP.md`](SCANNER-SETUP.md). CLI smoke test without WordPress:
`php wc-monero-gateway/test-scanner.php --crypto-only`.

> Trade-off: the view key sits in PHP memory during scans. It cannot move funds,
> but it links *all* your incoming transactions if the server leaks.

### Route C — Manual / Auto / Hybrid

Same settings page (**WooCommerce → Settings → Payments → Monero**):

- **Manual:** paste mainnet subaddresses (one per line) into the pool textarea.
  You match payments yourself; orders stay on-hold until you click
  *Mark XMR paid* on the orders list.
- **Auto:** paste one or more `monero-wallet-rpc` URLs into *Wallets (JSON)*.
  The poller creates subaddresses and polls transfers per open order
  (WP-Cron, scheduled only while orders are open).
- **Hybrid:** primary source + automatic failover to another source, with an
  admin alert whenever the fallback fires.

### Testing before real money

Under the same gateway settings, **Test mode** offers:

- `simulate` — fake addresses plus a *Simulate Payment* button in the order meta
  box that walks an order through every stage. Zero chain interaction.
- `testnet` — real wallet-rpc against test-network wallets.

Both are refused when WordPress reports a `production` environment unless you
tick the explicit override; an admin banner reminds you while active.

---

## What the customer sees

After checkout, the thank-you/order page shows address (QR + copy buttons),
exact XMR amount, countdown, and a live progress panel:

| Stage | Meaning |
|---|---|
| `awaiting` | nothing seen on-chain yet — page polls |
| `detected` | tx seen, below threshold confirmations — bar creeps |
| `underpaid` | seen but below `min_amount` — keeps polling so a top-up flips it forward |
| `confirmed` | paid at threshold confirmations — stops polling |
| `closed` | cancelled/failed/refunded |

Admin + customer e-mails carry address, amount, tx hashes; admins get a
*Mark XMR paid* quick-action on the orders list.

---

## Payment modes compared

| x | **Push** | **Scanner** | **Auto (wallet-rpc)** | **Manual / Hybrid** |
|---|---|---|---|---|
| Wallet keys on server | none | private **view** key only | none (RPC URL only) | none |
| Extra infrastructure | any always-on host + `monero-wallet-rpc` | reachable full `monerod` node | reachable `monero-wallet-rpc` | nothing |
| Detection latency | seconds after push | one cron cycle while orders open | same as scanner | human |
| Server CPU cost | ~zero | high-ish during scans | low | zero |
| Best for | production stores with a spare box | hosts without sidecars/devices | VPS already running a wallet | tiny stores |

## How a payment flows end-to-end

Push path shown; other paths converge at step 5.

1. **Address supply.** The device creates subaddresses via wallet-rpc and pushes
   `{type:"addresses"}` batches. The server validates each address, attaches
   `wallet_id/account_index/subaddress_index` metadata, and **merges** it into the
   per-network pool (merge-not-replace: entries backing open orders survive
   partial batches; a changed `wallet_id` clears stale entries).
2. **Checkout.** The gateway picks a free address, computes the XMR amount from
   the configured price source (rate locked per order), and inserts a reservation
   row carrying the address coordinates and a `min_amount_xmr` floor
   (underpayment tolerance).
3. **Payment arrives on-chain.** The daemon forces a wallet `refresh`, polls
   `get_transfers` (in + pool), groups transfers by subaddress index, and pushes
   `{type:"confirmation", received, confs, hashes[]}` on any change — pool
   payments pinned to `confs: 0`.
4. **Matching.** The endpoint resolves the push against the open reservation by
   `wallet_id + subaddress_index` (deterministic `ORDER BY id DESC`), with an
   address-lookup fallback for legacy rows. Unmatched pushes become `orphan`
   events + admin alerts instead of being dropped silently.
5. **Order update.** Everything converges in `wc_xmr_update_order()`: writes
   `_xmr_received/_xmr_confirmations/_xmr_tx_hashes` order meta and moves the
   reservation `reserved→detected→paid`; underpayments are recorded but never
   advance the order; at `conf_processing` → `payment_complete()` (Processing),
   at `conf_complete` → optional auto-complete.

Non-push detection runs through WP-Cron scheduled on-demand only while open
orders exist (~60 s after checkout, self-rescheduling): `auto` polls configured
wallet-rpc endpoints; `scanner` scans blocks from the order's per-order
`checkout_height` checkpoint to the current tip, fail-closed through four guards
(output ownership derivation, RingCT amount decode, Pedersen commitment re-check,
unlock/confirmation gates), bounded and checkpointed so slow hosts converge.

---

## Settings reference

### Gateway — WooCommerce → Settings → Payments → Monero (XMR)

| Setting | Values / default | Notes |
|---|---|---|
| Address source | `manual` `auto` `hybrid` `push` `scanner` | Primary supply strategy |
| Manual address pool | one address per line | manual/hybrid modes |
| Failover source | off / another source | alerts when used |
| Wallet selection | `round_robin` `random` `least_used` | multi-wallet auto mode |
| Price source | coingecko / kraken / fallback chain / `manual_rate` | rate locked per order |
| Underpayment tolerance | % (default 3) | sets `min_amount_xmr` floor |
| Reservation hours | float (default 2) | address held this long |
| `conf_processing` / `conf_complete` | int (1 / optional) | mark Processing / auto-complete |
| Poll interval / batch limit | minutes / rows | cron pacing for auto/scanner |
| Explorer URLs | template per line, `{txid}` placeholder | shown on order pages/e-mails |
| Test mode | `off` `simulate` `testnet` | production-gated |
| Scanner fields | daemon URL, primary address, view key *(encrypted)*, restore height, log level | see [SCANNER-SETUP.md](SCANNER-SETUP.md) |
| Tor/SOCKS options | onion gateway suffix, SOCKS5 relay, exit check | for `.onion` wallets / proxied FX APIs |

Secrets (wallet credentials, view key, push secret) are AES-encrypted at rest
(`enc:v1:`) when `WC_XMR_ENC_KEY` is defined in `wp-config.php`. Define it.

### Push Companion — Settings → Monero Push

| Setting | Default | Notes |
|---|---|---|
| Shared secret *(encrypted at rest)* | generated | or installed via ECDH pairing |
| POST field name | `msg` | mundane names recommended (anti-fingerprinting) |
| Status query param | `t` | GET param for authenticated status requests |
| Authorized devices | Ed25519 public key list | unsigned pushes accepted only while empty |
| Debug log | off | ring buffer (200 events) + viewer |

### Daemon — `daemon/xmr-pushd.conf`

Copy `xmr-pushd.conf.example`. Keys: `wp_url`, `wp_post_field`, `wp_status_param`,
`shared_secret_hex`, `wallet_rpc_url/user/pass`, `wallet_id`, `account_index`,
`network(mainnet|testnet|stagenet)`, `poll_interval`, `status_interval`,
`min_pool_free`, `batch_size`, `address_generation_cooldown`, `debug`,
`tls_verify` (**keep true in production**), `state_file`.
Runtime flags: `--edit` (TUI), `--debug`, `--pair <word1> <word2> [<word3>]`
(code words from the admin pairing screen; requires `wp_url` in the conf),
`--show-pubkey`,
`--prune-addresses` (+ `--prune-dry-run`, `--prune-keep=N`).
Never commit your real `xmr-pushd.conf` or `xmr-pushd-state.json` — both are gitignored.

---

## Security model

Wire protocol:

- **Encryption:** `crypto_secretbox` (XSalsa20-Poly1305) under a 32-byte shared
  secret; payload = urlsafe-base64(`nonce ‖ ciphertext`).
- **Authentication:** Ed25519 detached signature over the plaintext JSON,
  sent as `sig` + `pk` form fields; `pk` must be an authorized device.
- **Freshness:** `v:1` envelope + `ts` within ±300 s of server time. Every
  failure path answers with the identical generic HTTP-200 page, so probes learn
  nothing — diagnosis lives in the server-side debug log only.
- **Status channel:** GET `?<status_param>=<blob>`; responses are encrypted,
  strictly schema-validated blobs (pool stats + `active_indices` + server ts).
  Unknown keys make the *device* reject the blob, so protocol changes bump both sides.
- **At rest:** secrets encrypted via `WC_XMR_Crypto` when `WC_XMR_ENC_KEY` is defined.

Threat model:

| Risk | Mitigation |
|---|---|
| Server compromise cannot steal funds | No spend keys ever on the server; push/scanner hold at most a view secret |
| Forged confirmations marking orders paid | Valid Ed25519 sig from an authorized device + fresh `ts` + strict schema/range checks |
| Replay/delay attacks | Freshness window; per-index dedupe via daemon `last_seen` |
| Endpoint probing/enumeration | Identical generic responses on all failure paths; rate-limited pairing |
| Compromised/misbehaving device | Address audit flags reuse, index reassignment, range anomalies → admin alerts; prune requests unsigned-refused and re-checked server-side |
| Clock skew silently killing pushes | Daemon measures `server_offset` from status responses and stamps payloads through `server_now()`; corrections >60 s log loudly |
| Buyer pays after expiry | Late payments still land on expired-but-unreleased rows; truly released rows surface as `orphan` alerts for manual handling |
| Amount tampering / fake ecdh values | Scanner commitment guard re-derives mask and re-checks `C = mG + aH` on-chain |

**Residual risks we want you to see:** a compromised device *is* the wallet
operator (treat it like hardware); scanner mode's view key is linkable if the
server leaks; pruned nodes degrade scanner commitment checks (fail-closed);
WP-Cron reliability depends on traffic — a real cron trigger
(`wp-cli cron event run --due-now`) is recommended for quiet stores.

---

## Daily operation

Green signals: `confirm` / `addresses` events flowing in the debug log; orders
advancing to Processing; no new alert e-mails.
Investigate: `orphan`, `decrypt_fail`, `sig_*`, `bad_timestamp`, `pool_low`,
`pool_exhausted`, anything `scanner_*`.

Debug-log events:

| Event | Meaning | Action |
|---|---|---|
| `confirm` | Confirmation applied to an order | healthy |
| `addresses` | Address batch merged | healthy |
| `addresses_pruned` | Unused addresses dropped | intentional |
| `orphan` | Payment for coords with no open reservation | expected occasionally; investigate if repeated |
| `decrypt_fail` | Secret mismatch | re-copy secret or re-pair |
| `bad_timestamp` | Skew beyond ±300 s | fixed daemons self-heal via `server_offset`; sync NTP meanwhile |
| `sig_fail` / `sig_unknown_pk` | Bad signature / unpaired device | re-pair |
| `addr_reject` | Batch failed validation | check device `network` setting vs gateway mode |

Gateway-side admin alerts: `push_orphan`, `pool_low`, `pool_exhausted`,
`poll_wallet_missing_<id>`, `poll_fail_<id>`, `scanner_*`, `payment_complete_fail`.

Pruning unused subaddresses (`monero-wallet-rpc` cannot delete them, so pruning =
stop watching + remove from the server pool so they're never served again):

```bash
python3 xmr-pushd.py --prune-addresses --prune-dry-run   # preview
python3 xmr-pushd.py --prune-addresses                   # do it (+ server sync)
python3 xmr-pushd.py --prune-addresses --prune-keep=0    # purge ALL unused
```

Candidates are tracked indices that never received funds and hold no open order.
Requests are signed; the server re-checks open reservations before dropping
anything (checkout-race protection).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Order stays on-hold, no `confirm` events | Daemon down / transport broken | check daemon console; empty debug panel ⇒ pushes aren't arriving |
| `bad_timestamp` in log | Device clock skew | fixed daemons self-heal after first status check; sync NTP meanwhile |
| `decrypt_fail` repeatedly | Secret mismatch | re-copy secret or re-pair |
| `orphan` alerts | Reservation released/expired before payment | expected occasionally; resolve affected orders manually |
| Customer sees green but order on-hold | Old build lacking `underpaid` stage | update both sides |
| Pool never refills | Device can't reach wallet-rpc or status endpoint | watch the daemon's `Pool (...)` line |
| Nothing polls in auto/scanner | WP-Cron dead on quiet store | trigger real cron (`wp-cli cron event run --due-now`) |
| Scanner finds nothing despite payments | Wrong view key for the address | alerted via `scanner_creds_mismatch`; verify with `test-scanner.php --crypto-only` |
| Commitment warnings in scanner log | Pruned node omits commitments | use a full non-pruned node, or consciously accept degraded verification |

More depth: [`ARCHITECTURE.md`](ARCHITECTURE.md) (integration contracts),
[`SCANNER-SETUP.md`](SCANNER-SETUP.md) (scanner mode).


## Developer notes

Requirements: WordPress 5.8+, WooCommerce, PHP 7.4+ (**sodium** required;
scanner additionally GMP/BCMath + cURL). Device side: Python 3.8+, stdlib-only.

Everything under `testing/` is developer tooling — do not ship to production:

| Tool | Purpose |
|---|---|
| `sim-common.php` + `harness-port.php` | Offline sender-side RingCT simulation asserting the shipped scanner matches the upstream reference implementation |
| `rate-test.php` | FX-cache behavior assertions |
| `diag-scanner.php` | Read-only live diagnostic (credentials sanity, `verify_keys`, checkpoints, cron) |
| `smoke-scanner-live.php` | Live end-to-end scan against the configured node |
| `repro-push.php` / `repro-burst.php` | Craft signed+encrypted pushes against a dev store |
| `dump-*.php`, `diag-*.php`, `check-order-addr.php` | Read-only dumps of logs/state/mappings |

Daemon tests: `daemon/test_crypto.py`, `test_pairing*.py`, `test_e2e_simple.py`,
`test_full_e2e.py` (unit → pairing → wire-level E2E).
Scanner known-answer checks: `php wc-monero-gateway/test-scanner.php --crypto-only`.
Cross-plugin contracts: [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## Repository layout

```
.
├── README.md                           ← this file
├── LICENSE                             GPL-2.0-or-later
├── ARCHITECTURE.md                     cross-plugin integration contracts
├── SCANNER-SETUP.md                    scanner mode guide
├── wc-monero-gateway/                  plugin 1 (pure PHP, install-ready)
│   ├── wc-monero-gateway.php           bootstrap, DB schema, cron, admin columns/actions
│   ├── class-wc-gateway-monero.php     process_payment, thank-you UI + live JS, e-mails
│   ├── class-wc-xmr-poller.php         settings/helpers, pickers, cron pollers, update_order, ajax_status
│   ├── class-wc-xmr-rpc.php            wallet-rpc JSON-RPC client
│   ├── class-wc-xmr-testmode.php       simulate/testnet gating + meta box
│   ├── includes/class-wc-monero-native-scanner.php   pure-PHP view-key scanner
│   ├── vendor/                         monerophp + php-keccak (pinned; see LICENSE-NOTES)
│   └── test-scanner.php                standalone CLI scanner test
├── wc-monero-push/                     plugin 2 (pure PHP, install-ready)
│   ├── wc-monero-push.php              bootstrap, settings UI, address-injection filter
│   ├── class-wc-xmr-push-endpoint.php  routing, confirmations, pools, logger, pairing routes
│   └── class-wc-xmr-push-{crypto,sig,pairing,audit}.php
├── daemon/                             NOT a WordPress plugin - runs next to monero-wallet-rpc
│   ├── xmr-pushd.py                    the daemon (config, crypto, rpc, pushes, pairing, prune)
│   ├── xmr-pushd.conf.example          annotated config template
│   ├── xmr-push-start.sh               tmux launcher (wake-lock auto-detected)
│   └── test_*.py                       unit / pairing / E2E tests
└── testing/                            development-only diagnostics (never ship)
```

---

## FAQ

**Is this custodial?** No. Funds land directly in wallets you control. The store
holds addressing/verification data only; scanner mode additionally holds a view
key (incoming-tx privacy trade-off, documented above).

**Can the web server move money?** There is nothing to move with — no spend key
exists there in any mode.

**Do I need an Android phone?** No. Any machine that stays on works: laptop, mini
PC, VPS, Raspberry Pi. An old Android phone in Termux is simply the cheapest option.

**What happens if the device dies mid-order?** Open reservations keep existing;
push confirmations stop. Switch to `auto` or `scanner` mode as fallback, or
restore the daemon — its state rebuilds from the server's `active_indices`.

**Multiple stores / wallets?** Yes — `wallet_id` partitions pools and matching;
each daemon instance serves one store+wallet pair; multi-wallet JSON works in
auto mode.

**Does it work with HPOS / block checkout?** Built and tested against current
WooCommerce; HPOS and cart-checkout-blocks compatibility declared.

**Mainnet-ready?** Network-aware everywhere, but treat this as **beta software**:
run testnet/simulate first, keep amounts sane, monitor the alert stream.

**Can I donate / help Development?** You are always welcome to fork this project or to donate and fund developed that way.

xmr: 85zC5sgEff8KiZaaSv15D7jkgGVJhNSPhQWPnZwghbUdF3rBDU1rmCmeNwAxBABL9piK6xEW6T3vMZDCnFWMEn9KVsHmNBA

btc: bc1qxsv4egn3zfxy2nsdcn8p7hszuchgmdfxg2xnj0

---

## Security policy

Found a vulnerability? Please open a minimal issue describing the impact **or**
contact me privately before posting exploit details. Useful context:
plugin versions, debug-log event types (never post your shared secret, view key,
or authorized public keys), and whether `WC_XMR_ENC_KEY` was set.

Do not run hostile experiments against stores you don't own — the endpoint is
deliberately indistinguishable across failure modes precisely so probing buys
attackers nothing.

---

## Credits & license

- Scanner crypto inspired by [xmr-pay](https://github.com/SlowBearDigger/xmr-pay)
  (SlowBearDigger, MIT) — the pure-PHP port follows its four-guard verification design.
- Vendored primitives: [monerophp](https://github.com/monero-integrations/monerophp),
  php-keccak (kornrunner) — original licenses retained
  ([notes](wc-monero-gateway/vendor/LICENSE-NOTES.md)).
- Plugins licensed GPL-2.0-or-later ([LICENSE](LICENSE)).

> **Disclaimer:** This software handles real money. It has not been formally
> audited. Use at your own risk, start on testnet, and verify wallet backups
> before going live.
