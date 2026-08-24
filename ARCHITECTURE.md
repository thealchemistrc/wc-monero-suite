# WC Monero Plugin Architecture — Cross-Plugin Relationships

> **Purpose:** Documents how the two WordPress plugins interact, what pushes to what,
> and the integration contracts between them.

---

## 1. The Two Plugins

### WooCommerce Monero Gateway (`wc-monero-gateway/`)
- **Role:** WooCommerce payment gateway. Handles checkout, order status tracking,
  address pool management, and background polling of `monero-wallet-rpc`.
- **Key files:**
  - `class-wc-gateway-monero.php` — `WC_Payment_Gateway` subclass, `process_payment()`,
    checkout UI, order page rendering
  - `class-wc-xmr-poller.php` — WP-Cron poller, `wc_xmr_pick_address()`,
    `wc_xmr_pick_from_manual()`, `wc_xmr_update_order()` (canonical order-status function),
    `wc_xmr_wallets()`, `wc_xmr_valid_addr()`, `wc_xmr_settings()`
  - `class-wc-xmr-rpc.php` — `WC_XMR_RPC` class, talks to `monero-wallet-rpc`
  - `class-wc-xmr-crypto.php` — `WC_XMR_Crypto`, AES encryption for settings at rest
  - `class-wc-xmr-testmode.php` — testnet detection/switching
  - `wc-monero-gateway.php` — bootstrap, DB table creation, cron scheduling

### Monero Push Companion (`wc-monero-push/`)
- **Role:** Receives address batches and payment confirmations from a remote device
  running `monero-wallet-rpc` via a Python daemon (`daemon/xmr-pushd.py`).
  Injects them into the gateway plugin's infrastructure.
- **Key files:**
  - `wc-monero-push.php` — bootstrap, settings page, `wc_xmr_push_inject_addresses()`
    (hooks `wc_xmr_manual_address_pool` filter)
  - `class-wc-xmr-push-endpoint.php` — `WC_XMR_Push_Endpoint`, HTTP endpoint handler,
    `process_confirmation()`, `process_addresses()`, `get_pool_stats()`
  - `class-wc-xmr-push-crypto.php` — `WC_XMR_Push_Crypto`, shared-secret
    `crypto_secretbox` encryption/decryption
  - `class-wc-xmr-push-sig.php` — `WC_XMR_Push_Sig`, Ed25519 signature verification
  - `class-wc-xmr-push-pairing.php` — `WC_XMR_Push_Pairing`, ECDH device pairing protocol
  - `class-wc-xmr-push-audit.php` — `WC_XMR_Push_Audit`, address audit (wallet swap detection)

### Device Daemon (`daemon/xmr-pushd.py`)
- **Role:** Python daemon running on an Android device (Termux + proot-distro Debian).
  Polls `monero-wallet-rpc` for new subaddresses and incoming payments, then pushes
  encrypted+signed JSON payloads to the WordPress server over HTTPS.
- **Pushes two payload types:**
  - `{type: "addresses", wallet_id, account_index, addresses: [{address, index}]}` —
    fresh subaddresses for the gateway's address pool
  - `{type: "confirmation", wallet_id, subaddress_index, received, confs, hashes}` —
    payment detected on a subaddress

---

## 2. Integration Contracts (What Connects to What)

### 2.1 Address Pool Injection — `wc_xmr_manual_address_pool` filter
- **Push plugin → Gateway plugin**
- **Hook:** `add_filter('wc_xmr_manual_address_pool', 'wc_xmr_push_inject_addresses', 10, 3)`
  (registered in `wc-monero-push.php`)
- **Gateway side:** `wc_xmr_pick_from_manual()` in `class-wc-xmr-poller.php` calls
  `apply_filters('wc_xmr_manual_address_pool', $pool, $network, $settings)` at L938
- **Push side:** `wc_xmr_push_inject_addresses()` in `wc-monero-push.php` merges
  stored addresses from `get_option('wc_xmr_push_{network}_addresses')` into the pool
- **Entry format:** Each entry is either a plain address string or an array:
  `['address'=>..., 'wallet_id'=>..., 'account_index'=>..., 'subaddress_index'=>..., 'exact_amount'?=>float]`
- **Critical:** The `wallet_id`/`account_index`/`subaddress_index` metadata on each
  entry is what links an address back to its confirmation push. Without it,
  `wc_xmr_pick_from_manual()` falls back to `'manual'/0` placeholder and
  confirmations become orphans (payments silently never registered).

### 2.2 Payment Confirmation → Order Status — `wc_xmr_update_order()` function
- **Push plugin → Gateway plugin**
- **Push side:** `WC_XMR_Push_Endpoint::process_confirmation()` in
  `class-wc-xmr-push-endpoint.php` looks up a reservation by
  `wallet_id + subaddress_index`, then calls `wc_xmr_update_order($row, $received, $confs, $hashes, $settings)`
- **Gateway side:** `wc_xmr_update_order()` in `class-wc-xmr-poller.php` is the
  canonical order-status-transition function. It compares received amount against
  `min_amount_xmr`, updates the reservation row, and transitions the WooCommerce
  order status (`on-hold` → `processing` → `completed`) based on confirmation thresholds.
- **Fallback lookup:** If the primary `wallet_id + subaddress_index` lookup fails,
  `process_confirmation()` searches the pushed address pool for the matching address
  string, then looks up the reservation by address. This recovers reservations
  created with stale `'manual'/0` metadata. The reservation is then patched with
  correct `wallet_id`/`subaddress_index` so future pushes hit the primary path.

### 2.3 Settings Encryption — `WC_XMR_Crypto` class
- **Gateway plugin → Push plugin**
- **Push side:** `wc_xmr_push_get_secret_plain()` in `wc-monero-push.php` uses
  `WC_XMR_Crypto::decrypt()` to read the shared secret from the database at rest
- **Gateway side:** `WC_XMR_Crypto` in `class-wc-xmr-crypto.php` provides
  `encrypt()`/`decrypt()` using AES-256-CBC with key `WC_XMR_ENC_KEY` from `wp-config.php`
- **Dependency:** Push plugin checks `class_exists('WC_XMR_Crypto')` and
  `WC_XMR_Crypto::enabled()` — if unavailable, the secret is stored in plaintext

### 2.4 Address Validation — `wc_xmr_valid_addr()` function
- **Gateway plugin → Push plugin**
- **Push side:** `WC_XMR_Push_Endpoint::process_addresses()` calls
  `wc_xmr_valid_addr($addr, $network)` to validate pushed addresses
- **Gateway side:** `wc_xmr_valid_addr()` in `class-wc-xmr-poller.php` validates
  Monero address format (mainnet: starts with 8, 95 chars; testnet: 95 chars)
- **Fallback:** If the function doesn't exist (gateway not loaded), validation is
  skipped — addresses are still stored with metadata

### 2.5 Gateway Settings — `wc_xmr_settings()` / `wc_xmr_gw()` functions
- **Gateway plugin → Push plugin**
- **Push side:** `process_confirmation()` calls `wc_xmr_settings()` to get the
  gateway's settings array (confirmation thresholds, tolerance, etc.) before
  calling `wc_xmr_update_order()`
- **Gateway side:** `wc_xmr_settings()` / `wc_xmr_gw()` in `class-wc-xmr-poller.php`
  instantiate `WC_Gateway_Monero` and return its settings

### 2.6 Alert System — `wc_xmr_alert()` function
- **Gateway plugin → Push plugin**
- **Push side:** `process_confirmation()`, `process_addresses()`, and
  `WC_XMR_Push_Audit::audit()` call `wc_xmr_alert()` to surface admin notices
- **Gateway side:** `wc_xmr_alert()` in `class-wc-xmr-poller.php` stores alerts
  in `wp_options` as `wc_xmr_alerts` and emails the configured alert address

### 2.7 Test Mode Detection — `wc_xmr_test_mode()` function
- **Gateway plugin → Push plugin**
- **Push side:** `process_addresses()` and `get_pool_stats()` call
  `wc_xmr_test_mode()` to determine whether to store/serve testnet vs mainnet addresses
- **Gateway side:** `wc_xmr_test_mode()` in `class-wc-xmr-testmode.php` returns
  'off', 'testnet', or 'simulate'

---

## 3. Shared Database Table

Both plugins read/write `{$wpdb->prefix}wc_xmr_reservations`:

| Column | Gateway usage | Push plugin usage |
|---|---|---|
| `address` | Written by `process_payment()` at checkout | Read by `process_confirmation()` fallback lookup |
| `order_id` | Written at checkout | Read to identify which order to update |
| `wallet_id` | Written at checkout (from `wc_xmr_pick_address()`) | Read in confirmation lookup; **patched** by fallback |
| `account_index` | Written at checkout | Read in confirmation lookup |
| `subaddress_index` | Written at checkout | Read in confirmation lookup; **patched** by fallback |
| `amount_xmr` | Written at checkout (fiat_total / rate) | Read by `wc_xmr_update_order()` to compare |
| `min_amount_xmr` | Written at checkout (amount × tolerance) | Read by `wc_xmr_update_order()` to compare |
| `received_xmr` | Updated by `wc_xmr_update_order()` | Written via `wc_xmr_update_order()` call |
| `tx_hashes` | Updated by `wc_xmr_update_order()` | Written via `wc_xmr_update_order()` call |
| `confirmations` | Updated by `wc_xmr_update_order()` | Written via `wc_xmr_update_order()` call |
| `status` | `reserved` → `detected` → `paid` | Read to find active reservations; updated via `wc_xmr_update_order()` |
| `expires_at` | Written at checkout | Read to filter active reservations |

**Created by:** Gateway plugin's activation hook in `wc-monero-gateway.php`.
The push plugin assumes this table already exists.

---

## 4. Data Flow — End to End

### 4.1 Address Pool Flow (Device → Server → Checkout)
```
xmr-pushd.py
  └─ create_address loop on monero-wallet-rpc
  └─ POST {type:"addresses", wallet_id, account_index, addresses:[{address,index}]}
     └─ WC_XMR_Push_Endpoint::handle_post() [class-wc-xmr-push-endpoint.php]
        └─ decrypt + verify signature
        └─ process_addresses()
           ├─ validate each address (wc_xmr_valid_addr)
           ├─ attach metadata (wallet_id, account_index, subaddress_index)
           ├─ merge with existing pool (merge_address_pool)
           └─ update_option('wc_xmr_push_{network}_addresses', $merged)

Customer checkout
  └─ WC_Gateway_Monero::process_payment() [class-wc-gateway-monero.php]
     └─ wc_xmr_pick_address($settings) [class-wc-xmr-poller.php]
        └─ (push mode) wc_xmr_pick_from_manual() with empty local pool
           └─ apply_filters('wc_xmr_manual_address_pool', ...)
              └─ wc_xmr_push_inject_addresses() [wc-monero-push.php]
                 └─ get_option('wc_xmr_push_{network}_addresses')
                 └─ merge pushed addresses into pool
              └─ ← returns pool with pushed addresses
           └─ pick least-recently-used address
           └─ extract wallet_id/subaddress_index from entry metadata
              (falls back to 'manual'/0 if missing)
     └─ INSERT into wc_xmr_reservations (address, order_id, wallet_id, subaddress_index, ...)
     └─ order status → on-hold
```

### 4.2 Confirmation Flow (Device → Server → Order Update)
```
xmr-pushd.py
  └─ get_transfers on monero-wallet-rpc (in + pool)
  └─ POST {type:"confirmation", wallet_id, subaddress_index, received, confs, hashes}
     └─ WC_XMR_Push_Endpoint::handle_post() [class-wc-xmr-push-endpoint.php]
        └─ decrypt + verify signature
        └─ process_confirmation()
           ├─ SELECT reservation WHERE wallet_id=? AND subaddress_index=? AND status IN ('reserved','detected')
           ├─ IF NOT FOUND:
           │  └─ find_pushed_address_by_coords(wallet_id, subaddress_index)
           │     └─ search pushed address pools for matching entry
           │  └─ SELECT reservation WHERE address=? AND status IN ('reserved','detected')
           │  └─ PATCH reservation SET wallet_id=?, subaddress_index=? (fix stale metadata)
           ├─ IF FOUND:
           │  └─ wc_xmr_update_order($row, $received, $confs, $hashes, $settings)
           │     [class-wc-xmr-poller.php]
           │     ├─ compare received vs min_amount_xmr
           │     ├─ UPDATE reservation SET received_xmr, confirmations, tx_hashes, status
           │     └─ transition WooCommerce order status
           │        ├─ on-hold → processing (payment detected, min confirmations met)
           │        └─ processing → completed (full confirmations)
           └─ IF STILL NOT FOUND:
              └─ log 'orphan' + admin alert
```

### 4.3 Background Polling Flow (Server-side, no device involved)
```
WP-Cron (every ~5 min)
  └─ wc_xmr_poll_cb() [class-wc-xmr-poller.php]
     └─ SELECT reservations WHERE status IN ('reserved','detected') AND wallet_id <> 'manual'
     └─ group by wallet_id
     └─ for each wallet:
        ├─ scanner wallet_id → wc_xmr_poll_scanner_batch() (pure-PHP blockchain scan)
        └─ RPC wallet_id → WC_XMR_RPC::call('get_transfers', ...)
           └─ wc_xmr_update_order() for each detected payment
```
**Note:** Push-mode reservations with `wallet_id='manual'` (stale metadata) are
**excluded** from the poller. They rely entirely on the push plugin's
`process_confirmation()` for payment detection. This is why the fallback lookup
in `process_confirmation()` is critical — without it, these orders are invisible
to both the poller and the push confirmation path.

---

## 5. WordPress Options Used

| Option key | Owner | Purpose |
|---|---|---|
| `wc_xmr_push_mainnet_addresses` | Push plugin | Stored address batch (mainnet) |
| `wc_xmr_push_testnet_addresses` | Push plugin | Stored address batch (testnet) |
| `wc_xmr_push_stagenet_addresses` | Push plugin | Stored address batch (stagenet) |
| `wc_xmr_push_secret` | Push plugin | Shared secretbox key (encrypted at rest via `WC_XMR_Crypto`) |
| `wc_xmr_push_post_field` | Push plugin | POST field name for encrypted payload (default: `msg`) |
| `wc_xmr_push_status_param` | Push plugin | GET param for status endpoint (default: `t`) |
| `wc_xmr_push_debug_log` | Push plugin | Debug log entries array |
| `wc_xmr_push_debug_log_enabled` | Push plugin | Enable debug logging (yes/no) |
| `wc_xmr_push_authorized_phones` | Push plugin | Authorized Ed25519 public keys |
| `wc_xmr_push_phone_log` | Push plugin | Last device log push (daemon logs) |
| `woocommerce_wc-gateway-monero_settings` | Gateway | Gateway settings (address_mode, wallets_json, etc.) |
| `wc_xmr_alerts` | Gateway | Admin alert log |
| `wc_xmr_db_version` | Gateway | DB schema version |

---

## 6. Function Dependency Map (Cross-Plugin)

### Push plugin calls Gateway plugin functions:
| Push plugin caller | Gateway function | Purpose |
|---|---|---|
| `wc_xmr_push_inject_addresses()` | (filter hook `wc_xmr_manual_address_pool`) | Inject pushed addresses into pool |
| `process_confirmation()` | `wc_xmr_update_order()` | Update order status from confirmation |
| `process_confirmation()` | `wc_xmr_settings()` | Get gateway settings |
| `process_addresses()` | `wc_xmr_valid_addr()` | Validate address format |
| `wc_xmr_push_get_secret_plain()` | `WC_XMR_Crypto::decrypt()` | Decrypt shared secret at rest |
| `process_confirmation()` | `wc_xmr_alert()` | Surface orphan/alert notices |
| `process_addresses()` | `wc_xmr_alert()` | Surface address rejection alerts |
| `get_pool_stats()` | `wc_xmr_test_mode()` | Determine active network |
| `process_addresses()` | `wc_xmr_test_mode()` | Determine target network key |

### Gateway plugin calls Push plugin hooks:
| Gateway caller | Push hook | Purpose |
|---|---|---|
| `wc_xmr_pick_from_manual()` | `wc_xmr_push_inject_addresses()` (via filter) | Get pushed addresses into pool |

### Shared (both plugins read/write):
| Resource | Gateway | Push |
|---|---|---|
| `wc_xmr_reservations` table | Creates schema, inserts at checkout, updates via poller | Reads for confirmation lookup, patches metadata |
| `wc_xmr_update_order()` | Defines and calls | Calls from `process_confirmation()` |

---

## 7. Address Mode Integration

The gateway supports several address modes. Push mode is the one that
integrates with this plugin:

| Mode | Address source | Push plugin involved? |
|---|---|---|
| `manual` | Settings textarea pool | No |
| `auto` | Live `monero-wallet-rpc` `create_address` | No |
| `hybrid` | RPC with manual fallback | No |
| `scanner` | Pure-PHP view-key blockchain scan | No |
| `push` | Pushed addresses from device via Push Companion | **Yes — this plugin** |
| `address_failover` | Secondary source when primary fails | If secondary is `push`, yes |

In push mode, the gateway zeros out its local textarea pool and relies entirely
on the `wc_xmr_manual_address_pool` filter (hooked by this plugin) to supply
addresses. The device is the sole address provider.

---

## 8. Security Boundaries

| Boundary | Mechanism |
|---|---|
| Device → Server transport | HTTPS (TLS) |
| Device → Server payload | `crypto_secretbox` encryption (shared 32-byte key) |
| Device → Server authenticity | Ed25519 signature (device's keypair, authorized on server) |
| Server shared secret at rest | AES-256-CBC via `WC_XMR_Crypto` (key from `wp-config.php`) |
| Replay protection | Timestamp validation (±5 min tolerance) |
| Pairing | ECDH key exchange with SAS word verification (out-of-band) |
| Device wallet security | View-only wallet (view key only, no spend key on device) |
| Rate limiting | Per-IP on pairing endpoints (5/min); push endpoints not limited (every 30s by design) |
