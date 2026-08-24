# WC Monero Gateway — Native PHP Scanner

## Overview

The native scanner is a **pure-PHP** Monero payment scanner that detects incoming transactions using only the private view key and a Monero daemon's JSON-RPC API. No `monero-wallet-rpc`, no Node.js, no WASM — just PHP with GMP and BCMath extensions.

**LEAST SECURE:** This is the least secure payment verification mode. The private view key lives in server process memory. If the server is compromised, all incoming transactions can be extracted.

**MAY AFFECT SERVER PERFORMANCE:** Scanning blocks with PHP is slower than native code. Bounded scanning (`max_blocks`, `time_budget`) prevents PHP execution timeouts, but large scans will consume CPU.

**Attribution:** Inspired by [xmr-pay](https://github.com/SlowBearDigger/xmr-pay) (MIT license), which uses a Node.js + WASM approach. This is a pure-PHP reimplementation.

---

## Architecture

```
WordPress (PHP) → WC_Monero_Native_Scanner → Monero daemon JSON-RPC
                        
                   vendor/monero/  (ed25519, Keccak, base58, Cryptonote)
```

### Components

1. **`includes/class-wc-monero-native-scanner.php`** — Pure-PHP scanner class
2. **`vendor/monero/`** — Vendored crypto primitives (monerophp + php-keccak)
3. **Monero daemon** — Any `monerod` with `--rpc-bind-port` and `--confirm-external-bind`

---

## Prerequisites

### Required PHP Extensions

- **GMP** (GNU Multiple Precision) — for fast big-integer math
- **BCMath** — fallback big-integer math
- **cURL** — for daemon RPC calls
- **json** — for JSON encoding/decoding

Check with:
```bash
php -m | grep -E 'gmp|bcmath|curl|json'
```

If GMP is missing, enable it in `php.ini`:
```ini
extension=gmp
```

---

## How It Works

The scanner performs four verification checks on each transaction:

1. **Output Ownership** — Derives the one-time address `P = Hs(aR)G + B` and compares it to the transaction's output public key. This proves the output belongs to the merchant's address.

2. **Amount Decode** — XOR-decrypts the ECDH-masked amount using `Hs(aR || index)` as the shared secret. For v2 transactions, uses the `"amount"` prefix; for v1, uses double-hashed shared secret.

3. **Commitment Verification** (optional) — Checks the Pedersen commitment `C = xG + aH` where H is the hardcoded Monero generator point (`8b655970...`). This verifies the amount is not inflated.

4. **Confirmations / Unlock** — Checks the transaction has enough confirmations and is not time-locked.

---

## Usage

### Standalone Test

```bash
# Test crypto primitives only
php test-scanner.php --crypto-only

# Test with a real daemon
php test-scanner.php \
  --node=http://localhost:18081 \
  --address=4AbCdEf... \
  --viewkey=a1b2c3... \
  --txid=deadbeef... \
  --logging=4

# Scan a block range
php test-scanner.php \
  --node=http://localhost:18081 \
  --address=4AbCdEf... \
  --viewkey=a1b2c3... \
  --from=3100000 --to=3100010 \
  --max-blocks=30
```

### In WordPress

The scanner is auto-loaded by `wc-monero-gateway.php`. The gateway class can instantiate it:

```php
$scanner = new WC_Monero_Native_Scanner(
    array(
        'url'      => 'http://localhost:18081',
        'auth'     => 'none',
        'username' => '',
        'password' => '',
    ),
    $log_level  // 1=ERROR, 2=WARN, 3=INFO(default), 4=DEBUG
);

// Verify a single payment
$result = $scanner->verify_payment(
    $txid,
    $address,
    $viewkey,
    array(
        'require_commitment' => true,
        'tip'                => $height,
    )
);

// Scan a block range
$result = $scanner->scan(
    $address,
    $viewkey,
    $from_height,
    $to_height,
    array(
        'max_blocks'         => 30,
        'time_budget'        => 30.0,
        'require_commitment' => true,
        'tip'                => $height,
    )
);
```

---

## Logging Levels

| Level | Name   | Description                          |
|-------|--------|--------------------------------------|
| 1     | ERROR  | Only errors                          |
| 2     | WARN   | Errors + warnings                    |
| 3     | INFO   | Errors + warnings + info (default)   |
| 4     | DEBUG  | Everything — verbose trace output    |

---

## Security Considerations

1. **View Key Exposure** — The private view key is stored in WordPress options and used in PHP process memory. Use HTTPS for daemon connections if the daemon is remote.

2. **Daemon Trust** — The scanner trusts the daemon to return correct block data. Use a self-hosted daemon or a trusted remote node.

3. **Commitment Verification** — Enable `require_commitment` to verify Pedersen commitments. This catches amount manipulation but requires a non-pruned daemon for full `outPk` data.

4. **Bounded Scanning** — Always set `max_blocks` and `time_budget` to prevent PHP execution timeouts on large scans.

---

## Files

| File | Description |
|------|-------------|
| `includes/class-wc-monero-native-scanner.php` | Main scanner class |
| `vendor/monero/load.php` | Autoloader for crypto primitives |
| `vendor/monero/Cryptonote.php` | Cryptonote operations (key derivation, H point) |
| `vendor/monero/ed25519.php` | Ed25519 curve operations |
| `vendor/monero/base58.php` | Monero base58 encoding |
| `vendor/monero/Varint.php` | Varint encoding/decoding |
| `vendor/keccak/src/Keccak.php` | Keccak-256 hashing |
| `test-scanner.php` | Standalone CLI test script |

---

## Support

- **xmr-pay GitHub:** https://github.com/SlowBearDigger/xmr-pay
- **monerophp GitHub:** https://github.com/monero-integrations/monerophp
- **Monero generators source:** https://github.com/monero-project/monero/blob/master/src/crypto/generators.cpp