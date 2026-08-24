# Vendored third-party crypto primitives

Pinned, minimal copies used by the pure-PHP blockchain scanner. Kept inline so
the gateway has zero Composer dependencies. Retain their original licenses:

| Path | Upstream | License |
|---|---|---|
| `monero/` | [monerophp](https://github.com/monero-integrations/monerophp) (`base58.php`, `Cryptonote.php`, `ed25519.php`, `Varint.php`, `load.php`) | MIT |
| `keccak/src/Keccak.php` | [kornrunner/php-keccak](https://github.com/kornrunner/PHP-Keccak) | MIT |

Scanner verification design follows [xmr-pay](https://github.com/SlowBearDigger/xmr-pay)
(MIT) — four independent guards (output ownership derivation, RingCT amount decode,
Pedersen commitment re-check, unlock/confirmation gates).
