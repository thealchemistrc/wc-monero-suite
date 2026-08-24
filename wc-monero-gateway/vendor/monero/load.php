<?php
/**
 * Vendored, self-contained Monero crypto — no Composer, no PHP extension, no Node.
 * These are the verified primitives the WP-native proof/watch verifier stands on:
 * pure-PHP ed25519 (over GMP/BCMath), Keccak-256, base58, varint, and the cryptonote
 * key-derivation toolbox. We VENDOR them (rather than depend on Composer) so the plugin
 * works on any shared host and so we OWN the exact, audited bytes.
 *
 * Provenance (pinned for auditability):
 *   ed25519.php, base58.php, Varint.php, Cryptonote.php
 *     — monero-integrations/monerophp @ 25d4c5838b35cbf1fb55170b831e895681a7410a (MIT)
 *   Keccak.php
 *     — kornrunner/php-keccak (MIT) — the correct Monero Keccak-256 padding
 *
 * The ed25519 + key-derivation + amount-decode math is fixed in the Monero protocol
 * (unchanged for years) and was cross-checked against monero-ts on real stagenet
 * payments. monerophp itself is unmaintained, which is WHY we vendor + own it;
 * it runs clean on PHP 8.x.
 *
 * Requires BOTH the GMP and BCMath extensions: base58 is BCMath-only, the money math is
 * GMP-only, and ed25519 uses GMP when present (BCMath fallback works but is ~10x slower).
 */

// Allow loading both inside WordPress (ABSPATH defined) and from CLI test scripts.
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', dirname( __DIR__, 3 ) . '/' );
}

$wc_monero_vendor = __DIR__;
require_once $wc_monero_vendor . '/../keccak/src/Keccak.php';     // kornrunner\Keccak
require_once $wc_monero_vendor . '/base58.php';                    // MoneroIntegrations\MoneroPhp\base58
require_once $wc_monero_vendor . '/Varint.php';                    // ...\Varint
require_once $wc_monero_vendor . '/ed25519.php';                   // ...\ed25519
require_once $wc_monero_vendor . '/Cryptonote.php';                // ...\Cryptonote (uses kornrunner\Keccak + the above)