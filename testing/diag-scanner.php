<?php
/**
 * READ-ONLY diagnostic for scanner mode. Boots WordPress and dumps:
 *   - which XMR plugins are loaded / active
 *   - address_mode + test_mode + scanner settings (secrets masked)
 *   - view-key ↔ primary-address consistency check (enemy-plugin verify_keys logic)
 *   - daemon reachability + height from THIS process
 *   - open scanner reservations vs tip (stale checkpoints visible)
 *   - scheduled wc_xmr_poll events
 *   - recent WC_Logger records from source=wc-monero-native-scanner (last 40)
 *
 *   php diag-scanner.php
 */

require_once dirname( __DIR__, 4 ) . '/wp-load.php';

echo "SAPI=" . php_sapi_name() . " gmp=" . ( extension_loaded( 'gmp' ) ? 'Y' : 'N' ) . " bcmath=" . ( extension_loaded( 'bcmath' ) ? 'Y' : 'N' ) . "\n";

$active = get_option( 'active_plugins', array() );
echo "active_plugins:\n";
foreach ( (array) $active as $p ) { echo "  - {$p}\n"; }

$s = function_exists( 'wc_xmr_settings' ) ? wc_xmr_settings() : get_option( 'woocommerce_monero_settings', array() );
if ( ! is_array( $s ) ) { $s = array(); }

$mode      = $s['address_mode'] ?? '(unset)';
$testmode  = function_exists( 'wc_xmr_test_mode' ) ? wc_xmr_test_mode() : '(n/a)';
$daemon    = trim( (string) ( $s['scanner_daemon_url'] ?? '' ) );
$view_raw  = trim( (string) ( $s['scanner_view_key'] ?? '' ) );
$primary   = trim( (string) ( $s['scanner_primary_address'] ?? '' ) );
$restore   = (int) ( $s['scanner_restore_height'] ?? 0 );

echo "address_mode={$mode} test_mode={$testmode} restore_height={$restore}\n";
echo "scanner_daemon_url=" . ( $daemon !== '' ? $daemon : '(EMPTY)' ) . "\n";
echo "scanner_primary_address=" . ( $primary !== '' ? substr( $primary, 0, 10 ) . '...' . substr( $primary, -6 ) : '(EMPTY)' ) . "\n";
$vlen  = strlen( $view_raw );
$is_hex64 = (bool) preg_match( '/^[0-9a-fA-F]{64}$/', $view_raw );
echo "scanner_view_key len={$vlen} looks_hex64=" . ( $is_hex64 ? 'Y' : 'N (encrypted?)' ) . "\n";

// Decrypt like the poller does.
$view_key = $view_raw;
if ( $view_key && ! $is_hex64 && function_exists( 'wc_xmr_decrypt' ) ) {
    try { $dec = wc_xmr_decrypt( $view_key ); } catch ( Throwable $e ) { $dec = ''; }
    echo "decrypt: " . ( $dec ? 'OK (len=' . strlen( $dec ) . ')' : 'FAILED - poller would alert scanner_poll_no_creds EVERY cycle' ) . "\n";
    if ( $dec ) { $view_key = $dec; }
}
$is_hex64_after = (bool) preg_match( '/^[0-9a-fA-F]{64}$/', $view_key );
echo "effective view key hex64=" . ( $is_hex64_after ? 'Y' : 'NO - scanning impossible' ) . "\n";

// Key ↔ address consistency (the enemy plugin's verify_keys check).
if ( $is_hex64_after && $primary && class_exists( 'WC_Monero_Native_Scanner' ) === false ) {
    $scan_file = dirname( __DIR__, 1 ) . '/wc-monero-gateway/includes/class-wc-monero-native-scanner.php';
}
if ( $is_hex64_after && $primary && ! class_exists( 'MoneroIntegrations\MoneroPhp\Cryptonote' ) ) {
    require_once dirname( __DIR__ ) . '/wc-monero-gateway/vendor/monero/load.php';
}
try {
    $cn  = new MoneroIntegrations\MoneroPhp\Cryptonote( 'mainnet' );
    $dec = $cn->decode_address( $primary );
    $derived = $cn->pk_from_sk( strtolower( $view_key ) );
    $match = hash_equals( strtolower( (string) $dec['viewKey'] ), strtolower( $derived ) );
    echo "verify_keys: viewkey↔address match=" . ( $match ? 'YES' : '*** NO - WRONG VIEW KEY FOR THIS ADDRESS: scanner will silently find NOTHING ***' ) . "\n";
} catch ( Throwable $e ) {
    echo "verify_keys: threw - " . $e->getMessage() . "\n";
}

// Daemon reachability from this process.
if ( $daemon ) {
    $url = rtrim( $daemon, '/' ) . '/json_rpc';
    $r   = wp_remote_post( $url, array(
        'timeout' => 15,
        'headers' => array( 'Content-Type' => 'application/json' ),
        'body'    => wp_json_encode( array( 'jsonrpc' => '2.0', 'id' => '0', 'method' => 'get_last_block_header', 'params' => new stdClass() ) ),
    ) );
    if ( is_wp_error( $r ) ) {
        echo "daemon: ERROR - " . $r->get_error_message() . "\n";
    } else {
        $code = wp_remote_retrieve_response_code( $r );
        $body = json_decode( wp_remote_retrieve_body( $r ), true );
        $h    = isset( $body['result']['block_header']['height'] ) ? (int) $body['result']['block_header']['height'] : null;
        echo "daemon: HTTP {$code} height=" . ( null !== $h ? $h : '(no height - inspect body)' ) . "\n";
    }
}

// Open scanner reservations.
global $wpdb;
$t = $wpdb->prefix . 'wc_xmr_reservations';
$rows = $wpdb->get_results( "SELECT id, order_id, subaddress_index, checkout_height, status, received_xmr, confirmations, reserved_at, expires_at, LEFT(tx_hashes,20) AS th FROM {$t} WHERE wallet_id='scanner' ORDER BY id DESC LIMIT 12" );
echo "scanner reservations (latest " . count( (array) $rows ) . "):\n";
foreach ( (array) $rows as $row ) {
    printf( "  #%d order=%d idx=%d ckpt=%d %s recv=%.12f confs=%d reserved=%s expires=%s tx=%s...\n",
        $row->id, $row->order_id, $row->subaddress_index, $row->checkout_height, $row->status,
        (float) $row->received_xmr, (int) $row->confirmations, $row->reserved_at, $row->expires_at, $row->th );
}

// Cron.
echo "cron wc_xmr_poll next=" . ( wp_next_scheduled( 'wc_xmr_poll' ) ? gmdate( 'Y-m-d H:i:s', wp_next_scheduled( 'wc_xmr_poll' ) ) . 'UTC' : 'NOT SCHEDULED' ) . "\n";
echo "cron wc_xmr_release_expired next=" . ( wp_next_scheduled( 'wc_xmr_release_expired' ) ? gmdate( 'Y-m-d H:i:s', wp_next_scheduled( 'wc_xmr_release_expired' ) ) . 'UTC' : 'NOT SCHEDULED' ) . "\n";

// Recent scanner logs from WC_Logger (file-based handler).
$log_dir = defined( 'WC_LOG_DIR' ) ? WC_LOG_DIR : ( dirname( __DIR__, 4 ) . '/uploads/wc-logs/' );
echo "WC_LOG_DIR={$log_dir}\n";
$found = false;
foreach ( (array) glob( $log_dir . '*wc-monero-native-scanner*' ) as $f ) {
    $found = true;
    $lines = file( $f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
    echo "== tail of " . basename( $f ) . " (" . count( $lines ) . " lines) ==\n";
    foreach ( array_slice( $lines, -40 ) as $l ) { echo "  {$l}\n"; }
}
if ( ! $found ) { echo "(no wc-monero-native-scanner log files found)\n"; }

// Also any wc_xmr alerts log if present.
foreach ( (array) glob( $log_dir . '*wc-xmr*' ) as $f ) {
    $lines = @file( $f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
    if ( ! $lines ) continue;
    echo "== tail of " . basename( $f ) . " ==\n";
    foreach ( array_slice( $lines, -15 ) as $l ) { echo "  {$l}\n"; }
}

echo "=== END (read-only) ===\n";
