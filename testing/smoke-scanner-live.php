<?php
/**
 * READ-ONLY live smoke test for scanner mode against the REAL configured node.
 * Boots WP, pulls the saved scanner creds (never printed), and runs:
 *   verify_keys → get_height → scan_all over the last 2 blocks (primary address).
 *
 *   php smoke-scanner-live.php
 */

require_once dirname( __DIR__, 4 ) . '/wp-load.php';

$s = function_exists( 'wc_xmr_settings' ) ? wc_xmr_settings() : array();
if ( ! is_array( $s ) ) { $s = array(); }
$creds = function_exists( 'wc_xmr_scanner_credentials' ) ? wc_xmr_scanner_credentials( $s )
	: array( 'view_key' => trim( (string) ( $s['scanner_view_key'] ?? '' ) ), 'primary_address' => trim( (string) ( $s['scanner_primary_address'] ?? '' ) ) );

echo "daemon(raw)=" . trim( (string) ( $s['scanner_daemon_url'] ?? '' ) ) . "\n";
if ( empty( $creds['view_key'] ) || empty( $creds['primary_address'] ) ) { echo "no usable creds\n"; exit( 1 ); }

require_once dirname( __DIR__, 2 ) . '/wc-monero-gateway/includes/class-wc-monero-native-scanner.php';

// The store's node (cakewallet, port 18081) is MAINNET - smoke against mainnet.
$sc = new WC_Monero_Native_Scanner(
	array( 'url' => trim( (string) $s['scanner_daemon_url'] ), 'auth' => 'none', 'username' => '', 'password' => '' ),
	3,
	'mainnet'
);

echo "normalized url=" . ( is_callable( array( $sc, 'get_network' ) ) ? '' : '' );
$vk = $sc->verify_keys( $creds['primary_address'], $creds['view_key'] );
echo "verify_keys: address_valid=" . ( ! empty( $vk['address_valid'] ) ? 'Y' : 'N' ) . " key_match=" . ( ! empty( $vk['key_match'] ) ? 'YES' : 'NO' ) . "\n";
if ( empty( $vk['key_match'] ) ) { exit( 1 ); }

$tip = $sc->get_height();
echo "height=" . ( null === $tip ? 'NULL (unreachable!)' : $tip ) . "\n";
if ( null === $tip ) { exit( 1 ); }

$t0 = microtime( true );
$res = $sc->scan_all( $creds['primary_address'], $creds['view_key'], $tip - 2, $tip, array(
	'max_blocks'         => 3,
	'time_budget'        => 60.0,
	'require_commitment' => true,
	'tip'                => $tip,
) );
$dt = round( microtime( true ) - $t0, 1 );

$m = is_array( $res ) ? $res : array();
echo "scan: found_matches=" . count( $m['matches'] ?? array() ) . " scanned_to=" . ( $m['scanned_to'] ?? '?' ) . " took={$dt}s\n";
$met = $sc->get_metrics();
printf( "metrics: rpc=%d blocks=%d txs=%d outputs=%d errors=%d elapsed=%.1fs\n",
	$met['rpc_calls'], $met['blocks_scanned'], $met['txs_checked'], $met['outputs_checked'], $met['errors'], $met['elapsed'] );
echo ( ( $met['errors'] === 0 && isset( $m['scanned_to'] ) && $m['scanned_to'] >= $tip - 2 ) ? "SMOKE PASS" : "SMOKE FAIL" ) . "\n";
exit( ( $met['errors'] === 0 ) ? 0 : 1 );
