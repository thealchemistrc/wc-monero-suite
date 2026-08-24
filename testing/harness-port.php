<?php
/**
 * Harness B - run the SAME sender-side simulated payments through the PORTED
 * scanner (WC_Monero_Native_Scanner) shipped in wc-monero-gateway.
 *
 *   php harness-port.php
 */

if ( ! defined( 'ABSPATH' ) ) { define( 'ABSPATH', __DIR__ . '/' ); }
if ( ! function_exists( 'wp_json_encode' ) ) {
	function wp_json_encode( $data, $flags = 0 ) { return json_encode( $data, $flags ); }
}

require_once dirname( __DIR__, 2 ) . '\\wc-monero-gateway\\vendor\\monero\\load.php';
require_once dirname( __DIR__, 2 ) . '\\wc-monero-gateway\\includes\\class-wc-monero-native-scanner.php';
require_once __DIR__ . '/sim-common.php';

use MoneroIntegrations\MoneroPhp\Cryptonote;

$cn = new Cryptonote( 'mainnet' );

// Node config never touched offline: detect_in_tx() performs no RPC.
$sc = new WC_Monero_Native_Scanner(
	array( 'url' => 'http://127.0.0.1:1', 'auth' => 'none', 'username' => '', 'password' => '' ),
	1, // ERROR-only logging so the harness output stays readable
	'mainnet'
);

$ok = xmr_sim_run(
	'PORTED WC_Monero_Native_Scanner',
	array(
		'cn'     => $cn,
		'detect' => function ( $tx, $addr, $vk ) use ( $sc ) {
			return $sc->detect_in_tx( $tx, $addr, $vk );
		},
	)
);

exit( $ok ? 0 : 1 );
