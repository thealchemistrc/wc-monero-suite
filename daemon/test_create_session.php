<?php

/**
 * CLI script to create a test pairing session directly in the WordPress DB.
 * Run: php test_create_session.php
 * Outputs JSON with pairing_id and words for the E2E test.
 */

// Locate wp-load.php: --wp-load=... argument, WP_LOAD env var, then common layouts.
$wp_load = null;
foreach ( $_SERVER['argv'] ?? array() as $cli_arg ) {
    if ( strpos( $cli_arg, '--wp-load=' ) === 0 ) { $wp_load = substr( $cli_arg, 10 ); }
}
if ( empty( $wp_load ) && getenv( 'WP_LOAD' ) ) {
    $wp_load = getenv( 'WP_LOAD' );
}
if ( empty( $wp_load ) || ! file_exists( $wp_load ) ) {
    foreach ( array(
        __DIR__ . '/../../../../wp-load.php', 
        __DIR__ . '/../../../wp-load.php',
    ) as $candidate ) {
        if ( file_exists( $candidate ) ) { $wp_load = $candidate; break; }
    }
}

if ( empty( $wp_load ) || ! file_exists( $wp_load ) ) {
    die( json_encode( array( 'error' => 'wp-load.php not found. Pass --wp-load=/path/to/wp-load.php or set WP_LOAD.' ) ) );
}

require_once $wp_load;

// Load pairing class
require_once __DIR__ . '/../wc-monero-push/class-wc-xmr-push-pairing.php';

$result = WC_XMR_Push_Pairing::generate_session();

if ( is_wp_error( $result ) ) {
    echo json_encode( array(
        'error' => $result->get_error_message(),
        'code'  => $result->get_error_code(),
    ) ) . "\n";
    exit( 1 );
}

echo json_encode( $result, JSON_PRETTY_PRINT ) . "\n";