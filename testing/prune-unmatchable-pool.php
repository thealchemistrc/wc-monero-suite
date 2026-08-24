<?php

// One-off repair (2026-08-22): drop metadata-less (pre-fix) entries from pushed
// address pools so pool_free reads true capacity and the device re-pushes a
// metadata-bearing batch. Idempotent; safe to run repeatedly.
require_once dirname(__DIR__,4) . '/wp-load.php';

foreach ( array( 'mainnet', 'testnet', 'stagenet' ) as $net ) {
    $key  = "wc_xmr_push_{$net}_addresses";
    $pool = get_option( $key, array() );
    if ( ! is_array( $pool ) ) { echo "{$key}: not an array, skipping\n"; continue; }
    $kept = array();
    $dropped = 0;
    foreach ( $pool as $e ) {
        if ( is_array( $e ) && ! empty( $e['address'] ) && isset( $e['wallet_id'], $e['subaddress_index'] ) ) {
            $kept[] = $e;
        } else {
            $dropped++;
        }
    }
    if ( $dropped > 0 ) {
        update_option( $key, array_values( $kept ), false );
    }
    echo "{$key}: kept=" . count( $kept ) . " dropped={$dropped}\n";
}
echo "=== END ===\n";
