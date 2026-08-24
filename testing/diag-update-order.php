<?php

require_once dirname(__DIR__,4) . '/wp-load.php';
global $wpdb;
$t = $wpdb->prefix . 'wc_xmr_reservations';
echo "--- live table columns ---\n";
$cols = $wpdb->get_results("SHOW COLUMNS FROM {$t}");
foreach ((array)$cols as $c) echo '  ', $c->Field, ' ', $c->Type, "\n";
echo "db last_error after SHOW: ", $wpdb->last_error ?: '(none)', "\n";

echo "\n--- direct update_order test on reservation #41 ---\n";
$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$t} WHERE id = %d", 41 ) );
if ( ! $row ) { echo "no row\n"; exit; }
$s = wc_xmr_settings();
$before = json_encode( $row );
try {
    wc_xmr_update_order( $row, 0.000028086955, 16, array( 'deadbeef' . str_repeat('a',56) ), $s );
    echo "update_order returned without fatal\n";
} catch ( Throwable $e ) {
    echo "THREW: ", get_class( $e ), ': ', $e->getMessage(), " @ ", $e->getFile(), ":", $e->getLine(), "\n";
}
$after = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$t} WHERE id = %d", 41 ) );
echo "before: ", substr($before,0,200), "\n";
echo "after : ", json_encode( array_slice( (array)$after, 0, 14 ) ), "\n";
$order = wc_get_order( $row->order_id );
echo "order #", $row->order_id, " status=", $order ? $order->get_status() : '?',
     " _xmr_received=", var_export( $order ? $order->get_meta('_xmr_received') : null, true ),
     " _xmr_confirmations=", var_export( $order ? $order->get_meta('_xmr_confirmations') : null, true ), "\n";
