<?php

require_once dirname(__DIR__,4) . '/wp-load.php';
echo "--- push debug log (all) ---\n";
$log = get_option( 'wc_xmr_push_debug_log', array() );
foreach ( array_reverse( (array)$log ) as $e ) {
    echo '[' . gmdate('H:i:s', (int)$e['t']) . '] ' . ($e['type'] ?? '?');
    $x = $e; unset($x['t'],$x['type'],$x['ip']);
    echo ($x ? ' ' . json_encode($x) : ''), "\n";
}
global $wpdb;
$rows = $wpdb->get_results("SELECT id,order_id,wallet_id,account_index,subaddress_index,status,received_xmr,confirmations FROM {$wpdb->prefix}wc_xmr_reservations ORDER BY id DESC LIMIT 3");
echo "\n--- newest reservations ---\n";
foreach ((array)$rows as $r) echo json_encode($r), "\n";
