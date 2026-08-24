<?php

require_once dirname(__DIR__,4) . '/wp-load.php';
global $wpdb;
echo 'debug_log_enabled=', var_export(get_option('wc_xmr_push_debug_log_enabled','(unset)'),true),
     ' post_field=', var_export(get_option('wc_xmr_push_post_field','(unset)'),true), "\n";
echo 'phones=', count((array)get_option('wc_xmr_push_authorized_phones',array()));
foreach ((array)get_option('wc_xmr_push_authorized_phones',array()) as $p) {
    echo ' pk=', substr($p['pk'] ?? '?',0,12),'... seen=', $p['last_seen'] ?? 0;
} echo "\n";
echo "--- newest 15 debug events ---\n";
$log = (array) get_option('wc_xmr_push_debug_log', array());
foreach ( array_slice( array_reverse($log), 0, 15 ) as $e ) {
    echo '[', gmdate('H:i:s',(int)$e['t']), '] ', ($e['type'] ?? '?');
    $x=$e; unset($x['t'],$x['type'],$x['ip']); echo ($x?' '.json_encode($x):''), "\n";
}
echo "(total: ", count($log), ")\n";
foreach ( $wpdb->get_results("SELECT id,order_id,wallet_id,subaddress_index,status,received_xmr,confirmations FROM {$wpdb->prefix}wc_xmr_reservations ORDER BY id DESC LIMIT 4") as $r ) {
    echo "#{$r->id} order={$r->order_id} w={$r->wallet_id} sub={$r->subaddress_index} st={$r->status} recv={$r->received_xmr} confs={$r->confirmations}\n";
}
