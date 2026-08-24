<?php

require_once dirname(__DIR__,4) . '/wp-load.php';
global $wpdb;
$s = wc_xmr_settings();
echo "conf_processing=", var_export($s['conf_processing'] ?? null, true),
     " conf_complete=", var_export($s['conf_complete'] ?? null, true),
     " address_mode=", ($s['address_mode'] ?? '?'), "\n";
$t = $wpdb->prefix . 'wc_xmr_reservations';
foreach ( $wpdb->get_results("SELECT id,order_id,wallet_id,subaddress_index,status,received_xmr,confirmations FROM {$t} ORDER BY id DESC LIMIT 5") as $r ) {
    echo "#{$r->id} order={$r->order_id} w={$r->wallet_id} sub={$r->subaddress_index} st={$r->status} recv={$r->received_xmr} confs={$r->confirmations}\n";
}
echo "--- orders 853-855 meta ---\n";
foreach ( array(853,854,855) as $oid ) {
    $o = wc_get_order($oid);
    if (!$o) { echo "#$oid missing\n"; continue; }
    echo "#$oid st=", $o->get_status(), " recv=", var_export($o->get_meta('_xmr_received'),true), " confs=", var_export($o->get_meta('_xmr_confirmations'),true), "\n";
}
echo "--- newest 20 debug events ---\n";
$log = (array) get_option('wc_xmr_push_debug_log',array());
foreach ( array_slice( array_reverse($log), 0, 20 ) as $e ) {
    echo '[', gmdate('H:i:s',(int)$e['t']), '] ', ($e['type'] ?? '?');
    $x=$e; unset($x['t'],$x['type'],$x['ip']); echo ($x?' '.json_encode($x):''), "\n";
}
echo "(total entries: ", count($log), ")\n";
