<?php

require_once dirname(__DIR__,4) . '/wp-load.php';
global $wpdb;
$targets = array(
    'BbMY76PU8ioPxBBXcgmBJCd6pcfAjRt8vRBH2Fr6iqawUTKxT2wWVi8ihVK6T5mknJYq9JGnR2zaFZ6jrPEPwT4DBWepyBT',
    'BfjTpU2atoC8', // short prefix match below
);
$pool = get_option('wc_xmr_push_testnet_addresses', array());
echo "pool_total=" . count($pool) . "\n";
foreach ($pool as $e) {
    $a = is_array($e) ? ($e['address'] ?? '') : (string)$e;
    if (strpos($a, 'BbMY76PU8i') === 0 || strpos($a, 'BfjTpU2ato') === 0 || strpos($a, 'BYfSjriXCk') === 0) {
        echo "FOUND " . substr($a,0,10) . "... meta=" . json_encode(is_array($e) ? array_intersect_key($e, array_flip(array('wallet_id','account_index','subaddress_index'))) : 'NONE') . "\n";
    }
}
$t = $wpdb->prefix . 'wc_xmr_reservations';
echo "\nreservations (newest 6):\n";
$rows = $wpdb->get_results("SELECT id,order_id,wallet_id,account_index,subaddress_index,status,received_xmr,confirmations,address FROM {$t} ORDER BY id DESC LIMIT 6");
foreach ((array)$rows as $r) echo "  #{$r->id} order={$r->order_id} w={$r->wallet_id} acct={$r->account_index} sub={$r->subaddress_index} st={$r->status} recv={$r->received_xmr} confs={$r->confirmations} addr=" . substr($r->address,0,10) . "...\n";
