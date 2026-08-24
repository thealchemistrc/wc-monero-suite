<?php

require_once dirname(__DIR__,4) . '/wp-load.php';
$pl = get_option('wc_xmr_push_phone_log', array());
if (empty($pl['entries'])) { echo "phone log not uploaded yet\n"; exit; }
echo 'uploaded at=', gmdate('H:i:s', (int)$pl['t']), ' wallet=', ($pl['wallet'] ?? '?'), "\n";
foreach ( array_slice( array_reverse((array)$pl['entries']), 0, 45 ) as $e ) {
    echo '[', gmdate('H:i:s', (int)($e['t'] ?? 0)), '] ', str_pad($e['level'] ?? '', 5), ' ', ($e['msg'] ?? ''), "\n";
}
