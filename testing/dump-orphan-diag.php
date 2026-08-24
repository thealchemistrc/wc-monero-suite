<?php

// One-off orphan diagnosis (2026-08-22): dump pushed pools + reservations + push log.
require_once dirname(__DIR__,4) . '/wp-load.php';

$addr = 'BbMY76PU8ioPxBBXcgmBJCd6pcfAjRt8vRBH2Fr6iqawUTKxT2wWVi8ihVK6T5mknJYq9JGnR2zaFZ6jrPEPwT4DBWepyBT';
global $wpdb;

echo "== test mode / address mode ==\n";
echo "test_mode=" . (function_exists('wc_xmr_test_mode') ? wc_xmr_test_mode() : '?') . "\n";
$s = function_exists('wc_xmr_settings') ? wc_xmr_settings() : array();
echo "address_mode=" . ($s['address_mode'] ?? '?') . " failover=" . ($s['address_failover'] ?? '?') . "\n";

foreach (array('mainnet','testnet','stagenet') as $net) {
    $pool = get_option("wc_xmr_push_{$net}_addresses", array());
    echo "\n== pool {$net}: " . count((array)$pool) . " entries ==\n";
    $i = 0;
    foreach ((array)$pool as $e) {
        if (is_array($e)) {
            $meta = isset($e['wallet_id']) ? ("wallet={$e['wallet_id']} acct=" . var_export($e['account_index'] ?? null, true) . " sub=" . var_export($e['subaddress_index'] ?? null, true) . " types=a:" . gettype($e['account_index'] ?? null) . "/s:" . gettype($e['subaddress_index'] ?? null)) : 'NO-META';
            $isTarget = (($e['address'] ?? '') === $addr);
            if ($i < 8 || $isTarget || ($e['subaddress_index'] ?? -1) == 157) {
                echo "  [" . substr($e['address'],0,10) . "...] idx=" . var_export($e['index'] ?? '(none)', true) . " {$meta}" . ($isTarget ? "  <== ORDER ADDRESS" : '') . "\n";
            }
        } else {
            echo "  BARE-STRING " . substr((string)$e,0,10) . "...\n";
        }
        $i++;
    }
}

$t = $wpdb->prefix . 'wc_xmr_reservations';
echo "\n== recent reservations ==\n";
$rows = $wpdb->get_results("SELECT id, order_id, address, wallet_id, account_index, subaddress_index, amount_xmr, min_amount_xmr, received_xmr, confirmations, status, reserved_at, expires_at FROM {$t} ORDER BY id DESC LIMIT 12");
foreach ((array)$rows as $r) {
    $mark = ($r->address === $addr) ? '  <== ORDER ADDRESS' : '';
    echo "  #" . $r->id . " order=" . $r->order_id . " w=" . $r->wallet_id . " acct=" . $r->account_index . " sub=" . $r->subaddress_index
        . " amt=" . $r->amount_xmr . " recv=" . $r->received_xmr . " confs=" . $r->confirmations . " st=" . $r->status
        . " exp=" . $r->expires_at . " addr=" . substr($r->address,0,10) . "..." . $mark . "\n";
}
if ($wpdb->last_error) echo "DB ERR: " . $wpdb->last_error . "\n";

echo "\n== push debug log (newest first, 25) ==\n";
$l = get_option('wc_xmr_push_debug_log', array());
$c = 0;
foreach (array_reverse((array)$l) as $e) {
    if (++$c > 25) break;
    $ts = isset($e['t']) ? gmdate('H:i:s', (int)$e['t']) : '?';
    $extra = $e; unset($extra['t'], $extra['type'], $extra['ip']);
    echo "  [{$ts}] " . ($e['type'] ?? '?') . ($extra ? ' ' . wp_json_encode($extra) : '') . "\n";
}
echo "=== END ===\n";
