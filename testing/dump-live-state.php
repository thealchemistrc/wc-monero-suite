<?php

require_once dirname(__DIR__,4) . '/wp-load.php';
echo "SAPI=" . php_sapi_name() . " sodium=" . (extension_loaded('sodium')?'Y':'N') . " opc=" . ini_get('opcache.enable') . " vts=" . ini_get('opcache.validate_timestamps') . " rf=" . ini_get('opcache.revalidate_freq') . "\n";
$s = get_option('wc_xmr_push_pairing', array());
foreach ((array)$s as $id => $x) { echo "SESS $id status=" . ($x['status'] ?? '?') . " created=" . ($x['created_at'] ?? '?') . " exp=" . ($x['expires_at'] ?? '?') . " has_pk=" . (isset($x['server_kx_pk'])?'Y':'N') . " has_sk=" . (isset($x['server_kx_sk'])?'Y':'N') . "\n"; }
$l = get_option('wc_xmr_push_debug_log', array());
foreach (array_reverse((array)$l) as $e) { $t = isset($e['t']) ? gmdate('Y-m-d H:i:s', (int)$e['t']) . 'UTC' : '?'; $extra = $e; unset($extra['t'], $extra['type'], $extra['ip']); echo "[$t] " . ($e['type'] ?? '?') . " ip=" . ($e['ip'] ?? '?') . ($extra ? ' ' . wp_json_encode($extra) : '') . "\n"; }
echo "=== END ===\n";
