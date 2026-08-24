<?php

require_once dirname(__DIR__,4) . '/wp-load.php';
set_transient( 'wc_xmr_push_request_phone_log', 1, 600 );
echo "phone-log request SET (daemon uploads its log on next status cycle)\n";
$o = wc_get_order(857);
echo 'order857 addr=', $o ? $o->get_meta('_xmr_address') : '?', "\n";
echo 'order857 sub=', var_export($o ? $o->get_meta('_xmr_subaddress_index') : null, true), "\n";

$statePath = dirname(__DIR__) . '/daemon/xmr-pushd-state.json';
$s = is_readable($statePath) ? json_decode(file_get_contents($statePath), true) : null;
if (!is_array($s)) { echo "state: missing/unparseable at $statePath\n"; exit; }
$gi = $s['generated_indices'] ?? array();
echo 'generated: count=', count($gi), ' max=', $gi ? max($gi) : '-',
     ' has262=', in_array(262, $gi, true) ? 'Y' : 'N',
     ' has261=', in_array(261, $gi, true) ? 'Y' : 'N', "\n";
echo 'active_watch=', json_encode($s['active_watch'] ?? null), "\n";
echo 'last_seen[261]=', json_encode($s['last_seen']['261'] ?? null),
     ' [262]=', json_encode($s['last_seen']['262'] ?? null), "\n";
echo 'server_offset=', var_export($s['server_offset'] ?? null, true), "\n";
echo 'state keys=', json_encode(array_keys($s)), "\n";
