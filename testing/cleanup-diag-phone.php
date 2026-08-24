<?php

// Remove the leaked diagnostic device (repro-push.php first run crashed after add_phone).
require_once dirname(__DIR__,4) . '/wp-load.php';
$phones = get_option('wc_xmr_push_authorized_phones', array());
foreach ((array)$phones as $p) {
    echo 'pk=', substr($p['pk'] ?? '?', 0, 16), '... label=', var_export($p['label'] ?? '', true),
         ' added=', $p['added'] ?? 0, ' seen=', $p['last_seen'] ?? 0, "\n";
}
// The leaked key was added ~2026-08-22 16:04 UTC with label 'local-diag-temp' and never seen.
foreach ((array)$phones as $i => $p) {
    if (($p['label'] ?? '') === 'local-diag-temp') {
        unset($phones[$i]);
        echo "REMOVED leaked diag device: ", substr($p['pk'],0,16), "...\n";
    }
}
update_option('wc_xmr_push_authorized_phones', array_values($phones), false);
echo 'remaining=', count($phones), "\n";
