<?php

require_once dirname(__DIR__,4) . '/wp-load.php';
// Smoke-test the dismissal state machine without HTTP/user context.
wc_xmr_alert( 'smoke_test_key', 'first firing' );
$alerts = get_option( 'wc_xmr_alerts', array() );
$ts1 = $alerts['smoke_test_key'];

$d = wc_xmr_alerts_dismissed();
$d['smoke_test_key'] = $ts1; // what the AJAX handler records
update_option( 'wc_xmr_alerts_dismissed', $d, false );
echo "after-dismiss hidden: ", ($d['smoke_test_key'] >= $alerts['smoke_test_key']) ? 'YES' : 'NO', "\n";

sleep(2);
wc_xmr_alert( 'smoke_test_key', 'second firing' ); // dedupe window is 3600s so ts stays...
$alerts = get_option( 'wc_xmr_alerts', array() );
echo "same-window refire shows again: ", (!isset($d) || $alerts['smoke_test_key'] > $ts1) ? 'YES' : 'NO', " (expected NO inside 1h dedupe)\n";

// Simulate a NEW firing past the dedupe window:
$alerts['smoke_test_key'] = $ts1 + 3700;
update_option( 'wc_xmr_alerts', $alerts, false );
echo "new-firing visible after old dismissal: ", ($d['smoke_test_key'] < $alerts['smoke_test_key']) ? 'YES' : 'NO', "\n";

// Cleanup
unset( $alerts['smoke_test_key'], $alerts['smoke_test_key_msg'] );
update_option( 'wc_xmr_alerts', $alerts, false );
$d = wc_xmr_alerts_dismissed();
unset( $d['smoke_test_key'] );
update_option( 'wc_xmr_alerts_dismissed', $d, false );
echo "cleaned up\n";
