<?php

// Transport repro: send properly encrypted+signed pushes to the live site and
// record exactly what comes back + what the endpoint logs.
require_once dirname(__DIR__,4) . '/wp-load.php';

update_option( 'wc_xmr_push_debug_log_enabled', 'yes', false );
echo "debug log ENABLED\n";

// Temp authorized device so the signature path is exercised like the real daemon.
$kp = sodium_crypto_sign_keypair();
$pk_hex = strtolower( bin2hex( sodium_crypto_sign_publickey( $kp ) ) );
$sk = sodium_crypto_sign_secretkey( $kp );
WC_XMR_Push_Sig::add_phone( $pk_hex, 'local-diag-temp' );

$secret = get_option( 'wc_xmr_push_secret', '' );
if ( strpos( $secret, 'enc:v1:' ) === 0 && class_exists( 'WC_XMR_Crypto' ) ) {
    $d = WC_XMR_Crypto::decrypt( $secret );
    if ( $d !== '' && $d !== null ) $secret = $d;
}
$key = hex2bin( $secret );
$url = 'https://localhost/shop/';
echo "target=$url\n";

function make_payload( $key, $sk, $plain ) {
    $nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
    $ct = sodium_crypto_secretbox( $plain, $nonce, $key );
    $enc = sodium_bin2base64( $nonce . $ct, SODIUM_BASE64_VARIANT_URLSAFE );
    $sig = sodium_crypto_sign_detached( $plain, $sk );
    return array( 'msg' => $enc, 'sig' => bin2hex( $sig ), 'pk' => strtolower( bin2hex( sodium_crypto_sign_publickey_from_secretkey( $sk ) ) ) );
}
function send( $url, $fields ) {
    $r = wp_remote_post( $url, array( 'sslverify' => false, 'timeout' => 20, 'body' => $fields ) );
    if ( is_wp_error( $r ) ) { echo "  ERROR: " . $r->get_error_message() . "\n"; return null; }
    $body = wp_remote_retrieve_body( $r );
    echo "  code=" . wp_remote_retrieve_response_code( $r ) . " len=" . strlen( $body ) . " head=" . substr( preg_replace('/\s+/',' ', $body ), 0, 90 ) . "\n";
    return $body;
}

$ts = time();

// T1: well-formed confirmation for coordinates that match NOTHING (expect orphan log)
$p = array( 'v'=>1, 'ts'=>$ts, 'type'=>'confirmation', 'wallet_id'=>'diagwallet', 'subaddress_index'=>999999, 'received'=>0.001, 'confs'=>1, 'hashes'=>array() );
echo "T1 valid confirmation (orphan expected):\n";
send( $url, make_payload( $key, $sk, json_encode( $p ) ) );

// T2: POST WITHOUT the msg field (simulates field mismatch) - what responds?
echo "T2 missing msg field:\n";
send( $url, array( 'notmsg' => 'x', 'sig' => str_repeat('ab',64), 'pk' => $pk_hex ) );

// T3: garbage ciphertext (expect decrypt_fail)
echo "T3 garbage ciphertext:\n";
send( $url, array( 'msg' => 'AAAA-invalid-base64!!', 'sig' => str_repeat('ab',64), 'pk' => $pk_hex ) );

// T4: valid envelope, WRONG timestamp (expect bad_timestamp)
$p4 = array( 'v'=>1, 'ts'=>$ts-4000, 'type'=>'addresses', 'network'=>'testnet', 'wallet_id'=>'default', 'account_index'=>0, 'addresses'=>array() );
echo "T4 stale timestamp:\n";
send( $url, make_payload( $key, $sk, json_encode( $p4 ) ) );

// T5: unsigned while devices exist (expect sig_missing)
$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
$enc5 = sodium_bin2base64( $nonce . sodium_crypto_secretbox( '{"v":1,"ts":'. $ts .',"type":"debug_log","wallet_id":"default","entries":[]}', $nonce, $key ), SODIUM_BASE64_VARIANT_URLSAFE );
echo "T5 unsigned push:\n";
send( $url, array( 'msg' => $enc5 ) );

sleep( 2 );
echo "\n--- push debug log (newest 10) ---\n";
$log = get_option( 'wc_xmr_push_debug_log', array() );
$c=0;
foreach ( array_reverse( (array)$log ) as $e ) {
    if (++$c > 10) break;
    echo '  [' . gmdate('H:i:s', (int)$e['t']) . '] ' . ($e['type'] ?? '?');
    $x = $e; unset($x['t'],$x['type'],$x['ip']);
    echo ($x ? ' ' . wp_json_encode($x) : ''), "\n";
}

// cleanup temp device
WC_XMR_Push_Sig::remove_phone( $pk_hex );
echo "\ntemp diag device removed\n";
