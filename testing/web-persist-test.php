<?php

require_once dirname(__DIR__,4) . '/wp-load.php';
global $wpdb;
$t = $wpdb->prefix . 'wc_xmr_reservations';

$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$t} WHERE id = %d", 39 ) );
if ( ! $row ) { echo "no res 39\n"; exit; }
echo "pre : st={$row->status} recv={$row->received_xmr} confs={$row->confirmations} tx={$row->tx_hashes}\n";

$secret = get_option( 'wc_xmr_push_secret', '' );
if ( strpos( $secret, 'enc:v1:' ) === 0 && class_exists( 'WC_XMR_Crypto' ) ) { $d = WC_XMR_Crypto::decrypt( $secret ); if ( $d !== '' && $d !== null ) $secret = $d; }
$key = hex2bin( $secret );
$kp = sodium_crypto_sign_keypair();
$sk = sodium_crypto_sign_secretkey( $kp );
$pk_hex = strtolower( bin2hex( sodium_crypto_sign_publickey( $kp ) ) );
WC_XMR_Push_Sig::add_phone( $pk_hex, 'webtest' );

$plain = json_encode( array(
    'v'=>1, 'ts'=>time(), 'type'=>'confirmation',
    'wallet_id'=>'default', 'subaddress_index'=>211,
    'received'=>0.000027169513, 'confs'=>30,
    'hashes'=>array( str_repeat('ab',32) ),
) );
$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
$enc = sodium_bin2base64( $nonce . sodium_crypto_secretbox( $plain, $nonce, $key ), SODIUM_BASE64_VARIANT_URLSAFE );
$sig = bin2hex( sodium_crypto_sign_detached( $plain, $sk ) );

$ch = curl_init( 'https://localhost/shop/' );
curl_setopt_array( $ch, array(
    CURLOPT_POST => true, CURLOPT_POSTFIELDS => http_build_query( array( 'msg'=>$enc, 'sig'=>$sig, 'pk'=>$pk_hex ) ),
    CURLOPT_RETURNTRANSFER => true, CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0,
    CURLOPT_TIMEOUT => 30, CURLOPT_HTTPHEADER => array( 'Expect:' ),
) );
$body = curl_exec( $ch );
echo 'resp code=', curl_getinfo( $ch, CURLINFO_RESPONSE_CODE ), ' len=', strlen( (string)$body ), "\n";
if ( strlen( (string)$body ) !== 126 ) {
    echo "---- FULL ANOMALOUS BODY ----\n", $body, "\n---- END BODY ----\n";
}
curl_close( $ch );
WC_XMR_Push_Sig::remove_phone( $pk_hex );

sleep(1);
$after = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$t} WHERE id = %d", 39 ) );
echo "post: st={$after->status} recv={$after->received_xmr} confs={$after->confirmations} tx=" . substr((string)$after->tx_hashes,0,20) . "\n";
$order = wc_get_order( $row->order_id );
echo "order {$row->order_id}: status=", $order ? $order->get_status() : '?', " _xmr_received=", var_export( $order ? $order->get_meta('_xmr_received') : null, true ), "\n";
echo "--- last debug log entries ---\n";
$log = get_option('wc_xmr_push_debug_log', array());
foreach ( array_reverse( array_slice( array_reverse((array)$log), -3 ) ) as $e ) {
    echo '[', gmdate('H:i:s',(int)$e['t']), '] ', ($e['type'] ?? '?');
    $x=$e; unset($x['t'],$x['type'],$x['ip']); echo ($x?' '.json_encode($x):''), "\n";
}
