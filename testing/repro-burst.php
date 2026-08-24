<?php

// Fire 4 rapid valid pushes (daemon burst shape) and dump FULL response bodies.
require_once dirname(__DIR__,4) . '/wp-load.php';

$secret = get_option( 'wc_xmr_push_secret', '' );
if ( strpos( $secret, 'enc:v1:' ) === 0 && class_exists( 'WC_XMR_Crypto' ) ) { $d = WC_XMR_Crypto::decrypt( $secret ); if ( $d !== '' && $d !== null ) $secret = $d; }
$key = hex2bin( $secret );
$kp = sodium_crypto_sign_keypair();
$sk = sodium_crypto_sign_secretkey( $kp );
$pk_hex = strtolower( bin2hex( sodium_crypto_sign_publickey( $kp ) ) );
WC_XMR_Push_Sig::add_phone( $pk_hex, 'burst-diag' );

function payload( $key, $sk, $plain ) {
    $nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
    $enc = sodium_bin2base64( $nonce . sodium_crypto_secretbox( $plain, $nonce, $key ), SODIUM_BASE64_VARIANT_URLSAFE );
    $sig = sodium_crypto_sign_detached( $plain, $sk );
    return array( 'msg' => $enc, 'sig' => bin2hex( $sig ), 'pk' => strtolower( bin2hex( sodium_crypto_sign_publickey_from_secretkey( $sk ) ) ) );
}

$ch = curl_init();
curl_setopt_array( $ch, array(
    CURLOPT_URL => 'https://localhost/shop/',
    CURLOPT_POST => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => 0,
    CURLOPT_TIMEOUT => 20,
    CURLOPT_HTTPHEADER => array( 'Expect:' ),
) );

$ts = time();
$targets = array( array( 'diagburst', 900001 ), array( 'diagburst', 900002 ), array( 'diagburst', 900003 ), array( 'diagburst', 900004 ) );
$i = 0;
foreach ( $targets as $t ) {
    $i++;
    $plain = json_encode( array( 'v'=>1, 'ts'=>$ts, 'type'=>'confirmation', 'wallet_id'=>$t[0], 'subaddress_index'=>$t[1], 'received'=>0.001+$i*0.001, 'confs'=>1, 'hashes'=>array() ) );
    curl_setopt( $ch, CURLOPT_POSTFIELDS, http_build_query( payload( $key, $sk, $plain ) ) );
    $body = curl_exec( $ch );
    $code = curl_getinfo( $ch, CURLINFO_RESPONSE_CODE );
    echo "req#$i code=$code len=" . strlen( (string)$body ) . "\n";
    if ( strlen( (string)$body ) !== 126 ) {
        echo "---- FULL BODY ----\n", $body, "\n---- END ----\n";
        break; // first anomaly is enough
    }
}
curl_close( $ch );
WC_XMR_Push_Sig::remove_phone( $pk_hex );
echo "done\n";
