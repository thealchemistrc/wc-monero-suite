<?php

require_once dirname(__DIR__,4) . '/wp-load.php';
function mask($s){ $s=(string)$s; return strlen($s)<10 ? '(short/'.strlen($s).')' : substr($s,0,6).'...'.substr($s,-4).' len='.strlen($s); }
echo 'debug_log_enabled=', var_export(get_option('wc_xmr_push_debug_log_enabled','(unset)'),true), "\n";
echo 'post_field=', var_export(get_option('wc_xmr_push_post_field','(unset)'),true), ' status_param=', var_export(get_option('wc_xmr_push_status_param','(unset)'),true), "\n";
$sec = get_option('wc_xmr_push_secret','');
if (strpos($sec,'enc:v1:')===0 && class_exists('WC_XMR_Crypto')) { $d=WC_XMR_Crypto::decrypt($sec); $sec = ($d!==''&&$d!==null)?$d:'DECRYPT-FAILED'; }
echo 'server_secret=', mask($sec), ' sha1=', substr(sha1($sec),0,10), "\n";
$phones = get_option('wc_xmr_push_authorized_phones', array());
echo 'authorized_phones=', count((array)$phones), "\n";
foreach ((array)$phones as $p) {
    echo '  pk=', substr(is_array($p)?($p['pk'] ?? '?'):'?',0,12),"... label=", ($p['label'] ?? ''), " last_seen=", ($p['last_seen'] ?? 0), "\n";
}
$c = json_decode(file_get_contents(dirname(__DIR__) . '/daemon/xmr-pushd.conf'), true);
if (!is_array($c)) { echo "daemon conf: PARSE FAILED\n"; exit; }
echo "--- daemon conf ---\n";
echo 'wp_url=', ($c['wp_url'] ?? '?'), "\n";
echo 'post_field=', ($c['wp_post_field'] ?? '?'), ' status_param=', ($c['wp_status_param'] ?? '?'), "\n";
echo 'secret=', mask($c['shared_secret_hex'] ?? ''), ' sha1=', isset($c['shared_secret_hex']) ? substr(sha1($c['shared_secret_hex']),0,10) : '-', "\n";
echo 'wallet_id=', ($c['wallet_id'] ?? '?'), ' network=', ($c['network'] ?? '?'), ' account=', ($c['account_index'] ?? '?'), "\n";
echo 'tls_verify=', var_export($c['tls_verify'] ?? null, true), " poll_interval=", ($c['poll_interval'] ?? '?'), "\n";
