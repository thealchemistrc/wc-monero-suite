<?php

/**
 * Unit tests for WC_XMR_Push_Pairing.
 * Run: php test_pairing_unit.php --wp-load=/path/to/wp-load.php
 * Tests the pairing class directly (requires WordPress bootstrap).
 */

// Locate wp-load.php: --wp-load=... argument, WP_LOAD env var, then common layouts.
$wp_load = null;
foreach ( $_SERVER['argv'] ?? array() as $cli_arg ) {
    if ( strpos( $cli_arg, '--wp-load=' ) === 0 ) { $wp_load = substr( $cli_arg, 10 ); }
}
if ( empty( $wp_load ) && getenv( 'WP_LOAD' ) ) {
    $wp_load = getenv( 'WP_LOAD' );
}
if ( empty( $wp_load ) || ! file_exists( $wp_load ) ) {
    foreach ( array(
        __DIR__ . '/../../../../wp-load.php', // <repo>/daemon when repo sits at wp-content/plugins/<repo> -> WP root
        __DIR__ . '/../../../wp-load.php',
    ) as $candidate ) {
        if ( file_exists( $candidate ) ) { $wp_load = $candidate; break; }
    }
}
if ( empty( $wp_load ) || ! file_exists( $wp_load ) ) {
    die( "ERROR: wp-load.php not found. Pass --wp-load=/path/to/wp-load.php or set WP_LOAD.\n" );
}

define( 'WP_USE_THEMES', false );
require_once $wp_load;

// These classes may already be loaded by the active WordPress plugin
if ( ! class_exists( 'WC_XMR_Push_Pairing' ) ) {
    require_once __DIR__ . '/../wc-monero-push/class-wc-xmr-push-pairing.php';
}
if ( ! class_exists( 'WC_XMR_Push_Sig' ) ) {
    require_once __DIR__ . '/../wc-monero-push/class-wc-xmr-push-sig.php';
}

$passed = 0;
$failed = 0;
$errors = array();

function assert_true( $condition, $msg ) {
    global $passed, $failed, $errors;
    if ( $condition ) {
        $passed++;
        echo "  [ok] $msg\n";
    } else {
        $failed++;
        $errors[] = $msg;
        echo "  [x] FAIL: $msg\n";
    }
}

function assert_eq( $expected, $actual, $msg ) {
    global $passed, $failed, $errors;
    if ( $expected === $actual ) {
        $passed++;
        echo "  [ok] $msg\n";
    } else {
        $failed++;
        $errors[] = "$msg (expected: " . var_export($expected, true) . ", got: " . var_export($actual, true) . ")";
        echo "  [x] FAIL: $msg\n";
        echo "    expected: " . var_export($expected, true) . "\n";
        echo "    got:      " . var_export($actual, true) . "\n";
    }
}

// Clean up any stale sessions from previous runs
delete_option( 'wc_xmr_push_pairings' );
echo "Cleaned up stale sessions.\n\n";

echo "========================================\n";
echo "WC_XMR_Push_Pairing Unit Tests\n";
echo "PHP " . phpversion() . " | " . (PHP_INT_SIZE * 8) . "-bit\n";
echo "========================================\n\n";

// ============================================================================
// TEST 1: generate_session() - no "abandon abandon abandon"
// ============================================================================
echo "[1] generate_session() - verify no all-abandon results (20 iterations)\n";

$all_abandon_count = 0;
$unique_words = array();
for ( $i = 0; $i < 20; $i++ ) {
    $result = WC_XMR_Push_Pairing::generate_session();
    if ( is_wp_error( $result ) ) {
        assert_true( false, "generate_session() returned WP_Error: " . $result->get_error_message() );
        continue;
    }
    $words = $result['words'];
    $word_str = implode( ' ', $words );
    $unique_words[$word_str] = true;

    if ( $words[0] === 'abandon' && $words[1] === 'abandon' && $words[2] === 'abandon' ) {
        $all_abandon_count++;
    }

    // Verify each word is in the wordlist
    $valid = true;
    foreach ( $words as $w ) {
        if ( array_search( $w, WC_XMR_Push_Pairing::WORDLIST, true ) === false ) {
            $valid = false;
        }
    }
    assert_true( $valid, "Iteration $i: all words valid BIP39" );

    // Verify pairing_id is 9 hex chars
    assert_true( preg_match( '/^[0-9a-f]{9}$/', $result['pairing_id'] ) === 1, "Iteration $i: pairing_id format" );

    // Cancel session to stay under MAX_ACTIVE limit
    WC_XMR_Push_Pairing::cancel( $result['pairing_id'] );
}

assert_eq( 0, $all_abandon_count, "No 'abandon abandon abandon' results" );
assert_true( count( $unique_words ) >= 18, "At least 18/20 unique word combinations (got " . count($unique_words) . ")" );

echo "  Unique combinations: " . count($unique_words) . "/20\n\n";

// ============================================================================
// TEST 2: bits_to_words / words_to_bits roundtrip
// ============================================================================
echo "[2] bits_to_words() / words_to_bits() roundtrip\n";

for ( $i = 0; $i < 100; $i++ ) {
    $bits = random_int( 0, 0x1FFFFFFFF );
    $words = WC_XMR_Push_Pairing::bits_to_words( $bits );
    $decoded = WC_XMR_Push_Pairing::words_to_bits( $words[0], $words[1], $words[2] );
    assert_eq( $bits, $decoded, "Roundtrip $i: $bits → " . implode(' ', $words) . " → $decoded" );
}

// Edge cases
assert_eq( 0, WC_XMR_Push_Pairing::words_to_bits( 'abandon', 'abandon', 'abandon' ), "Edge: abandon abandon abandon = 0" );
$max_bits = 0x1FFFFFFFF;
$max_words = WC_XMR_Push_Pairing::bits_to_words( $max_bits );
$max_decoded = WC_XMR_Push_Pairing::words_to_bits( $max_words[0], $max_words[1], $max_words[2] );
assert_eq( $max_bits, $max_decoded, "Edge: max 33-bit value roundtrip" );

echo "\n";

// ============================================================================
// TEST 3: Full ECDH flow (generate → get → post → confirm)
// ============================================================================
echo "[3] Full ECDH pairing flow\n";

// 3a: Generate session
$session = WC_XMR_Push_Pairing::generate_session();
assert_true( ! is_wp_error( $session ), "generate_session() succeeded" );
if ( is_wp_error( $session ) ) {
    echo "  Cannot continue - session generation failed.\n";
    goto summary;
}

$pairing_id = $session['pairing_id'];
$code_words = $session['words'];
echo "  Code words: " . implode( ' ', $code_words ) . "\n";
echo "  Pairing ID: $pairing_id\n";

// 3b: GET - device fetches server's ephemeral key
$get_result = WC_XMR_Push_Pairing::handle_get( $pairing_id );
assert_true( ! is_wp_error( $get_result ), "handle_get() succeeded" );
if ( is_wp_error( $get_result ) ) {
    echo "  Cannot continue - GET failed: " . $get_result->get_error_message() . "\n";
    goto summary;
}
$server_kx_pk_hex = $get_result['server_kx_pk'];
assert_true( preg_match( '/^[0-9a-fA-F]{64}$/', $server_kx_pk_hex ) === 1, "server_kx_pk is 64 hex chars" );
echo "  Server KX pk: " . substr( $server_kx_pk_hex, 0, 16 ) . "...\n";

// 3c: Simulate phone-side ECDH
// Device generates its own KX keypair
$client_kx_kp = sodium_crypto_kx_keypair();
$client_kx_pk = sodium_crypto_kx_publickey( $client_kx_kp );
$client_kx_sk = sodium_crypto_kx_secretkey( $client_kx_kp );
$client_kx_pk_hex = sodium_bin2hex( $client_kx_pk );

// Device generates Ed25519 signing keypair
$phone_kp = sodium_crypto_sign_keypair();
$phone_pk = sodium_crypto_sign_publickey( $phone_kp );
$phone_pk_hex = sodium_bin2hex( $phone_pk );

echo "  Client KX pk: " . substr( $client_kx_pk_hex, 0, 16 ) . "...\n";
echo "  Device Ed25519 pk: " . substr( $phone_pk_hex, 0, 16 ) . "...\n";

// Device computes shared secret using the SAME KDF as the server
$server_kx_pk = sodium_hex2bin( $server_kx_pk_hex );
$shared_secret = sodium_crypto_scalarmult( $client_kx_sk, $server_kx_pk );
$pks = array( $server_kx_pk, $client_kx_pk );
sort( $pks );
$session_keys = sodium_crypto_generichash(
    $shared_secret . $pks[0] . $pks[1] . 'xmr-push-kx-v1',
    '',
    64
);
$rx_key = substr( $session_keys, 0, 32 );
$tx_key = substr( $session_keys, 32, 32 );

// Device computes SAS
$k1 = $rx_key;
$k2 = $tx_key;
if ( strcmp( $rx_key, $tx_key ) > 0 ) {
    $k1 = $tx_key;
    $k2 = $rx_key;
}
$sas_hash = sodium_crypto_generichash(
    $k1 . $k2 . $pairing_id . 'xmr-push-pairing-v1',
    '',
    32
);
$sas_bits = hexdec( bin2hex( substr( $sas_hash, 0, 5 ) ) ) & 0x1FFFFFFFF;
$client_sas_words = WC_XMR_Push_Pairing::bits_to_words( $sas_bits );
echo "  Client SAS: " . implode( ' ', $client_sas_words ) . "\n";

// Device encrypts its Ed25519 pk (as hex string) with rx_key
$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
$ciphertext = sodium_crypto_secretbox( $phone_pk_hex, $nonce, $rx_key );
$encrypted_phone_pk = sodium_bin2base64( $nonce . $ciphertext, SODIUM_BASE64_VARIANT_URLSAFE );

// 3d: POST - device sends its ephemeral pk + encrypted device pk
$post_data = array(
    'pairing_id'         => $pairing_id,
    'client_kx_pk'       => $client_kx_pk_hex,
    'encrypted_phone_pk' => $encrypted_phone_pk,
);
$post_result = WC_XMR_Push_Pairing::handle_post( $post_data );
assert_true( ! is_wp_error( $post_result ), "handle_post() succeeded" );
if ( is_wp_error( $post_result ) ) {
    echo "  Cannot continue - POST failed: " . $post_result->get_error_message() . "\n";
    goto summary;
}

$server_sas_words = $post_result['sas_words'];
echo "  Server SAS: " . implode( ' ', $server_sas_words ) . "\n";

// 3e: Verify SAS match
assert_eq( $client_sas_words, $server_sas_words, "SAS words match between client and server" );

// 3f: Confirm
$confirm_result = WC_XMR_Push_Pairing::confirm( $pairing_id );
assert_true( ! is_wp_error( $confirm_result ), "confirm() succeeded" );
if ( is_wp_error( $confirm_result ) ) {
    echo "  Confirm failed: " . $confirm_result->get_error_message() . "\n";
} else {
    assert_eq( 'confirmed', $confirm_result['status'], "confirm() returns status=confirmed" );
    assert_eq( $phone_pk_hex, $confirm_result['phone_pk'], "Phone pk matches" );
}

echo "\n";

// ============================================================================
// TEST 4: Error handling
// ============================================================================
echo "[4] Error handling\n";

// 4a: GET with invalid pairing_id
$bad_get = WC_XMR_Push_Pairing::handle_get( 'nonexistent' );
assert_true( is_wp_error( $bad_get ), "GET with bad ID returns WP_Error" );

// 4b: POST with missing fields
$bad_post = WC_XMR_Push_Pairing::handle_post( array( 'pairing_id' => 'test' ) );
assert_true( is_wp_error( $bad_post ), "POST with missing fields returns WP_Error" );

// 4c: POST with invalid client_kx_pk format
$bad_post2 = WC_XMR_Push_Pairing::handle_post( array(
    'pairing_id'         => 'test',
    'client_kx_pk'       => 'not-hex',
    'encrypted_phone_pk' => 'dGVzdA==',
) );
assert_true( is_wp_error( $bad_post2 ), "POST with bad pk format returns WP_Error" );

// 4d: Confirm with bad state
$bad_confirm = WC_XMR_Push_Pairing::confirm( 'nonexistent' );
assert_true( is_wp_error( $bad_confirm ), "confirm() with bad ID returns WP_Error" );

echo "\n";

// ============================================================================
// TEST 5: Cancel session
// ============================================================================
echo "[5] Cancel session\n";

$session2 = WC_XMR_Push_Pairing::generate_session();
if ( ! is_wp_error( $session2 ) ) {
    $cancel_result = WC_XMR_Push_Pairing::cancel( $session2['pairing_id'] );
    assert_true( $cancel_result === true, "cancel() returns true" );
    $after_cancel = WC_XMR_Push_Pairing::get_session( $session2['pairing_id'] );
    assert_true( $after_cancel === null, "Session is null after cancel" );
}

echo "\n";

// ============================================================================
// TEST 6: find_by_bits
// ============================================================================
echo "[6] find_by_bits()\n";

$session3 = WC_XMR_Push_Pairing::generate_session();
if ( ! is_wp_error( $session3 ) ) {
    $bits = WC_XMR_Push_Pairing::words_to_bits( $session3['words'][0], $session3['words'][1], $session3['words'][2] );
    $found = WC_XMR_Push_Pairing::find_by_bits( $bits );
    assert_true( $found !== null, "find_by_bits() finds the session" );
    assert_eq( $session3['pairing_id'], $found['pairing_id'], "Found session has correct pairing_id" );
    WC_XMR_Push_Pairing::cancel( $session3['pairing_id'] );
}

echo "\n";

// ============================================================================
// Summary
// ============================================================================
summary:
echo "========================================\n";
echo "RESULTS: $passed passed, $failed failed\n";
echo "========================================\n";

if ( $failed > 0 ) {
    echo "\nFAILURES:\n";
    foreach ( $errors as $e ) {
        echo "  - $e\n";
    }
    exit( 1 );
} else {
    echo "All tests passed!\n";
    exit( 0 );
}