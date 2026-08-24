<?php

// CLI-only diagnostic: replicates the state fingerprint logic used by the
// settings page auto-refresh (wc_xmr_push_state_fingerprint) to verify it
// runs cleanly against the live install. Read-only.
require_once dirname(__DIR__, 4) . '/wp-load.php';

$fp = array(
	'pair'     => 'none',
	'pair_id'  => '',
	'pair_bits'=> 0,
	'pair_sas' => '',
	'phones'   => 0,
	'log_sig'  => '',
	'phone_t'  => 0,
	'phone_n'  => 0,
);

try {
	if ( class_exists( 'WC_XMR_Push_Pairing' ) ) {
		foreach ( WC_XMR_Push_Pairing::get_sessions() as $s ) {
			if ( in_array( $s['status'], array( 'waiting', 'sas_ready', 'claimed', 'rejected' ), true ) ) {
				$fp['pair']      = $s['status'];
				$fp['pair_id']   = (string) ( $s['pairing_id'] ?? '' );
				$fp['pair_bits'] = (int) ( $s['bits'] ?? 0 );
				$fp['pair_sas']  = isset( $s['sas_words'] ) ? implode( '|', array_map( 'strval', (array) $s['sas_words'] ) ) : '';
				break;
			}
		}
	}

	if ( class_exists( 'WC_XMR_Push_Sig' ) && WC_XMR_Push_Sig::has_any() ) {
		$fp['phones'] = count( (array) WC_XMR_Push_Sig::get_phones() );
	}

	$interesting = array( 'confirm', 'addresses', 'phone_log', 'phone_log_empty', 'decrypt_fail', 'bad_payload', 'bad_timestamp', 'bad_type', 'bad_field', 'orphan', 'addr_reject', 'bad_confirm', 'encrypt_fail', 'no_crypto' );
	if ( class_exists( 'WC_XMR_Push_Logger' ) ) {
		$entries = WC_XMR_Push_Logger::get_entries();
		foreach ( (array) $entries as $e ) {
			$t = (string) ( $e['type'] ?? '' );
			if ( in_array( $t, $interesting, true ) ) {
				$fp['log_sig'] .= $t . ':' . ( (int) ( $e['t'] ?? 0 ) ) . ';';
			}
		}
	}

	$phone_log = get_option( 'wc_xmr_push_phone_log', null );
	if ( is_array( $phone_log ) ) {
		$fp['phone_t'] = (int) ( $phone_log['t'] ?? 0 );
		$fp['phone_n'] = is_array( $phone_log['entries'] ?? null ) ? count( $phone_log['entries'] ) : 0;
	}
} catch ( Throwable $e ) {
	fwrite( STDERR, "CRASH: " . $e->getMessage() . "\n" );
	exit( 1 );
}

echo wp_json_encode( $fp, JSON_PRETTY_PRINT ) . "\n";
echo "=== END ===\n";