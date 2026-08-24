<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class WC_XMR_Push_Sig {

	const OPTION = 'wc_xmr_push_authorized_phones';

	public static function available() {
		return function_exists( 'sodium_crypto_sign_verify_detached' )
			|| class_exists( 'ParagonIE_Sodium_Compat' );
	}

	public static function is_hex_pk( $s ) {
		return is_string( $s ) && preg_match( '/^[0-9a-fA-F]{64}$/', $s );
	}
	public static function is_hex_sig( $s ) {
		return is_string( $s ) && preg_match( '/^[0-9a-fA-F]{128}$/', $s );
	}

	public static function verify( $payload_str, $sig_hex, $pk_hex ) {
		if ( ! is_string( $payload_str ) || $payload_str === '' ) return false;
		if ( ! self::is_hex_sig( $sig_hex ) || ! self::is_hex_pk( $pk_hex ) ) return false;
		$sig = @hex2bin( strtolower( $sig_hex ) );
		$pk  = @hex2bin( strtolower( $pk_hex ) );
		if ( ! $sig || strlen( $sig ) !== SODIUM_CRYPTO_SIGN_BYTES ) return false;
		if ( ! $pk  || strlen( $pk )  !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES ) return false;
		try {
			if ( function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
				return sodium_crypto_sign_verify_detached( $sig, $payload_str, $pk );
			}
			if ( class_exists( 'ParagonIE_Sodium_Compat' ) ) {
				return ParagonIE_Sodium_Compat::crypto_sign_verify_detached( $sig, $payload_str, $pk );
			}
		} catch ( Throwable $e ) {
			error_log( 'WC XMR Push Sig: verify threw: ' . $e->getMessage() );
			return false;
		}
		return false;
	}

	public static function get_phones() {
		$list = get_option( self::OPTION, array() );
		if ( ! is_array( $list ) ) return array();
		$out = array();
		foreach ( $list as $row ) {
			if ( ! is_array( $row ) || empty( $row['pk'] ) || ! self::is_hex_pk( $row['pk'] ) ) continue;
			$pk = strtolower( $row['pk'] );
			$out[ $pk ] = array(
				'pk'        => $pk,
				'label'     => isset( $row['label'] ) ? (string) $row['label'] : '',
				'added'     => isset( $row['added'] ) ? (int) $row['added'] : 0,
				'last_seen' => isset( $row['last_seen'] ) ? (int) $row['last_seen'] : 0,
			);
		}
		return $out;
	}

	public static function is_authorized( $pk_hex ) {
		if ( ! self::is_hex_pk( $pk_hex ) ) return false;
		$phones = self::get_phones();
		return isset( $phones[ strtolower( $pk_hex ) ] );
	}
	public static function has_any() {
		return ! empty( self::get_phones() );
	}

	public static function add_phone( $pk_hex, $label = '' ) {
		$pk_hex = strtolower( trim( (string) $pk_hex ) );
		if ( ! self::is_hex_pk( $pk_hex ) ) return new WP_Error( 'bad_pk', 'Public key must be 64 hex chars (32 bytes Ed25519).' );
		$label = trim( (string) $label );
		if ( strlen( $label ) > 64 ) $label = substr( $label, 0, 64 );
		$phones = self::get_phones();
		$now = time();
		if ( isset( $phones[ $pk_hex ] ) ) {
			if ( $label !== '' ) $phones[ $pk_hex ]['label'] = $label;
			$ok = update_option( self::OPTION, array_values( $phones ), false );
			if ( $ok === false ) error_log( 'WC XMR Push Sig: update_option add_phone (update label) returned false for pk ' . substr( $pk_hex, 0, 8 ) . '...' );
			return true;
		}
		$phones[ $pk_hex ] = array( 'pk' => $pk_hex, 'label' => $label, 'added' => $now, 'last_seen' => 0 );
		$ok = update_option( self::OPTION, array_values( $phones ), false );
		if ( $ok === false ) error_log( 'WC XMR Push Sig: update_option add_phone failed for pk ' . substr( $pk_hex, 0, 8 ) . '...' );
		return true;
	}

	public static function remove_phone( $pk_hex ) {
		$pk_hex = strtolower( trim( (string) $pk_hex ) );
		if ( ! self::is_hex_pk( $pk_hex ) ) return new WP_Error( 'bad_pk', 'Invalid public key.' );
		$phones = self::get_phones();
		if ( ! isset( $phones[ $pk_hex ] ) ) return new WP_Error( 'not_found', 'Phone not found.' );
		unset( $phones[ $pk_hex ] );
		$ok = update_option( self::OPTION, array_values( $phones ), false );
		if ( $ok === false ) error_log( 'WC XMR Push Sig: update_option remove_phone failed.' );
		return true;
	}

	public static function touch_last_seen( $pk_hex ) {
		$pk_hex = strtolower( trim( (string) $pk_hex ) );
		if ( ! self::is_hex_pk( $pk_hex ) ) return;
		$phones = self::get_phones();
		if ( ! isset( $phones[ $pk_hex ] ) ) return;
		// Throttle: skip rewriting the whole devices option more than once a
		// minute per device - every signed push used to trigger a full RMW.
		$now = time();
		if ( $now - (int) $phones[ $pk_hex ]['last_seen'] < 60 ) return;
		$phones[ $pk_hex ]['last_seen'] = $now;
		update_option( self::OPTION, array_values( $phones ), false );
	}
}
