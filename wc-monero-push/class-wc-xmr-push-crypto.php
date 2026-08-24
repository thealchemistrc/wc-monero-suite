<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class WC_XMR_Push_Crypto {

	private static $key_cache = null;

	public static function available() {
		return function_exists( 'sodium_crypto_secretbox' )
			&& function_exists( 'sodium_crypto_secretbox_open' )
			&& function_exists( 'sodium_crypto_secretbox_keygen' )
			&& ( function_exists( 'sodium_crypto_sign_verify_detached' ) || class_exists( 'ParagonIE_Sodium_Compat' ) );
	}

	public static function generate_key() {
		return bin2hex( sodium_crypto_secretbox_keygen() );
	}

	private static function get_key() {
		if ( self::$key_cache !== null ) return self::$key_cache;
		$raw = get_option( 'wc_xmr_push_secret', '' );
		if ( ! $raw || ! is_string( $raw ) || strlen( $raw ) < 64 ) {
			error_log( 'WC XMR Push: shared secret is missing or too short - push decryption will fail until a valid 64-hex-char key is set in Settings → Monero Push.' );
			return false;
		}
		if ( class_exists( 'WC_XMR_Crypto' ) ) {
			$decrypted = WC_XMR_Crypto::decrypt( $raw );
			if ( $decrypted !== '' && $decrypted !== null ) $raw = $decrypted;
		}
		$bin = @hex2bin( $raw );
		if ( ! $bin || strlen( $bin ) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES ) {
			error_log( 'WC XMR Push: shared secret is not valid hex or wrong byte length after decryption - push decryption will fail. Check that the key in Settings → Monero Push matches what the device has.' );
			return false;
		}
		self::$key_cache = $bin;
		return $bin;
	}

	public static function clear_key_cache() {
		self::$key_cache = null;
	}

	/**
	 * Gated error_log for attacker-reachable failure paths: decrypt() sees
	 * anonymous POST/GET input, and an unconditional error_log() there lets
	 * anyone append log lines forever (log-flooding DoS).
	 */
	private static function debug_log( $msg ) {
		if ( class_exists( 'WC_XMR_Push_Logger' ) && WC_XMR_Push_Logger::is_enabled() ) {
			error_log( $msg );
		}
	}

	public static function safe_memzero( &$buf ) {
		if ( ! is_string( $buf ) ) return;
		if ( extension_loaded( 'sodium' ) && function_exists( 'sodium_memzero' ) ) {
			try { sodium_memzero( $buf ); } catch ( Throwable $e ) {}
		} else {
			$buf = str_repeat( "\0", strlen( $buf ) );
		}
	}

	public static function encrypt( $plaintext ) {
		$key = self::get_key();
		if ( ! $key ) return false;
		$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$ciphertext = sodium_crypto_secretbox( $plaintext, $nonce, $key );
		if ( $ciphertext === false ) {
			error_log( 'WC XMR Push: sodium_crypto_secretbox failed during encryption - this should not happen with a valid key and may indicate a PHP/libsodium bug.' );
			self::safe_memzero( $key );
			return false;
		}
		self::safe_memzero( $key );
		return sodium_bin2base64( $nonce . $ciphertext, SODIUM_BASE64_VARIANT_URLSAFE );
	}

	private static function parse_payload( $payload ) {
		// The Python daemon strips '=' padding (base64.urlsafe_b64encode(...)
		// .rstrip('=')). sodium_base642bin() with an empty ignore string
		// REQUIRES padding and returns false for unpadded input, so normalize
		// to a multiple of 4 before decoding. Accepts both padded and
		// unpadded forms for forward/backward compatibility.
		$payload = rtrim( (string) $payload, "=" );
		if ( strlen( $payload ) % 4 !== 0 ) {
			$payload .= str_repeat( '=', 4 - ( strlen( $payload ) % 4 ) );
		}
		try {
			$raw = @sodium_base642bin( $payload, SODIUM_BASE64_VARIANT_URLSAFE, '' );
		} catch ( Throwable $e ) {
			// Modern libsodium throws SodiumException on invalid base64;
			// older builds return false. Either way, degrade to a clean
			// failure instead of a fatal.
			$raw = false;
		}
		if ( ! $raw || strlen( $raw ) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + 16 ) {
			return false;
		}
		return array(
			substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ),
			substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ),
		);
	}

	/**
	 * Decrypt using an explicit per-device key rather than the (removed)
	 * global shared secret. Every device's key is the paired_secret derived
	 * during its own ECDH pairing exchange (see class-wc-xmr-push-pairing.php
	 * confirm() and class-wc-xmr-push-sig.php get_phone_secret()) - there is
	 * no server-wide secret anymore, so callers must look up the right key
	 * for a given pk before calling this.
	 */
	public static function decrypt_with_key( $payload, $key ) {
		if ( ! is_string( $key ) || strlen( $key ) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES ) {
			error_log( 'WC XMR Push: decrypt_with_key called with an invalid key length.' );
			return false;
		}
		$parsed = self::parse_payload( $payload );
		if ( $parsed === false ) {
			error_log( sprintf(
				'WC XMR Push: decrypt failed - payload is not valid URL-safe base64 or too short (%d chars input).',
				strlen( (string) $payload )
			) );
			return false;
		}
		list( $nonce, $ciphertext ) = $parsed;
		$plaintext = sodium_crypto_secretbox_open( $ciphertext, $nonce, $key );
		if ( $plaintext === false ) {
			error_log( 'WC XMR Push: decrypt failed - sodium_crypto_secretbox_open returned false. The per-device key does not match, or the payload was corrupted/tampered with.' );
			return false;
		}
		return $plaintext;
	}

	public static function decrypt( $payload ) {
		$key = self::get_key();
		if ( ! $key ) return false;
		$parsed = self::parse_payload( $payload );
		if ( $parsed === false ) {
			self::debug_log( sprintf(
				'WC XMR Push: decrypt failed - payload is not valid URL-safe base64 or too short (%d chars input).',
				strlen( (string) $payload )
			) );
			self::safe_memzero( $key );
			return false;
		}
		list( $nonce, $ciphertext ) = $parsed;
		$plaintext = sodium_crypto_secretbox_open( $ciphertext, $nonce, $key );
		self::safe_memzero( $key );
		if ( $plaintext === false ) {
			self::debug_log( 'WC XMR Push: decrypt failed - sodium_crypto_secretbox_open returned false. The shared secret on the server likely does not match the device, or the payload was corrupted/tampered with.' );
			return false;
		}
		return $plaintext;
	}
}
