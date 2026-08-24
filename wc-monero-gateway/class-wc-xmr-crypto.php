<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class WC_XMR_Crypto {

	const PREFIX = 'enc:v1:';

	private static function key() {
		if ( ! defined( 'WC_XMR_ENC_KEY' ) ) return false;
		if ( ! is_string( WC_XMR_ENC_KEY ) || strlen( WC_XMR_ENC_KEY ) < 32 ) {
			if ( defined( 'WC_XMR_ENC_KEY' ) ) {
				error_log( 'WC XMR Crypto: WC_XMR_ENC_KEY defined but too short (<32 chars) - encryption at rest is disabled.' );
			}
			return false;
		}
		return hash( 'sha256', WC_XMR_ENC_KEY, true );
	}

	public static function enabled() {
		$has_key = self::key() !== false;
		$has_openssl = function_exists( 'openssl_encrypt' ) && function_exists( 'openssl_decrypt' ) && function_exists( 'openssl_random_pseudo_bytes' );
		if ( $has_key && ! $has_openssl ) {
			error_log( 'WC XMR Crypto: WC_XMR_ENC_KEY is set but openssl extension missing - encryption at rest is disabled.' );
		}
		return $has_key && $has_openssl;
	}

	public static function encrypt( $plaintext ) {
		if ( $plaintext === '' || $plaintext === null ) return $plaintext;
		if ( ! self::enabled() ) return $plaintext;
		if ( strpos( (string) $plaintext, self::PREFIX ) === 0 ) return $plaintext;

		$key = self::key();
		if ( $key === false ) return $plaintext;
		try {
			$iv = random_bytes( 12 );
		} catch ( Throwable $e ) {
			error_log( 'WC XMR Crypto: random_bytes(12) failed in encrypt(): ' . $e->getMessage() );
			return $plaintext;
		}
		$tag = '';
		$ct  = openssl_encrypt( $plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16 );
		if ( $ct === false ) {
			error_log( 'WC XMR Crypto: openssl_encrypt failed - storing plaintext fail-open. OpenSSL error: ' . openssl_error_string() );
			return $plaintext;
		}
		if ( strlen( $tag ) !== 16 ) {
			error_log( 'WC XMR Crypto: GCM tag length unexpected (' . strlen( $tag ) . ') - storing plaintext fail-open.' );
			return $plaintext;
		}
		$raw = $iv . $tag . $ct;
		$b64 = base64_encode( $raw );
		if ( $b64 === false ) {
			error_log( 'WC XMR Crypto: base64_encode failed in encrypt().' );
			return $plaintext;
		}
		return self::PREFIX . $b64;
	}

	public static function decrypt( $value ) {
		if ( $value === '' || $value === null ) return $value;
		if ( strpos( (string) $value, self::PREFIX ) !== 0 ) return $value;

		$key = self::key();
		if ( $key === false ) {
			error_log( 'WC Monero Gateway: WC_XMR_ENC_KEY is missing/changed but stored settings are encrypted - decryption failed, wallet-rpc credentials are unreadable. Payments WILL fail until the original key is restored in wp-config.php.' );
			set_transient( 'wc_xmr_enc_key_lost', true, HOUR_IN_SECONDS );
			return '';
		}

		$b64 = substr( $value, strlen( self::PREFIX ) );
		$raw = base64_decode( $b64, true );
		if ( $raw === false ) {
			error_log( 'WC XMR Crypto: base64_decode failed for encrypted value (strict).' );
			set_transient( 'wc_xmr_enc_key_lost', true, HOUR_IN_SECONDS );
			return '';
		}
		if ( strlen( $raw ) < 28 ) {
			error_log( 'WC XMR Crypto: encrypted value too short (' . strlen( $raw ) . ' bytes, need >=28).' );
			return '';
		}
		$iv  = substr( $raw, 0, 12 );
		$tag = substr( $raw, 12, 16 );
		$ct  = substr( $raw, 28 );

		$pt = openssl_decrypt( $ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '' );
		if ( $pt === false ) {
			error_log( 'WC Monero Gateway: decryption failed for an encrypted settings value (key present but ciphertext/tag mismatch) - check WC_XMR_ENC_KEY hasn\'t changed. OpenSSL: ' . openssl_error_string() );
			set_transient( 'wc_xmr_enc_key_lost', true, HOUR_IN_SECONDS );
			return '';
		}
		return $pt;
	}
}

add_action( 'admin_notices', function() {
	if ( ! current_user_can( 'manage_woocommerce' ) ) return;
	if ( ! get_option( 'woocommerce_monero_settings' ) ) return;

	if ( get_transient( 'wc_xmr_enc_key_lost' ) ) {
		echo '<div class="notice notice-error"><p><strong>Monero gateway - URGENT:</strong> WC_XMR_ENC_KEY in wp-config.php no longer matches the key used to encrypt your saved wallet-rpc credentials (or the proxy password). Decryption is failing, meaning <strong>payments will not work</strong> until the original key is restored. If you intentionally rotated the key, re-enter and re-save your wallet-rpc settings now.</p></div>';
		return;
	}

	if ( WC_XMR_Crypto::enabled() ) return;
	echo '<div class="notice notice-warning"><p><strong>Monero gateway:</strong> WC_XMR_ENC_KEY is not set in wp-config.php - wallet-rpc credentials and the proxy password are stored in plaintext in the database. Run <code>openssl rand -hex 32</code> and add <code>define(\'WC_XMR_ENC_KEY\', \'&lt;that value&gt;\');</code> to wp-config.php to encrypt them at rest. Note this defends against a database-only leak, not against full server compromise.</p></div>';
});
