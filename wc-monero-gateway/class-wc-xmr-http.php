<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class WC_XMR_HTTP {

	private static $hooked = false;

	public static function init() {
		if ( self::$hooked ) return;
		self::$hooked = true;
		add_action( 'http_api_curl', array( __CLASS__, 'apply_curl_proxy' ), 10, 3 );
	}

	public static function proxy_settings( $settings = null ) {
		try {
			$s = $settings ?? wc_xmr_settings();
		} catch ( Throwable $e ) {
			error_log( 'WC XMR: proxy_settings - wc_xmr_settings() threw: ' . $e->getMessage() );
			$s = array();
		}
		if ( ! is_array( $s ) ) $s = array();
		$port = (int) ( $s['proxy_port'] ?? 0 );
		if ( $port < 1 || $port > 65535 ) {
			if ( ( $s['proxy_enabled'] ?? 'no' ) === 'yes' && ! empty( $s['proxy_host'] ) ) {
				error_log( 'WC XMR: proxy port out of range (1-65535): ' . $port );
			}
			$port = 0;
		}
		$type = $s['proxy_type'] ?? 'socks5h';
		if ( ! in_array( $type, array( 'http', 'socks5', 'socks5h' ), true ) ) {
			error_log( 'WC XMR: unknown proxy type "' . $type . '" - falling back to socks5h.' );
			$type = 'socks5h';
		}
		return array(
			'enabled' => ( $s['proxy_enabled'] ?? 'no' ) === 'yes',
			'type'    => $type,
			'host'    => trim( (string) ( $s['proxy_host'] ?? '' ) ),
			'port'    => $port,
			'user'    => (string) ( $s['proxy_user'] ?? '' ),
			'pass'    => (string) ( $s['proxy_pass'] ?? '' ),
		);
	}

	public static function apply_curl_proxy( $handle, $r, $url ) {
		if ( empty( $r['wc_xmr_proxy']['enabled'] ) ) return;
		if ( ! is_resource( $handle ) && ! $handle instanceof CurlHandle ) return;
		$p = $r['wc_xmr_proxy'];
		if ( empty( $p['host'] ) || empty( $p['port'] ) ) {
			error_log( 'WC XMR: proxy enabled but host/port missing - not applying proxy for ' . $url );
			return;
		}
		if ( ! is_string( $p['host'] ) || strlen( $p['host'] ) > 253 ) {
			error_log( 'WC XMR: proxy host looks invalid: ' . substr( $p['host'], 0, 80 ) );
			return;
		}

		$types = array(
			'http'    => defined( 'CURLPROXY_HTTP' ) ? CURLPROXY_HTTP : 0,
			'socks5'  => defined( 'CURLPROXY_SOCKS5' ) ? CURLPROXY_SOCKS5 : 5,
			'socks5h' => defined( 'CURLPROXY_SOCKS5_HOSTNAME' ) ? CURLPROXY_SOCKS5_HOSTNAME : 7,
		);
		$type = $types[ $p['type'] ] ?? $types['socks5h'];

		$ok = true;
		$ok = curl_setopt( $handle, CURLOPT_PROXY, $p['host'] ) && $ok;
		$ok = curl_setopt( $handle, CURLOPT_PROXYPORT, (int) $p['port'] ) && $ok;
		$ok = curl_setopt( $handle, CURLOPT_PROXYTYPE, $type ) && $ok;
		if ( ! empty( $p['user'] ) ) {
			$ok = curl_setopt( $handle, CURLOPT_PROXYUSERPWD, $p['user'] . ':' . $p['pass'] ) && $ok;
		}
		$ok = curl_setopt( $handle, CURLOPT_SSL_VERIFYPEER, true ) && $ok;
		$ok = curl_setopt( $handle, CURLOPT_SSL_VERIFYHOST, 2 ) && $ok;
		if ( ! $ok ) {
			error_log( 'WC XMR: one or more curl_setopt for proxy failed for ' . $url . ': ' . curl_error( $handle ) );
		}
	}

	private static function request( $method, $url, $args = array() ) {
		if ( empty( $url ) || ! is_string( $url ) ) {
			error_log( 'WC XMR HTTP: request called with empty/invalid URL.' );
			return new WP_Error( 'xmr_http_no_url', 'Request URL is empty or invalid.' );
		}
		if ( $method !== 'get' && $method !== 'post' ) {
			error_log( 'WC XMR HTTP: unknown method "' . $method . '" for ' . $url );
			return new WP_Error( 'xmr_http_bad_method', 'Unknown HTTP method: ' . $method );
		}
		if ( ! is_array( $args ) ) $args = array();
		self::init();
		try {
			$s = wc_xmr_settings();
		} catch ( Throwable $e ) {
			error_log( 'WC XMR HTTP: wc_xmr_settings() threw in request(): ' . $e->getMessage() );
			$s = array();
		}
		$p = self::proxy_settings( $s );

		if ( $p['enabled'] ) {
			if ( empty( $p['host'] ) || empty( $p['port'] ) ) {
				error_log( 'WC XMR HTTP: proxy enabled but host/port not configured - refusing to send request unproxied to ' . $url );
				return new WP_Error( 'xmr_proxy_incomplete', 'Proxy is enabled but host/port are not configured. Refusing to send request unproxied to ' . $url );
			}
			if ( ! function_exists( 'curl_init' ) ) {
				error_log( 'WC XMR HTTP: proxy enabled but curl_init missing - refusing unproxied request to ' . $url );
				return new WP_Error(
					'xmr_proxy_no_curl',
					'Proxy is enabled in settings, but this server cannot use cURL for outbound requests, so the request was NOT sent unproxied. Fix the server\'s HTTP transport or disable the proxy option.'
				);
			}
			$args['wc_xmr_proxy'] = $p;
		}

		if ( ! isset( $args['timeout'] ) ) $args['timeout'] = ( $method === 'post' ? 15 : 10 );
		$args['timeout'] = max( 5, min( 60, (int) $args['timeout'] ) );

		$fn = ( $method === 'post' ) ? 'wp_remote_post' : 'wp_remote_get';
		$result = call_user_func( $fn, $url, $args );
		if ( is_wp_error( $result ) ) {
			error_log( sprintf( 'WC XMR HTTP: %s %s failed: [%s] %s', strtoupper( $method ), $url, $result->get_error_code(), $result->get_error_message() ) );
		}
		return $result;
	}

	public static function get( $url, $args = array() ) {
		return self::request( 'get', $url, $args );
	}

	public static function post( $url, $args = array() ) {
		return self::request( 'post', $url, $args );
	}

	public static function check_exit( $settings = null ) {
		$resp = self::request( 'get', 'https://am.i.mullvad.net/json', array( 'timeout' => 10 ) );
		if ( is_wp_error( $resp ) ) return $resp;
		$code = wp_remote_retrieve_response_code( $resp );
		if ( $code !== 200 ) {
			error_log( 'WC XMR: exit check got HTTP ' . $code . ' from am.i.mullvad.net' );
			return new WP_Error( 'xmr_proxy_check_http', 'Exit check returned HTTP ' . $code );
		}
		$raw  = wp_remote_retrieve_body( $resp );
		if ( $raw === '' ) {
			error_log( 'WC XMR: exit check got empty body.' );
			return new WP_Error( 'xmr_proxy_check_empty', 'Exit check returned empty body.' );
		}
		$body = json_decode( $raw, true );
		if ( json_last_error() !== JSON_ERROR_NONE ) {
			error_log( 'WC XMR: exit check JSON decode failed: ' . json_last_error_msg() . ' - raw: ' . substr( $raw, 0, 200 ) );
			return new WP_Error( 'xmr_proxy_check', 'Unexpected response from exit-check endpoint: ' . json_last_error_msg() );
		}
		if ( ! is_array( $body ) ) return new WP_Error( 'xmr_proxy_check', 'Unexpected response from exit-check endpoint.' );
		return $body;
	}
}
