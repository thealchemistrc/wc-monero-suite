<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class WC_XMR_Push_Logger {

	const OPTION    = 'wc_xmr_push_debug_log';
	const MAX_ENTRIES = 200;

	public static function is_enabled() {
		return ( get_option( 'wc_xmr_push_debug_log_enabled', 'no' ) === 'yes' );
	}

	public static function log( $type, $data = array() ) {
		if ( ! self::is_enabled() ) return;

		$entries = get_option( self::OPTION, array() );
		if ( ! is_array( $entries ) ) $entries = array();

		$entry = array_merge( array(
			't'    => time(),
			'type' => $type,
			'ip'   => $_SERVER['REMOTE_ADDR'] ?? '?',
		), $data );

		$entries[] = $entry;

		while ( count( $entries ) > self::MAX_ENTRIES ) {
			array_shift( $entries );
		}

		update_option( self::OPTION, $entries, false );
	}

	public static function get_entries() {
		$entries = get_option( self::OPTION, array() );
		if ( ! is_array( $entries ) ) return array();
		return array_reverse( $entries );
	}

	public static function clear() {
		delete_option( self::OPTION );
	}
}

class WC_XMR_Push_Endpoint {

	private static $post_field;
	private static $status_param;

	public static function init() {
		self::$post_field   = get_option( 'wc_xmr_push_post_field', 'msg' );
		self::$status_param = get_option( 'wc_xmr_push_status_param', 't' );

		add_action( 'init', array( __CLASS__, 'handle_pairing_post' ), 0 );
		add_action( 'template_redirect', array( __CLASS__, 'handle_status' ), 0 );
		add_action( 'template_redirect', array( __CLASS__, 'handle_pairing_get' ), 0 );
		add_action( 'template_redirect', array( __CLASS__, 'handle_pairing_status' ), 0 );

		// Push processing MUST NOT run at init@0: matched confirmations call
		// wc_get_order()/payment_complete(), and WooCommerce registers its
		// order post types LATER during init. Calling wc_get_order before
		// that fires a _doing_it_wrong() and returns false, so update_order
		// silently bailed on EVERY matched payment - orders stayed on-hold
		// forever while orphan pushes (which never touch orders) looked
		// healthy. wp_loaded fires after ALL init callbacks, guaranteeing
		// post types exist. Nothing consumes $_POST before us, so deferring
		// is lossless.
		add_action( 'wp_loaded', array( __CLASS__, 'handle_post' ), 0 );
	}

	public static function handle_post() {
		if ( ( $_SERVER['REQUEST_METHOD'] ?? '' ) !== 'POST' ) return;
		// Skip wp-admin requests entirely. The device only ever pushes to the
		// frontend URL (home_url()), while admin-post.php submits are regular
		// form posts that must reach the admin_post_* handlers - not this
		// push receiver. Without this guard, a POST whose msg/post field is
		// absent but that carries e.g. a secretbox-shaped value could be
		// swallowed by respond_ok() and the admin action never runs.
		if ( is_admin() ) return;
		$field = self::$post_field;
		if ( empty( $_POST[ $field ] ) ) return;
		if ( ! WC_XMR_Push_Crypto::available() ) {
			WC_XMR_Push_Logger::log( 'no_crypto', array( 'path' => 'post' ) );
			self::respond_ok(); return;
		}

		$raw_field = wp_unslash( $_POST[ $field ] );
		if ( ! is_string( $raw_field ) ) {
			WC_XMR_Push_Logger::log( 'bad_field', array( 'type' => gettype( $raw_field ) ) );
			self::respond_ok(); return;
		}

		$plain = WC_XMR_Push_Crypto::decrypt( $raw_field );
		if ( $plain === false ) {
			WC_XMR_Push_Logger::log( 'decrypt_fail', array( 'path' => 'post', 'len' => strlen( $raw_field ) ) );
			self::respond_ok(); return;
		}

		// If signed envelope present, verify before trusting payload.
		// Device signs the plaintext JSON (canonical separators) with Ed25519.
		// Unsigned pushes still accepted when no devices are authorized (legacy / transition).
		$sig = isset( $_POST['sig'] ) ? (string) wp_unslash( $_POST['sig'] ) : '';
		$pk  = isset( $_POST['pk'] )  ? strtolower( trim( (string) wp_unslash( $_POST['pk'] ) ) ) : '';
		$sig_ok = false;
		$sig_pk = '';
		if ( $sig !== '' || $pk !== '' ) {
			if ( class_exists( 'WC_XMR_Push_Sig' ) && WC_XMR_Push_Sig::is_hex_sig( $sig ) && WC_XMR_Push_Sig::is_hex_pk( $pk ) ) {
				$sig_ok = WC_XMR_Push_Sig::verify( $plain, $sig, $pk );
				$sig_pk = $pk;
				if ( $sig_ok && ! WC_XMR_Push_Sig::is_authorized( $pk ) ) {
					WC_XMR_Push_Logger::log( 'sig_unknown_pk', array( 'pk' => substr( $pk, 0, 16 ) . '...' ) );
					self::respond_ok(); return;
				}
				if ( ! $sig_ok ) {
					WC_XMR_Push_Logger::log( 'sig_fail', array( 'pk' => $pk ? substr( $pk, 0, 16 ) . '...' : '' ) );
					self::respond_ok(); return;
				}
				WC_XMR_Push_Sig::touch_last_seen( $pk );
			} else {
				WC_XMR_Push_Logger::log( 'sig_bad_format', array( 'has_sig' => $sig !== '' ? 1 : 0, 'has_pk' => $pk !== '' ? 1 : 0 ) );
				self::respond_ok(); return;
			}
		} else {
			if ( class_exists( 'WC_XMR_Push_Sig' ) && WC_XMR_Push_Sig::has_any() ) {
				WC_XMR_Push_Logger::log( 'sig_missing', array( 'path' => 'post' ) );
				self::respond_ok(); return;
			}
		}

		$data = json_decode( $plain, true );
		if ( ! is_array( $data ) || ( $data['v'] ?? 0 ) !== 1 ) {
			WC_XMR_Push_Logger::log( 'bad_payload', array( 'path' => 'post', 'v' => $data['v'] ?? null, 'json_err' => json_last_error_msg() ) );
			self::respond_ok(); return;
		}

		if ( ! self::timestamp_valid( $data['ts'] ?? 0 ) ) {
			WC_XMR_Push_Logger::log( 'bad_timestamp', array( 'path' => 'post', 'ts' => $data['ts'] ?? 0, 'server_ts' => time() ) );
			self::respond_ok(); return;
		}

		$type = $data['type'] ?? '';

		if ( $type === 'confirmation' ) {
			if ( $sig_ok ) $data['_sig_pk'] = $sig_pk;
			self::process_confirmation( $data );
		} elseif ( $type === 'addresses' ) {
			if ( $sig_ok ) $data['_sig_pk'] = $sig_pk;
			self::process_addresses( $data );
		} elseif ( $type === 'prune_addresses' ) {
			// Destructive pool mutation - require a verified authorized device.
			if ( ! $sig_ok ) {
				WC_XMR_Push_Logger::log( 'prune_unsigned', array( 'path' => 'post' ) );
			} else {
				$data['_sig_pk'] = $sig_pk;
				self::process_prune_addresses( $data );
			}
		} elseif ( $type === 'debug_log' ) {
			self::process_debug_log( $data );
		} else {
			WC_XMR_Push_Logger::log( 'bad_type', array( 'path' => 'post', 'type' => $type ) );
		}

		self::respond_ok();
	}

	public static function handle_status() {
		if ( ( $_SERVER['REQUEST_METHOD'] ?? '' ) !== 'GET' ) return;
		// Skip admin-page requests so a stray status param on /wp-admin/
		// doesn't intercept the page. On frontend requests (where the device
		// actually hits us), is_admin() is false and the handler fires.
		// This is a scope guard, not an auth check - it does NOT check
		// whether the current user is an administrator.
		if ( is_admin() ) return;
		$param = self::$status_param;
		if ( empty( $_GET[ $param ] ) ) return;

		// Per-IP rate limit for the status endpoint. Deliberately generous -
		// the daemon heartbeat polls regularly and must NEVER trip it;
		// 120/min (~2 req/s per IP) only stops outright flooding of a handler
		// that costs crypto + ~5 SQL queries per request. Blocked requests
		// still get the mundane ack page so the block is indistinguishable
		// from any other no-op response.
		if ( self::status_rate_limit_exceeded() ) {
			self::respond_ok();
			return;
		}

		if ( ! WC_XMR_Push_Crypto::available() ) {
			WC_XMR_Push_Logger::log( 'no_crypto', array( 'path' => 'status' ) );
			return;
		}

		$plain = WC_XMR_Push_Crypto::decrypt( wp_unslash( $_GET[ $param ] ) );
		if ( $plain === false ) {
			WC_XMR_Push_Logger::log( 'decrypt_fail', array( 'path' => 'status' ) );
			return;
		}

		$data = json_decode( $plain, true );
		if ( ! is_array( $data ) || ( $data['v'] ?? 0 ) !== 1 ) {
			WC_XMR_Push_Logger::log( 'bad_payload', array( 'path' => 'status', 'json_err' => json_last_error_msg() ) );
			return;
		}
		if ( ( $data['type'] ?? '' ) !== 'status_request' ) {
			WC_XMR_Push_Logger::log( 'bad_type', array( 'path' => 'status', 'type' => $data['type'] ?? '' ) );
			return;
		}
		if ( ! self::timestamp_valid( $data['ts'] ?? 0 ) ) {
			WC_XMR_Push_Logger::log( 'bad_timestamp', array( 'path' => 'status', 'ts' => $data['ts'] ?? 0 ) );
			return;
		}

		$req_network = $data['network'] ?? null;
		if ( $req_network !== null && ! in_array( $req_network, array( 'mainnet', 'testnet', 'stagenet' ), true ) ) {
			WC_XMR_Push_Logger::log( 'bad_network', array( 'path' => 'status', 'net' => is_scalar( $req_network ) ? substr( (string) $req_network, 0, 32 ) : gettype( $req_network ) ) );
			return;
		}
		$req_wallet_id = $data['wallet_id'] ?? null;
		if ( $req_wallet_id !== null && ( ! is_string( $req_wallet_id ) || ! preg_match( '/^[A-Za-z0-9_\-]{1,64}$/', $req_wallet_id ) ) ) {
			WC_XMR_Push_Logger::log( 'bad_wallet_id', array( 'path' => 'status' ) );
			return;
		}
		$status = self::get_pool_stats( $req_network, $req_wallet_id );
		$resp   = array(
			'v'  => 1,
			'ts' => time(),
			'network'        => $status['network'],
			'pool_free'      => $status['free'],
			'pool_total'     => $status['total'],
			'reserved_count' => $status['reserved'],
			'detected_count' => $status['detected'],
			'burn_rate_24h'  => $status['burn_rate'],
		);
		if ( $status['active_indices'] !== null ) {
			$resp['active_indices'] = $status['active_indices'];
		}
		if ( get_transient( 'wc_xmr_push_request_phone_log' ) ) {
			$resp['request_log'] = true;
		}

		$blob = WC_XMR_Push_Crypto::encrypt( wp_json_encode( $resp ) );

		if ( $blob === false ) {
			WC_XMR_Push_Logger::log( 'encrypt_fail', array( 'path' => 'status_response' ) );
			return;
		}

		WC_XMR_Push_Logger::log( 'status', array(
			'net' => $status['network'], 'free' => $status['free'],
			'total' => $status['total'], 'reserved' => $status['reserved'],
			'wallet' => $req_wallet_id ?? '',
			'active' => $status['active_indices'] !== null ? count( $status['active_indices'] ) : null,
		) );

		nocache_headers();
		header( 'Content-Type: text/plain; charset=utf-8' );
		echo $blob;
		exit;
	}

	private static function process_confirmation( $data ) {
		$wallet_id = $data['wallet_id'] ?? '';
		if ( ! is_string( $wallet_id ) || ! preg_match( '/^[A-Za-z0-9_\-]{1,64}$/', $wallet_id ) ) {
			WC_XMR_Push_Logger::log( 'bad_confirm', array( 'wallet' => is_string( $wallet_id ) ? substr( $wallet_id, 0, 64 ) : gettype( $wallet_id ), 'idx' => '?' ) );
			return;
		}

		$sub_idx = $data['subaddress_index'] ?? -1;
		if ( ( ! is_int( $sub_idx ) && ! ( is_string( $sub_idx ) && preg_match( '/^\d+$/', $sub_idx ) ) )
			|| (int) $sub_idx < 0 || (int) $sub_idx > 2000000 ) {
			WC_XMR_Push_Logger::log( 'bad_confirm', array( 'wallet' => $wallet_id, 'idx' => is_scalar( $sub_idx ) ? $sub_idx : gettype( $sub_idx ) ) );
			return;
		}
		$sub_idx = (int) $sub_idx;

		$received = $data['received'] ?? 0;
		if ( ! is_numeric( $received ) || ! is_finite( (float) $received )
			|| (float) $received < 0 || (float) $received > 1000000000 ) {
			WC_XMR_Push_Logger::log( 'bad_confirm', array( 'wallet' => $wallet_id, 'idx' => $sub_idx, 'recv' => is_scalar( $received ) ? substr( (string) $received, 0, 32 ) : gettype( $received ) ) );
			return;
		}
		$received = (float) $received;

		$confs = $data['confs'] ?? 0;
		if ( ( ! is_int( $confs ) && ! ( is_string( $confs ) && preg_match( '/^\d+$/', $confs ) ) )
			|| (int) $confs < 0 || (int) $confs > 10000000 ) {
			WC_XMR_Push_Logger::log( 'bad_confirm', array( 'wallet' => $wallet_id, 'idx' => $sub_idx, 'confs' => is_scalar( $confs ) ? $confs : gettype( $confs ) ) );
			return;
		}
		$confs = (int) $confs;

		$hashes = $data['hashes'] ?? array();
		if ( ! is_array( $hashes ) || count( $hashes ) > 100 ) {
			WC_XMR_Push_Logger::log( 'bad_confirm', array( 'wallet' => $wallet_id, 'idx' => $sub_idx, 'hashes_n' => is_array( $hashes ) ? count( $hashes ) : gettype( $hashes ) ) );
			return;
		}
		$clean_hashes = array();
		foreach ( $hashes as $h ) {
			if ( is_string( $h ) && preg_match( '/^[0-9a-fA-F]{64}$/', $h ) ) {
				$clean_hashes[] = strtolower( $h );
			}
		}
		// Drop malformed hash entries rather than failing the whole push;
		// wc_xmr_update_order only ever sees 64-hex strings.
		$hashes = $clean_hashes;

		global $wpdb;
		$t = $wpdb->prefix . 'wc_xmr_reservations';
		$row = $wpdb->get_row( $wpdb->prepare(
			// 'paid' included ON PURPOSE: once an order auto-completes, its
			// reservation leaves reserved/detected - excluding it turned every
			// later confirmation push into a silent orphan, freezing the
			// customer-visible confirmation count forever. Later pushes on a
			// paid reservation are legitimate metadata updates; update_order
			// is idempotent and its transition guards prevent re-completion.
			"SELECT * FROM {$t} WHERE wallet_id = %s AND subaddress_index = %d AND status IN ('reserved','detected','paid') ORDER BY id DESC LIMIT 1",
			$wallet_id, $sub_idx
		) );

		// Fallback: if no reservation matched on wallet_id + subaddress_index,
		// the reservation may have been created with the 'manual'/0 placeholder
		// (address was picked before metadata was attached, or the gateway wasn't
		// loaded when the address was pushed). Look up the pushed address pool to
		// find which address string corresponds to this wallet_id/subaddress_index,
		// then find the reservation by address. This recovers existing in-flight
		// orders that were created with stale metadata.
		if ( ! $row ) {
			$addr = self::find_pushed_address_by_coords( $wallet_id, $sub_idx );
			if ( $addr !== null ) {
				$row = $wpdb->get_row( $wpdb->prepare(
					"SELECT * FROM {$t} WHERE address = %s AND status IN ('reserved','detected','paid') ORDER BY id DESC LIMIT 1",
					$addr
				) );
				if ( $row ) {
					// Patch the reservation's wallet_id/subaddress_index so future
					// confirmation pushes match on the primary path directly.
					$updated = $wpdb->update( $t, array(
						'wallet_id' => $wallet_id,
						'subaddress_index' => $sub_idx,
					), array( 'id' => $row->id ), array( '%s', '%d' ), array( '%d' ) );
					if ( $updated === false ) {
						error_log( 'WC XMR Push: fallback reservation patch failed for order #' . (int) $row->order_id . ': ' . $wpdb->last_error );
					}
					WC_XMR_Push_Logger::log( 'confirm_fallback', array(
						'wallet' => $wallet_id, 'idx' => $sub_idx,
						'addr' => substr( $addr, 0, 12 ) . '...',
						'order' => (int) $row->order_id,
					) );
				}
			}
		}

		if ( ! $row ) {
			WC_XMR_Push_Logger::log( 'orphan', array(
				'wallet' => $wallet_id, 'idx' => $sub_idx,
				'recv' => $received, 'confs' => $confs,
			) );
			if ( function_exists( 'wc_xmr_alert' ) ) {
				wc_xmr_alert( 'push_orphan', sprintf(
					'Received confirmation push for wallet %s subaddress %d but no matching reservation found.',
					$wallet_id, $sub_idx
				) );
			}
			return;
		}

		$prev_recv = (float) $row->received_xmr;
		$prev_conf = (int) $row->confirmations;
		if ( abs( $received - $prev_recv ) < 1e-12 && (int) $confs === (int) $prev_conf ) return;

		if ( ! function_exists( 'wc_xmr_update_order' ) ) {
			WC_XMR_Push_Logger::log( 'no_update_fn', array( 'wallet' => $wallet_id, 'idx' => $sub_idx ) );
			return;
		}

		if ( ! function_exists( 'wc_xmr_settings' ) ) {
			WC_XMR_Push_Logger::log( 'no_settings_fn', array( 'wallet' => $wallet_id, 'idx' => $sub_idx ) );
			return;
		}
		$s = wc_xmr_settings();

		// Belt-and-braces: a crash inside the order-update path must never
		// leak fatal output into the HTTP response (display_errors) - ack
		// cleanly and leave a forensic trace instead.
		try {
			wc_xmr_update_order( $row, $received, $confs, $hashes, $s );
		} catch ( Throwable $e ) {
			error_log( 'WC XMR Push: wc_xmr_update_order threw for order #' . (int) $row->order_id . ': ' . $e->getMessage() );
			WC_XMR_Push_Logger::log( 'update_crash', array(
				'wallet' => $wallet_id, 'idx' => $sub_idx,
				'order' => (int) $row->order_id,
				'err' => substr( $e->getMessage(), 0, 300 ),
			) );
		}

		WC_XMR_Push_Logger::log( 'confirm', array(
			'wallet' => $wallet_id, 'idx' => $sub_idx,
			'recv' => $received, 'confs' => $confs,
			'txs' => count( $hashes ), 'order' => (int) $row->order_id,
		) );
	}

	private static function process_addresses( $data ) {
		$addresses = $data['addresses'] ?? array();
		if ( ! is_array( $addresses ) || empty( $addresses ) ) {
			WC_XMR_Push_Logger::log( 'addr_empty', array( 'net' => $data['network'] ?? null ) );
			return;
		}
		if ( count( $addresses ) > 2000 ) {
			WC_XMR_Push_Logger::log( 'addr_too_many', array( 'count' => count( $addresses ) ) );
			$addresses = array_slice( $addresses, -2000 );
		}

		$network = $data['network'] ?? null;

		if ( in_array( $network, array( 'mainnet', 'testnet', 'stagenet' ), true ) ) {
			$network_key = 'wc_xmr_push_' . $network . '_addresses';
		} else {
			$network_key = ( function_exists( 'wc_xmr_test_mode' ) && wc_xmr_test_mode() === 'testnet' )
				? 'wc_xmr_push_testnet_addresses'
				: 'wc_xmr_push_mainnet_addresses';
		}

		// wallet_id/account_index describe the whole batch (one device/wallet
		// config per push) and must match what that same device reports on
		// its later confirmation pushes (see process_confirmation()'s
		// lookup). Real per-address subaddress_index comes from each
		// entry's own 'index' field. Without all three attached to a
		// stored entry, a picked address can never be matched back to its
		// confirmation - see wc_xmr_pick_from_manual() on the gateway side,
		// which falls back to a 'manual'/0 placeholder when they're absent
		// (hand-typed addresses, or entries pushed before this field existed).
		$wallet_id    = $data['wallet_id'] ?? '';
		$wallet_id_ok = is_string( $wallet_id ) && preg_match( '/^[A-Za-z0-9_\-]{1,64}$/', $wallet_id );
		$account_index = $data['account_index'] ?? 0;
		$account_index_ok = ( is_int( $account_index ) || ( is_string( $account_index ) && preg_match( '/^\d+$/', $account_index ) ) )
			&& (int) $account_index >= 0 && (int) $account_index <= 1000000;
		$account_index = $account_index_ok ? (int) $account_index : 0;

		// Only explicit mainnet gets strict mainnet validation; anything else
		// (testnet, unrecognized, omitted) uses the permissive testnet-shaped
		// check (charset/length only), matching wc_xmr_valid_addr()'s own
		// permissive-by-default behavior for non-mainnet.
		$net_for_validation = ( $network === 'mainnet' ) ? 'mainnet' : 'testnet';

		if ( function_exists( 'wc_xmr_valid_addr' ) ) {
			$validated = array();
			$rejected  = 0;
			foreach ( $addresses as $entry ) {
				$addr = is_array( $entry ) ? ( $entry['address'] ?? '' ) : (string) $entry;
				if ( $addr === '' ) { $rejected++; continue; }
				if ( ! wc_xmr_valid_addr( $addr, $net_for_validation ) ) {
					$rejected++;
					continue;
				}
				$stored = array( 'address' => $addr );
				if ( is_array( $entry ) && isset( $entry['exact_amount'] ) && is_numeric( $entry['exact_amount'] ) ) {
					$stored['exact_amount'] = (float) $entry['exact_amount'];
				}
				// Preserve index for metadata attachment below (outside validation).
				if ( is_array( $entry ) && isset( $entry['index'] ) ) {
					$stored['index'] = $entry['index'];
				}
				$validated[] = $stored;
			}
			if ( empty( $validated ) ) {
				WC_XMR_Push_Logger::log( 'addr_reject', array(
					'net' => $net_for_validation, 'total' => count( $addresses ),
					'rejected' => $rejected,
				) );
				if ( function_exists( 'wc_xmr_alert' ) ) {
					wc_xmr_alert( 'push_bad_addrs', sprintf(
						'Address batch push rejected entirely: all %d addresses failed %s format validation.',
						count( $addresses ), $net_for_validation
					) );
				}
				return;
			}
			if ( $rejected > 0 && function_exists( 'wc_xmr_alert' ) ) {
				wc_xmr_alert( 'push_addr_partial', sprintf(
					'%d of %d pushed addresses rejected by %s format validation (stored %d).',
					$rejected, count( $addresses ), $net_for_validation, count( $validated )
				) );
			}
			$addresses = $validated;
		}

		// Always attach wallet_id/account_index/subaddress_index metadata to
		// every entry, regardless of whether wc_xmr_valid_addr() ran. Previously
		// this was inside the validation block, so if the gateway plugin wasn't
		// loaded yet (or any edge case), entries were stored WITHOUT metadata -
		// and when picked by wc_xmr_pick_from_manual() they fell back to a
		// 'manual'/0 placeholder that could never match a real confirmation push.
		$addresses = self::attach_address_metadata( $addresses, $wallet_id, $wallet_id_ok, $account_index );

		// Merge with existing pool instead of replacing it. A full replace
		// discards entries that still have active reservations but weren't in
		// this push's batch (the device may only push a subset each cycle). We
		// also prefer entries WITH metadata when the same address appears in
		// both old and new sets. If the wallet_id changed (operator swapped
		// devices), we clear old entries entirely since their coordinates are stale.
		$existing = get_option( $network_key, array() );
		if ( ! is_array( $existing ) ) $existing = array();

		$old_wallet_id = '';
		foreach ( $existing as $e ) {
			if ( is_array( $e ) && ! empty( $e['wallet_id'] ) ) { $old_wallet_id = $e['wallet_id']; break; }
		}

		if ( $old_wallet_id !== '' && $wallet_id_ok && $old_wallet_id !== $wallet_id ) {
			// Wallet swap - old coordinates are meaningless for new confirmations.
			$existing = array();
		}

		// Prune legacy metadata-less entries while we're here: they can never
		// be matched to a confirmation push, so keeping them only pollutes the
		// pool and risks serving guaranteed-orphan checkouts if any other code
		// path ever reads the raw option.
		$pruned_legacy = 0;
		foreach ( $existing as $k => $e ) {
			if ( ! is_array( $e ) || ! isset( $e['wallet_id'], $e['subaddress_index'] ) || empty( $e['address'] ) ) {
				unset( $existing[ $k ] );
				$pruned_legacy++;
			}
		}
		if ( $pruned_legacy > 0 ) {
			WC_XMR_Push_Logger::log( 'pool_pruned', array( 'net' => $network_key, 'count' => $pruned_legacy ) );
			error_log( "WC XMR Push: pruned {$pruned_legacy} metadata-less address(es) from {$network_key}." );
		}

		$merged = self::merge_address_pool( $existing, $addresses );

		$ok = update_option( $network_key, $merged, false );
		if ( $ok === false ) error_log( 'WC XMR Push: update_option failed for ' . $network_key );

		// Historical address audit - detect wallet swaps, compromised devices,
		// or attackers injecting addresses from a different wallet.
		// NOTE: audit the PUSHED BATCH, not the merged pool. Auditing $merged
		// made every future push re-flag whatever happened to sit in storage
		// (e.g. legacy addresses matching old reservation rows), producing
		// recurring "wallet swap?" error emails for known-good state.
		$phone_pk = $data['_sig_pk'] ?? '';
		if ( class_exists( 'WC_XMR_Push_Audit' ) ) {
			$alerts = WC_XMR_Push_Audit::audit( $phone_pk, $addresses );
			foreach ( $alerts as $alert ) {
				$level = $alert['level'] ?? 'warn';
				$msg   = $alert['msg'] ?? '';
				if ( $msg === '' ) continue;
				error_log( 'WC XMR Push Audit [' . strtoupper( $level ) . ']: ' . $msg );
				if ( $level === 'error' && function_exists( 'wc_xmr_alert' ) ) {
					wc_xmr_alert( 'push_audit_error', $msg );
				}
			}
		}

		WC_XMR_Push_Logger::log( 'addresses', array(
			'net' => $network_key, 'stored' => count( $merged ),
			'pushed' => count( $addresses ),
			'rejected' => $rejected ?? 0,
		) );
	}

	/**
	 * Handle 'prune_addresses': drop never-used subaddresses from the pushed
	 * address pool at the paired device's request (--prune-addresses on
	 * xmr-pushd). Dispatch requires a verified authorized-device signature.
	 *
	 * Safety: an entry whose address currently holds an unexpired
	 * reserved/detected reservation is NEVER removed - this is checked HERE,
	 * at processing time, so a checkout that raced the device's status
	 * snapshot cannot lose its address.
	 */
	private static function process_prune_addresses( $data ) {
		$indices = $data['indices'] ?? null;
		if ( ! is_array( $indices ) || empty( $indices ) ) {
			WC_XMR_Push_Logger::log( 'prune_empty', array( 'net' => $data['network'] ?? null ) );
			return;
		}
		if ( count( $indices ) > 1000 ) {
			WC_XMR_Push_Logger::log( 'prune_too_many', array( 'count' => count( $indices ) ) );
			return;
		}

		$clean = array();
		foreach ( $indices as $idx ) {
			if ( ! is_int( $idx ) || $idx < 0 || $idx > 2000000 ) continue;
			$clean[ $idx ] = true;
		}
		if ( empty( $clean ) ) {
			WC_XMR_Push_Logger::log( 'prune_no_valid_indices', array() );
			return;
		}

		$wallet_id    = $data['wallet_id'] ?? '';
		$wallet_id_ok = is_string( $wallet_id ) && preg_match( '/^[A-Za-z0-9_\-]{1,64}$/', $wallet_id );
		$account_index = ( isset( $data['account_index'] ) && is_int( $data['account_index'] )
			&& $data['account_index'] >= 0 && $data['account_index'] <= 1000000 )
			? $data['account_index'] : null;

		if ( ! $wallet_id_ok || $account_index === null ) {
			WC_XMR_Push_Logger::log( 'prune_bad_meta', array(
				'wallet_ok' => $wallet_id_ok ? 1 : 0,
				'account'   => $account_index,
			) );
			return;
		}

		$network = $data['network'] ?? null;
		if ( in_array( $network, array( 'mainnet', 'testnet', 'stagenet' ), true ) ) {
			$network_key = 'wc_xmr_push_' . $network . '_addresses';
		} else {
			$network_key = ( function_exists( 'wc_xmr_test_mode' ) && wc_xmr_test_mode() === 'testnet' )
				? 'wc_xmr_push_testnet_addresses'
				: 'wc_xmr_push_mainnet_addresses';
		}

		$pool = get_option( $network_key, array() );
		if ( ! is_array( $pool ) ) $pool = array();

		global $wpdb;
		$t = $wpdb->prefix . 'wc_xmr_reservations';
		$reserved_set = array();
		try {
			$now = current_time( 'mysql', 1 );
			$rows = $wpdb->get_col( $wpdb->prepare(
				"SELECT DISTINCT address FROM {$t} WHERE status IN ('reserved','detected') AND expires_at > %s",
				$now
			) );
			if ( $wpdb->last_error ) { error_log( 'WC XMR Push: prune reserved lookup failed: ' . $wpdb->last_error ); $rows = array(); }
			if ( is_array( $rows ) ) {
				foreach ( $rows as $a ) { $reserved_set[ (string) $a ] = true; }
			}
		} catch ( Throwable $e ) {
			error_log( 'WC XMR Push: prune reserved lookup threw: ' . $e->getMessage() );
		}

		$kept           = array();
		$removed        = 0;
		$skipped_active = 0;
		foreach ( $pool as $entry ) {
			if ( ! is_array( $entry ) || empty( $entry['address'] ) || ! isset( $entry['subaddress_index'] ) ) {
				$kept[] = $entry;
				continue;
			}
			$idx = $entry['subaddress_index'];
			if ( is_string( $idx ) && ctype_digit( $idx ) ) $idx = (int) $idx;
			if ( ! is_int( $idx ) || ! isset( $clean[ $idx ] ) ) {
				$kept[] = $entry;
				continue;
			}
			if ( ( $entry['wallet_id'] ?? '' ) !== $wallet_id
				|| ! isset( $entry['account_index'] ) || (int) $entry['account_index'] !== $account_index ) {
				// Not ours / different coordinates - never touch.
				$kept[] = $entry;
				continue;
			}
			if ( isset( $reserved_set[ (string) $entry['address'] ] ) ) {
				$skipped_active++;
				$kept[] = $entry;
				continue;
			}
			$removed++;
		}

		if ( $removed > 0 ) {
			$ok = update_option( $network_key, array_values( $kept ), false );
			if ( $ok === false ) error_log( 'WC XMR Push: update_option failed during prune for ' . $network_key );
		}

		WC_XMR_Push_Logger::log( 'addresses_pruned', array(
			'net'            => $network_key,
			'requested'      => count( $clean ),
			'removed'        => $removed,
			'skipped_active' => $skipped_active,
			'stored'         => count( $kept ),
			'pk'             => substr( (string) ( $data['_sig_pk'] ?? '' ), 0, 16 ),
		) );
	}

	/**
	 * Look up the pushed address pool to find which address string
	 * corresponds to a given wallet_id + subaddress_index. Searches
	 * both mainnet and testnet pools since we may not know which network
	 * the confirmation is for at this point. Returns the address string
	 * or null if no match.
	 */
	private static function find_pushed_address_by_coords( $wallet_id, $sub_idx ) {
		foreach ( array( 'mainnet', 'testnet', 'stagenet' ) as $net ) {
			$pool = get_option( 'wc_xmr_push_' . $net . '_addresses', array() );
			if ( ! is_array( $pool ) ) continue;
			foreach ( $pool as $entry ) {
				if ( ! is_array( $entry ) ) continue;
				if ( ! isset( $entry['wallet_id'], $entry['subaddress_index'] ) ) continue;
				if ( $entry['wallet_id'] === $wallet_id && (int) $entry['subaddress_index'] === (int) $sub_idx ) {
					return $entry['address'] ?? null;
				}
			}
		}
		return null;
	}

	/**
	 * Attach wallet_id/account_index/subaddress_index metadata to every
	 * address entry. Called after validation, always - so entries are
	 * usable for confirmation matching even if wc_xmr_valid_addr() wasn't
	 * available.
	 */
	private static function attach_address_metadata( $addresses, $wallet_id, $wallet_id_ok, $account_index ) {
		foreach ( $addresses as &$stored ) {
			if ( ! is_array( $stored ) ) continue;
			$idx = $stored['index'] ?? null;
			unset( $stored['index'] ); // don't persist the raw 'index' key
			$idx_ok = ( is_int( $idx ) || ( is_string( $idx ) && preg_match( '/^\d+$/', $idx ) ) )
				&& $idx !== null && (int) $idx >= 0 && (int) $idx <= 2000000;
			if ( $wallet_id_ok && $idx_ok ) {
				$stored['wallet_id']        = $wallet_id;
				$stored['account_index']    = $account_index;
				$stored['subaddress_index'] = (int) $idx;
			}
		}
		unset( $stored );
		return $addresses;
	}

	/**
	 * Merge old and new address pool entries, deduplicating by address
	 * (and exact_amount for concurrent-reuse entries). When the same
	 * address appears in both, prefer the entry that HAS metadata
	 * (wallet_id/subaddress_index) - typically the new push - so a
	 * previously bare entry gets upgraded rather than preserving the
	 * metadata-less version.
	 */
	private static function merge_address_pool( $existing, $new_entries ) {
		$merged = array();
		$seen   = array();

		// Add new entries first (they typically have metadata).
		foreach ( $new_entries as $entry ) {
			$addr = is_array( $entry ) ? ( $entry['address'] ?? '' ) : (string) $entry;
			if ( $addr === '' ) continue;
			$key = $addr;
			if ( is_array( $entry ) && isset( $entry['exact_amount'] ) ) {
				$key .= '|' . (string) $entry['exact_amount'];
			}
			if ( isset( $seen[ $key ] ) ) continue;
			$seen[ $key ] = true;
			$merged[] = $entry;
		}

		// Add old entries that aren't in the new batch (preserve active pool).
		foreach ( $existing as $entry ) {
			$addr = is_array( $entry ) ? ( $entry['address'] ?? '' ) : (string) $entry;
			if ( $addr === '' ) continue;
			$key = $addr;
			if ( is_array( $entry ) && isset( $entry['exact_amount'] ) ) {
				$key .= '|' . (string) $entry['exact_amount'];
			}
			if ( isset( $seen[ $key ] ) ) continue;
			$seen[ $key ] = true;
			$merged[] = $entry;
		}

		return $merged;
	}

	private static function process_debug_log( $data ) {
		$entries = $data['entries'] ?? array();
		if ( ! is_array( $entries ) || empty( $entries ) ) {
			WC_XMR_Push_Logger::log( 'phone_log_empty', array() );
			return;
		}
		if ( count( $entries ) > 500 ) {
			error_log( 'WC XMR Push: device log push has ' . count( $entries ) . ' entries - truncating to 500.' );
			$entries = array_slice( $entries, -500 );
		}

		$wallet_id = $data['wallet_id'] ?? '';
		if ( ! is_string( $wallet_id ) || ! preg_match( '/^[A-Za-z0-9_\-]{1,64}$/', $wallet_id ) ) {
			WC_XMR_Push_Logger::log( 'phone_log_bad_wallet', array( 'wallet' => is_string( $wallet_id ) ? substr( $wallet_id, 0, 64 ) : gettype( $wallet_id ) ) );
			return;
		}

		// Strict per-entry validation: each entry must be {t:int, level:str,
		// msg:str, d?:str} with bounded sizes, all control/ANSI chars stripped.
		// Prevents a compromised device from stuffing the option table or
		// storing terminal-escape payloads that later render in the admin UI.
		$clean = array();
		foreach ( $entries as $e ) {
			if ( ! is_array( $e ) || count( $e ) > 16 ) continue;
			$t = isset( $e['t'] ) && is_int( $e['t'] ) ? $e['t'] : 0;
			$level = isset( $e['level'] ) && is_string( $e['level'] ) ? substr( $e['level'], 0, 16 ) : '';
			$msg = isset( $e['msg'] ) && is_string( $e['msg'] ) ? self::sanitize_log_text( $e['msg'], 2000 ) : '';
			if ( $msg === '' && $level === '' ) continue;
			$entry = array( 't' => $t, 'level' => $level, 'msg' => $msg );
			if ( isset( $e['d'] ) && is_string( $e['d'] ) ) {
				$entry['d'] = self::sanitize_log_text( $e['d'], 800 );
			}
			$clean[] = $entry;
			if ( count( $clean ) >= 500 ) break;
		}
		if ( empty( $clean ) ) {
			WC_XMR_Push_Logger::log( 'phone_log_empty', array() );
			return;
		}
		$entries = $clean;

		$now = time();

		$opt = array(
			't'       => $now,
			'wallet'  => $wallet_id,
			'entries' => $entries,
		);
		// Bounded option size - a full device log must stay well under 256KB.
		if ( strlen( (string) wp_json_encode( $opt ) ) > 262144 ) {
			$opt['entries'] = array_slice( $entries, -100 );
		}

		$ok = update_option( 'wc_xmr_push_phone_log', $opt, false );
		if ( $ok === false ) error_log( 'WC XMR Push: update_option wc_xmr_push_phone_log failed.' );

		WC_XMR_Push_Logger::log( 'phone_log', array(
			'wallet' => $wallet_id, 'entries' => count( $entries ),
		) );
	}

	private static function get_pool_stats( $req_network = null, $req_wallet_id = null ) {
		global $wpdb;
		$t = $wpdb->prefix . 'wc_xmr_reservations';
		if ( empty( $t ) || ! is_string( $t ) ) { error_log( 'WC XMR Push: get_pool_stats got empty table prefix.' ); return array( 'network' => 'mainnet', 'free' => 0, 'total' => 0, 'reserved' => 0, 'detected' => 0, 'burn_rate' => 0, 'active_indices' => null ); }

		try { $s = function_exists( 'wc_xmr_settings' ) ? wc_xmr_settings() : array(); } catch ( Throwable $e ) { error_log( 'WC XMR Push: wc_xmr_settings threw in get_pool_stats: ' . $e->getMessage() ); $s = array(); }
		if ( ! is_array( $s ) ) $s = array();

		if ( in_array( $req_network, array( 'mainnet', 'testnet', 'stagenet' ), true ) ) {
			$network = $req_network;
		} else {
			$network = ( function_exists( 'wc_xmr_test_mode' ) && wc_xmr_test_mode() === 'testnet' )
				? 'testnet' : 'mainnet';
		}

		$addr_key   = $network === 'mainnet' ? 'addresses' : 'test_addresses';
		$raw        = $s[ $addr_key ] ?? '';

		$manual_pool = array_filter( array_map( 'trim', preg_split( '/\r\n|\r|\n/', $raw ) ),
			function( $l ) { return $l && $l[0] !== '#'; } );
		$manual_pool = array_values( array_unique( $manual_pool ) );

		$pushed  = get_option( 'wc_xmr_push_' . $network . '_addresses', array() );
		if ( ! is_array( $pushed ) ) $pushed = array();
		$pushed_strs = array();
		$unmatchable = 0;
		foreach ( $pushed as $e ) {
			// Count only metadata-bearing entries. A bare entry can be picked
			// for a checkout but its payment can NEVER be matched back (the
			// reservation would carry the 'manual'/0 placeholder), so it is
			// dead capacity, not supply. Mirrors wc_xmr_push_inject_addresses()
			// - keeping this exclusion here makes pool_free read low, which
			// drives the device to re-push a fresh metadata-bearing batch.
			if ( is_array( $e ) && ! empty( $e['address'] ) && isset( $e['wallet_id'], $e['subaddress_index'] ) ) {
				$pushed_strs[] = (string) $e['address'];
			} else {
				$unmatchable++;
			}
		}
		if ( $unmatchable > 0 ) {
			WC_XMR_Push_Logger::log( 'pool_unmatchable', array( 'net' => $network, 'count' => $unmatchable ) );
		}
		$pushed_strs = array_values( array_unique( array_filter( $pushed_strs ) ) );

		$all_addresses = array_values( array_unique( array_merge( $manual_pool, $pushed_strs ) ) );
		$total = count( $all_addresses );

		try { $now = current_time( 'mysql', 1 ); } catch ( Throwable $e ) { $now = gmdate( 'Y-m-d H:i:s' ); error_log( 'WC XMR Push: current_time threw in get_pool_stats: ' . $e->getMessage() ); }
		$reserved_addrs = array();
		try {
			$reserved_addrs = $wpdb->get_col( $wpdb->prepare(
				"SELECT DISTINCT address FROM {$t} WHERE status IN ('reserved','detected') AND expires_at > %s", $now
			) );
			if ( $wpdb->last_error ) { error_log( 'WC XMR Push: get_col reserved_addrs failed: ' . $wpdb->last_error ); $reserved_addrs = array(); }
		} catch ( Throwable $e ) { error_log( 'WC XMR Push: get_col reserved_addrs threw: ' . $e->getMessage() ); }
		if ( ! is_array( $reserved_addrs ) ) $reserved_addrs = array();
		$reserved_addrs = array_map( 'strval', $reserved_addrs );

		$avail = array_values( array_diff( $all_addresses, $reserved_addrs ) );
		$free  = count( $avail );

		try {
			$reserved_count = (int) $wpdb->get_var( $wpdb->prepare(
				"SELECT COUNT(*) FROM {$t} WHERE status IN ('reserved','detected') AND expires_at > %s", $now
			) );
			if ( $wpdb->last_error ) { error_log( 'WC XMR Push: get_var reserved_count failed: ' . $wpdb->last_error ); $reserved_count = 0; }
		} catch ( Throwable $e ) { error_log( 'WC XMR Push: get_var reserved_count threw: ' . $e->getMessage() ); $reserved_count = 0; }
		try {
			$detected_count = (int) $wpdb->get_var( $wpdb->prepare(
				"SELECT COUNT(*) FROM {$t} WHERE status = 'detected' AND expires_at > %s", $now
			) );
			if ( $wpdb->last_error ) { error_log( 'WC XMR Push: get_var detected_count failed: ' . $wpdb->last_error ); $detected_count = 0; }
		} catch ( Throwable $e ) { error_log( 'WC XMR Push: get_var detected_count threw: ' . $e->getMessage() ); $detected_count = 0; }

		$day_ago = gmdate( 'Y-m-d H:i:s', time() - 86400 );
		try {
			$burn = (float) $wpdb->get_var( $wpdb->prepare(
				"SELECT COUNT(*) FROM {$t} WHERE reserved_at > %s", $day_ago
			) );
			if ( $wpdb->last_error ) { error_log( 'WC XMR Push: get_var burn failed: ' . $wpdb->last_error ); $burn = 0; }
		} catch ( Throwable $e ) { error_log( 'WC XMR Push: get_var burn threw: ' . $e->getMessage() ); $burn = 0; }
		$burn_rate = round( $burn / 24, 2 );

		$active_indices = null;
		if ( is_string( $req_wallet_id ) && $req_wallet_id !== '' ) {
			try {
				$indices = $wpdb->get_col( $wpdb->prepare(
					"SELECT DISTINCT subaddress_index FROM {$t} WHERE wallet_id = %s AND status IN ('reserved','detected') ORDER BY subaddress_index ASC LIMIT 500",
					$req_wallet_id
				) );
				if ( $wpdb->last_error ) { error_log( 'WC XMR Push: get_col active_indices failed: ' . $wpdb->last_error ); $indices = array(); }
			} catch ( Throwable $e ) { error_log( 'WC XMR Push: get_col active_indices threw: ' . $e->getMessage() ); $indices = array(); }
			if ( ! is_array( $indices ) ) $indices = array();
			$active_indices = array_map( 'intval', $indices );
		}

		return array(
			'network'        => $network,
			'free'           => $free,
			'total'          => $total,
			'reserved'       => $reserved_count,
			'detected'       => $detected_count,
			'burn_rate'      => $burn_rate,
			'active_indices' => $active_indices,
		);
	}

	private static function timestamp_valid( $ts ) {
		if ( ! is_int( $ts ) || $ts <= 0 ) return false;
		$tolerance = 300;
		return abs( $ts - time() ) <= $tolerance;
	}

	/**
	 * Strip control/ANSI characters and bound length of arbitrary log text
	 * coming from the device (mirrors xmr-pushd.py _sanitize_log_str).
	 */
	private static function sanitize_log_text( $s, $limit = 2000 ) {
		$s = (string) $s;
		$s = preg_replace( '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $s );
		$s = str_replace( array( "\x1b", "\r" ), array( '', ' ' ), $s );
		$s = str_replace( "\n", ' ', $s );
		if ( strlen( $s ) > $limit ) {
			if ( function_exists( 'mb_substr' ) ) {
				$s = mb_substr( $s, 0, $limit, 'UTF-8' ) . '...[truncated]';
			} else {
				$s = substr( $s, 0, $limit ) . '...[truncated]';
			}
		}
		return $s;
	}

	private static function respond_ok() {
		nocache_headers();
		status_header( 200 );
		header( 'Content-Type: text/html; charset=utf-8' );
		echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title></title></head><body><p>Thank you for your message.</p></body></html>';
		exit;
	}

	/**
	 * Emit a JSON response for the device daemon. Discards anything buffered
	 * before this point (stray PHP notices, BOM, whitespace after a closing
	 * ?> tag) so the JSON the daemon parses is never corrupted - a leading
	 * newline before <!DOCTYPE html> is exactly what produced the daemon's
	 * "expecting value: line 2 column 1" crash. Pairing handlers are device
	 * endpoints, not browser pages: HTML is NEVER a valid response here.
	 */
	private static function respond_json( $payload ) {
		while ( ob_get_level() ) {
			ob_end_clean();
		}
		nocache_headers();
		status_header( 200 );
		header( 'Content-Type: application/json; charset=utf-8' );
		echo wp_json_encode( $payload );
		exit;
	}

	/**
	 * Rate-limit pairing endpoints by IP to prevent brute-force.
	 * Each endpoint (get / post / status) has its OWN bucket so the normal
	 * GET→POST→status pairing flow can't trip its own limiter - previously a
	 * shared bucket meant an N-th retry during testing burned all three, and
	 * the daemon's POST then received the HTML "Thank you" page instead of JSON.
	 * Returns true if the request should be blocked.
	 */
	private static function pairing_rate_limit_exceeded( $endpoint = 'get' ) {
		$ip  = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
		$key = 'wc_xmr_push_pairing_rl_' . $endpoint . '_' . crc32( $ip );
		$window = 60;        // 1 minute window
		$max_attempts = 5;   // max 5 attempts per window
		$count = (int) get_transient( $key );
		if ( $count >= $max_attempts ) {
			WC_XMR_Push_Logger::log( 'pairing_rate_limit', array( 'ip' => $ip, 'endpoint' => $endpoint ) );
			return true;
		}
		set_transient( $key, $count + 1, $window );
		return false;
	}

	/**
	 * Status-endpoint rate limit - separate, generous per-IP bucket so the
	 * pairing flow's tight 5/min limits can't starve the daemon heartbeat.
	 * Returns true if the request should be blocked.
	 */
	private static function status_rate_limit_exceeded() {
		$ip  = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
		$key = 'wc_xmr_push_status_rl_' . crc32( $ip );
		$window       = 60;   // 1 minute window
		$max_attempts = 120;  // ~2 req/s - far above any heartbeat cadence
		$count = (int) get_transient( $key );
		if ( $count >= $max_attempts ) {
			WC_XMR_Push_Logger::log( 'status_rate_limit', array( 'ip' => $ip ) );
			return true;
		}
		set_transient( $key, $count + 1, $window );
		return false;
	}

	/**
	 * Handle GET ?pair=<pairing_id> - device fetches server's ephemeral KX public key.
	 */
	public static function handle_pairing_get() {
		if ( ( $_SERVER['REQUEST_METHOD'] ?? '' ) !== 'GET' ) return;
		if ( is_admin() ) return;
		if ( empty( $_GET['pair'] ) ) return;
		if ( ! class_exists( 'WC_XMR_Push_Pairing' ) ) return;
		if ( self::pairing_rate_limit_exceeded( 'get' ) ) {
			self::respond_json( array( 'error' => 'rate_limited' ) );
		}

		$pairing_id = trim( (string) wp_unslash( $_GET['pair'] ) );
		if ( ! preg_match( '/^[0-9a-fA-F]{9}$/', $pairing_id ) ) {
			WC_XMR_Push_Logger::log( 'pairing_bad_id', array( 'id' => $pairing_id ) );
			self::respond_json( array( 'error' => 'bad_id' ) );
		}

		$result = WC_XMR_Push_Pairing::handle_get( $pairing_id );
		if ( is_wp_error( $result ) ) {
			WC_XMR_Push_Logger::log( 'pairing_get_err', array(
				'id' => $pairing_id,
				'err' => $result->get_error_code(),
			) );
			self::respond_json( array( 'error' => $result->get_error_code() ) );
		}

		self::respond_json( $result );
	}

	/**
	 * Handle POST with pairing_id - device sends its ephemeral KX pk + encrypted Ed25519 pk.
	 */
	public static function handle_pairing_post() {
		if ( ( $_SERVER['REQUEST_METHOD'] ?? '' ) !== 'POST' ) return;
		// CRITICAL: The admin "Confirm pair" / "Cancel pairing" forms POST to
		// admin-post.php with a pairing_id field. Without this guard this
		// handler fires on 'init' (priority 0), sees the pairing_id, calls
		// WC_XMR_Push_Pairing::handle_post() with empty client_kx_pk /
		// encrypted_phone_pk, gets WP_Error('missing_fields') and exits via
		// respond_ok() - redirecting the admin browser to the "Thank you for
		// your message." page while the admin_post_* action never runs.
		if ( is_admin() ) return;
		if ( empty( $_POST['pairing_id'] ) ) return;
		if ( ! class_exists( 'WC_XMR_Push_Pairing' ) ) return;

		// The device daemon parses OUR response as JSON. Every failure path
		// below must return JSON (not the HTML respond_ok() page) - otherwise
		// the daemon dies with "expecting value: line 2 column 1" because a
		// freshline precedes <!DOCTYPE html> in the HTML response.
		if ( self::pairing_rate_limit_exceeded( 'post' ) ) {
			self::respond_json( array( 'error' => 'rate_limited' ) );
		}

		$pairing_id = trim( (string) wp_unslash( $_POST['pairing_id'] ) );
		if ( ! preg_match( '/^[0-9a-fA-F]{9}$/', $pairing_id ) ) {
			WC_XMR_Push_Logger::log( 'pairing_bad_id', array( 'id' => $pairing_id ) );
			self::respond_json( array( 'error' => 'bad_id' ) );
		}

		$data = array(
			'pairing_id'         => $pairing_id,
			'client_kx_pk'       => isset( $_POST['client_kx_pk'] ) ? (string) wp_unslash( $_POST['client_kx_pk'] ) : '',
			'encrypted_phone_pk' => isset( $_POST['encrypted_phone_pk'] ) ? (string) wp_unslash( $_POST['encrypted_phone_pk'] ) : '',
			'kx_version'         => isset( $_POST['kx_version'] ) ? (string) wp_unslash( $_POST['kx_version'] ) : '',
		);

		$result = WC_XMR_Push_Pairing::handle_post( $data );
		if ( is_wp_error( $result ) ) {
			WC_XMR_Push_Logger::log( 'pairing_post_err', array(
				'id' => $pairing_id,
				'err' => $result->get_error_code(),
			) );
			$err = $result->get_error_code();
			if ( in_array( $err, array( 'too_many_attempts', 'already_used', 'rejected', 'expired' ), true ) ) {
				// Include a machine-readable code the daemon can use to print
				// a "start a fresh pairing" hint instead of a cryptic failure.
				self::respond_json( array( 'error' => $err, 'retry' => false ) );
			}
			self::respond_json( array( 'error' => $err ) );
		}

		self::respond_json( $result );
	}

	/**
	 * Handle GET ?pair_status=<pairing_id> - device polls for confirmation status.
	 * Returns { status: "sas_ready"|"confirmed"|"expired"|"not_found" }
	 */
	public static function handle_pairing_status() {
		if ( ( $_SERVER['REQUEST_METHOD'] ?? '' ) !== 'GET' ) return;
		if ( is_admin() ) return;
		if ( empty( $_GET['pair_status'] ) ) return;
		if ( ! class_exists( 'WC_XMR_Push_Pairing' ) ) return;
		if ( self::pairing_rate_limit_exceeded( 'status' ) ) {
			self::respond_json( array( 'error' => 'rate_limited' ) );
		}

		$pairing_id = trim( (string) wp_unslash( $_GET['pair_status'] ) );
		if ( ! preg_match( '/^[0-9a-fA-F]{9}$/', $pairing_id ) ) {
			WC_XMR_Push_Logger::log( 'pairing_status_bad_id', array( 'id' => $pairing_id ) );
			self::respond_json( array( 'error' => 'bad_id' ) );
		}

		$session = WC_XMR_Push_Pairing::get_session( $pairing_id );

		if ( ! $session ) {
			// Session not found - check if device was already authorized
			// (session is deleted after confirm, so this means success)
			self::respond_json( array( 'status' => 'not_found' ) );
		}

		if ( $session['expires_at'] < time() ) {
			self::respond_json( array( 'status' => 'expired' ) );
		}

		self::respond_json( array( 'status' => $session['status'] ) );
	}

}