<?php
/**
 * WC_Monero_Native_Scanner - PHP-native Monero payment scanner.
 *
 * Scans the Monero blockchain directly via a monerod JSON-RPC node, using vendored
 * pure-PHP crypto (monerophp + php-keccak) to detect payments to any address/subaddress
 * WITHOUT monero-wallet-rpc or a Node.js sidecar.
 *
 * LEAST SECURE: the private view key is held in PHP process memory. If the server is
 * compromised, the view key can be extracted, revealing all incoming transactions.
 *
 * MAY AFFECT SERVER PERFORMANCE: scanning fetches full blocks from a daemon and runs
 * ed25519 + Keccak in pure PHP (GMP/BCMath). CPU/memory intensive. NOT recommended for
 * production stores on shared hosting.
 *
 * Powered by xmr-pay (SlowBearDigger) - https://github.com/SlowBearDigger/xmr-pay
 * Integrated into wc-monero-gateway.
 *
 * Logging levels (mirrors the --logging CLI flag):
 *   1 = ERROR only (critical failures, data corruption, security issues)
 *   2 = WARN  (recoverable errors, degraded operation, unexpected data)
 *   3 = INFO  (normal operation: block scans, matches, confirmations)  [DEFAULT]
 *   4 = DEBUG (verbose: every RPC call, every output checked, crypto intermediates)
 *
 * @package WC_Monero_Gateway
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

// Load vendored crypto primitives.
require_once dirname( __DIR__ ) . '/vendor/monero/load.php';

use MoneroIntegrations\MoneroPhp\Cryptonote;

class WC_Monero_Native_Scanner {

	/** @var Cryptonote */
	private $cn;

	/** @var array Daemon node config: ['url','auth','username','password'] */
	private $node;

	/** @var int|null Cached daemon tip height. */
	private $cached_tip = null;

	/** @var float Timestamp of last tip fetch. */
	private $tip_ts = 0.0;

	/** @var int Tip cache TTL in seconds. */
	const TIP_TTL = 30;

	/** @var int Logging level: 1=ERROR, 2=WARN, 3=INFO, 4=DEBUG */
	private $log_level = 3;

	/** @var string Network type: 'mainnet', 'testnet', or 'stagenet' */
	private $network = 'mainnet';

	/** @var array Scan metrics for diagnostics. */
	private $metrics = array(
		'rpc_calls'        => 0,
		'blocks_scanned'   => 0,
		'txs_checked'      => 0,
		'outputs_checked'  => 0,
		'matches_found'    => 0,
		'commitment_ok'    => 0,
		'commitment_fail'  => 0,
		'errors'            => 0,
		'start_time'        => 0.0,
		'elapsed'           => 0.0,
	);

	/* ------------------------------------------------------------------ *
	 *  Construction & configuration
	 * ------------------------------------------------------------------ */

	/**
	 * @param array  $node       Node config: ['url'=>'http://...','auth'=>'none|basic','username'=>'','password'=>'']
	 * @param int    $log_level  1=ERROR, 2=WARN, 3=INFO(default), 4=DEBUG
	 * @param string $network    'mainnet', 'testnet', or 'stagenet' (default: 'mainnet')
	 */
	public function __construct( array $node, $log_level = 3, $network = 'mainnet' ) {
		// Validate network type - Cryptonote() will throw if invalid.
		$valid_networks = array( 'mainnet', 'testnet', 'stagenet' );
		if ( ! in_array( $network, $valid_networks, true ) ) {
			$network = 'mainnet';
		}
		$this->network = $network;
		$this->cn      = new Cryptonote( $network );

		// Normalize daemon URL. WordPress's HTTP API REJECTS scheme-less URLs
		// ("xmr-node.cakewallet.com:18081") with WP_Error "A valid URL was not
		// provided" - the #1 reason scanner polls silently did nothing while
		// logging an ERROR every cycle. Monero node RPC is plain HTTP unless
		// https:// was typed explicitly, so prepend it when missing. Trailing
		// slashes are stripped so we never produce "...//json_rpc" (some daemons
		// answer 404 there, breaking get_height).
		$raw_url = isset( $node['url'] ) ? trim( (string) $node['url'] ) : '';
		if ( '' !== $raw_url && ! preg_match( '#^https?://#i', $raw_url ) ) {
			$raw_url = 'http://' . $raw_url;
		}
		$node['url'] = rtrim( $raw_url, '/' );

		$this->node      = $node;
		$this->log_level = max( 1, min( 4, (int) $log_level ) );
	}

	/**
	 * Get the network type this scanner is configured for.
	 *
	 * @return string  'mainnet', 'testnet', or 'stagenet'
	 */
	public function get_network() {
		return $this->network;
	}

	/**
	 * Set the logging level at runtime.
	 *
	 * @param int $level  1=ERROR, 2=WARN, 3=INFO, 4=DEBUG
	 */
	public function set_log_level( $level ) {
		$this->log_level = max( 1, min( 4, (int) $level ) );
	}

	/**
	 * Get the current logging level.
	 *
	 * @return int
	 */
	public function get_log_level() {
		return $this->log_level;
	}

	/**
	 * Get scan metrics.
	 *
	 * @return array
	 */
	public function get_metrics() {
		if ( $this->metrics['start_time'] > 0 ) {
			$this->metrics['elapsed'] = microtime( true ) - $this->metrics['start_time'];
		}
		return $this->metrics;
	}

	/**
	 * Reset metrics for a new scan.
	 */
	public function reset_metrics() {
		$this->metrics = array(
			'rpc_calls'        => 0,
			'blocks_scanned'   => 0,
			'txs_checked'      => 0,
			'outputs_checked'  => 0,
			'matches_found'    => 0,
			'commitment_ok'    => 0,
			'commitment_fail'  => 0,
			'errors'            => 0,
			'start_time'        => 0.0,
			'elapsed'           => 0.0,
		);
	}

	/* ------------------------------------------------------------------ *
	 *  Daemon RPC helpers
	 * ------------------------------------------------------------------ */

	/**
	 * Call monerod JSON-RPC.
	 *
	 * @param string $method  e.g. 'get_block', 'get_last_block_header'
	 * @param array  $params
	 * @return array|null  Decoded 'result' key, or null on failure.
	 */
	private function rpc( $method, $params = array() ) {
		$this->metrics['rpc_calls']++;
		$this->log_debug( 'rpc', "→ {$method} params=" . wp_json_encode( $params ) );

		$payload = wp_json_encode( array(
			'jsonrpc' => '2.0',
			'id'      => '0',
			'method'  => $method,
			'params'  => $params,
		) );

		$args = array(
			'body'        => $payload,
			'timeout'     => 30,
			'httpversion' => '1.1',
			'headers'     => array(
				'Content-Type' => 'application/json',
				'Accept'       => 'application/json',
			),
			'sslverify'   => false,
		);

		$url = $this->node['url'];
		if ( ! empty( $this->node['auth'] ) && 'none' !== $this->node['auth'] ) {
			if ( 'basic' === $this->node['auth'] && ! empty( $this->node['username'] ) ) {
				$args['headers']['Authorization'] = 'Basic ' . base64_encode( $this->node['username'] . ':' . $this->node['password'] );
			}
		}

		$response = wp_remote_post( $url . '/json_rpc', $args );

		if ( is_wp_error( $response ) ) {
			$this->metrics['errors']++;
			$this->log_error( 'rpc', "{$method} WP_HTTP error: " . $response->get_error_message() );
			return null;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			$this->metrics['errors']++;
			$body = wp_remote_retrieve_body( $response );
			$this->log_error( 'rpc', "{$method} HTTP {$code}: " . substr( $body, 0, 200 ) );
			return null;
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( ! is_array( $data ) || isset( $data['error'] ) ) {
			$this->metrics['errors']++;
			$err = isset( $data['error']['message'] ) ? $data['error']['message'] : 'unknown';
			$this->log_error( 'rpc', "{$method} JSON-RPC error: {$err}" );
			return null;
		}

		$result = isset( $data['result'] ) ? $data['result'] : null;
		$this->log_debug( 'rpc', "← {$method} OK" );
		return $result;
	}

	/**
	 * Call a monerod REST endpoint (non-JSON-RPC).
	 *
	 * Some daemon methods like 'get_transactions' are NOT available via /json_rpc.
	 * They use their own POST endpoint, e.g. POST /get_transactions with a JSON body.
	 *
	 * @param string $endpoint  e.g. 'get_transactions'
	 * @param array  $params    Request body as associative array.
	 * @return array|null  Decoded response, or null on failure.
	 */
	private function rpc_rest( $endpoint, $params = array() ) {
		$this->metrics['rpc_calls']++;
		$this->log_debug( 'rpc_rest', "→ /{$endpoint} params=" . wp_json_encode( $params ) );

		$args = array(
			'body'        => wp_json_encode( $params ),
			'timeout'     => 30,
			'httpversion' => '1.1',
			'headers'     => array(
				'Content-Type' => 'application/json',
				'Accept'       => 'application/json',
			),
			'sslverify'   => false,
		);

		$url = $this->node['url'];
		if ( ! empty( $this->node['auth'] ) && 'none' !== $this->node['auth'] ) {
			if ( 'basic' === $this->node['auth'] && ! empty( $this->node['username'] ) ) {
				$args['headers']['Authorization'] = 'Basic ' . base64_encode( $this->node['username'] . ':' . $this->node['password'] );
			}
		}

		$response = wp_remote_post( $url . '/' . $endpoint, $args );

		if ( is_wp_error( $response ) ) {
			$this->metrics['errors']++;
			$this->log_error( 'rpc_rest', "/{$endpoint} WP_HTTP error: " . $response->get_error_message() );
			return null;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			$this->metrics['errors']++;
			$body = wp_remote_retrieve_body( $response );
			$this->log_error( 'rpc_rest', "/{$endpoint} HTTP {$code}: " . substr( $body, 0, 200 ) );
			return null;
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( ! is_array( $data ) ) {
			$this->metrics['errors']++;
			$this->log_error( 'rpc_rest', "/{$endpoint} returned non-JSON: " . substr( $body, 0, 200 ) );
			return null;
		}

		if ( isset( $data['status'] ) && 'OK' !== $data['status'] ) {
			$this->metrics['errors']++;
			$this->log_error( 'rpc_rest', "/{$endpoint} status: " . $data['status'] );
			return null;
		}

		$this->log_debug( 'rpc_rest', "← /{$endpoint} OK" );
		return $data;
	}

	/**
	 * Get current daemon height (cached for TIP_TTL seconds).
	 *
	 * @return int|null
	 */
	public function get_height() {
		if ( null !== $this->cached_tip && ( microtime( true ) - $this->tip_ts ) < self::TIP_TTL ) {
			$this->log_debug( 'height', "cached tip={$this->cached_tip}" );
			return $this->cached_tip;
		}
		$result = $this->rpc( 'get_last_block_header' );
		if ( ! is_array( $result ) || ! isset( $result['block_header']['height'] ) ) {
			$this->log_error( 'height', 'get_last_block_header returned no height' );
			// Return stale cached value if available - better than skipping
			// the entire poll cycle when the daemon is temporarily unreachable.
			if ( null !== $this->cached_tip ) {
				$this->log_warn( 'height', "returning stale cached tip={$this->cached_tip} (RPC failed)" );
				return $this->cached_tip;
			}
			return null;
		}
		$this->cached_tip = (int) $result['block_header']['height'];
		$this->tip_ts     = microtime( true );
		$this->log_info( 'height', "daemon tip={$this->cached_tip}" );
		return $this->cached_tip;
	}

	/**
	 * Fetch a single block by height.
	 *
	 * @param int $height
	 * @return array|null  Decoded block with ['_block_height'=>int, '_txids'=>string[], 'json'=>raw]
	 */
	public function get_block( $height ) {
		$result = $this->rpc( 'get_block', array( 'height' => (int) $height ) );
		if ( ! is_array( $result ) ) {
			$this->log_warn( 'block', "height={$height} returned null" );
			return null;
		}

		$txids = array();
		if ( isset( $result['tx_hashes'] ) && is_array( $result['tx_hashes'] ) ) {
			$txids = $result['tx_hashes'];
		}

		$block = array(
			'_block_height' => (int) $height,
			'_txids'        => $txids,
			'json'          => wp_json_encode( $result ),
			'miner_tx'      => isset( $result['miner_tx'] ) ? $result['miner_tx'] : null,
			'block_header'  => isset( $result['block_header'] ) ? $result['block_header'] : null,
		);

		if ( isset( $result['txs'] ) && is_array( $result['txs'] ) ) {
			$block['_txs'] = array();
			foreach ( $result['txs'] as $tx ) {
				if ( is_array( $tx ) ) {
					$tx['_block_height'] = (int) $height;
					$tx['_txid']         = isset( $tx['txid'] ) ? $tx['txid'] : '';
					$block['_txs'][]     = $tx;
				}
			}
		}

		$this->log_debug( 'block', "height={$height} tx_count=" . count( $txids ) );
		return $block;
	}

	/**
	 * Fetch transaction hashes for a block (lightweight - no tx bodies).
	 *
	 * @param int $height
	 * @return string[]|null  Array of txids, or null on failure.
	 */
	public function block_tx_hashes( $height ) {
		$result = $this->rpc( 'get_block', array( 'height' => (int) $height ) );
		if ( ! is_array( $result ) ) {
			$this->log_warn( 'block_tx_hashes', "height={$height} returned null" );
			return null;
		}
		if ( isset( $result['tx_hashes'] ) && is_array( $result['tx_hashes'] ) ) {
			$this->log_debug( 'block_tx_hashes', "height={$height} count=" . count( $result['tx_hashes'] ) );
			return $result['tx_hashes'];
		}
		$this->log_debug( 'block_tx_hashes', "height={$height} no txs" );
		return array();
	}

	/**
	 * Fetch a single transaction by txid.
	 *
	 * @param string $txid
	 * @return array|null  Decoded tx with ['_txid','_block_height','_in_pool',...]
	 */
	public function fetch_tx( $txid ) {
		$this->log_debug( 'fetch_tx', "txid={$txid}" );
		$result = $this->rpc_rest( 'get_transactions', array(
			'txs_hashes' => array( $txid ),
			'decode_as_json' => true,
		) );
		if ( ! is_array( $result ) ) { return null; }

		$txs = isset( $result['txs'] ) ? $result['txs'] : array();
		if ( empty( $txs ) ) {
			$this->log_warn( 'fetch_tx', "txid={$txid} not found" );
			return null;
		}

		$tx = $txs[0];
		if ( ! is_array( $tx ) ) { return null; }

		// Cross-check (mirrors xmr-pay): a node that returns a DIFFERENT tx than
		// requested must be rejected, never classified as the requested payment.
		$returned_txid = isset( $tx['tx_hash'] ) ? strtolower( trim( (string) $tx['tx_hash'] ) ) : '';
		if ( '' !== $returned_txid && strcasecmp( $returned_txid, strtolower( trim( (string) $txid ) ) ) !== 0 ) {
			$this->log_warn( 'fetch_tx', "node returned txid={$returned_txid} for requested {$txid} - rejecting" );
			return null;
		}

		$tx['_txid'] = $txid;

		if ( isset( $tx['block_height'] ) && $tx['block_height'] > 0 ) {
			$tx['_block_height'] = (int) $tx['block_height'];
			$tx['_in_pool']      = false;
		} else {
			$tx['_block_height'] = null;
			$tx['_in_pool']      = true;
		}

		$tx['_double_spend_seen'] = ! empty( $tx['double_spend_seen'] );

		if ( isset( $tx['as_json'] ) && is_string( $tx['as_json'] ) ) {
			$decoded = json_decode( $tx['as_json'], true );
			if ( is_array( $decoded ) ) {
				$tx = array_merge( $tx, $decoded );
			}
		} elseif ( isset( $tx['json'] ) && is_string( $tx['json'] ) ) {
			$decoded = json_decode( $tx['json'], true );
			if ( is_array( $decoded ) ) {
				$tx = array_merge( $tx, $decoded );
			}
		}

		$this->log_debug( 'fetch_tx', "txid={$txid} decoded, in_pool=" . ( $tx['_in_pool'] ? 'yes' : 'no' ) );
		return $tx;
	}

	/**
	 * Fetch multiple transactions by txid (batched).
	 *
	 * @param string[] $txids
	 * @return array[]|null  Array of decoded txs, or null on failure.
	 */
	public function fetch_txs( array $txids ) {
		if ( empty( $txids ) ) { return array(); }

		$this->log_debug( 'fetch_txs', 'count=' . count( $txids ) );
		$result = $this->rpc_rest( 'get_transactions', array(
			'txs_hashes'     => array_values( $txids ),
			'decode_as_json' => true,
		) );
		if ( ! is_array( $result ) ) { return null; }

		$txs = isset( $result['txs'] ) ? $result['txs'] : array();
		$out = array();

		foreach ( $txs as $tx ) {
			if ( ! is_array( $tx ) ) { continue; }

			$txid = isset( $tx['tx_hash'] ) ? $tx['tx_hash'] : '';
			$tx['_txid'] = $txid;

			if ( isset( $tx['block_height'] ) && $tx['block_height'] > 0 ) {
				$tx['_block_height'] = (int) $tx['block_height'];
				$tx['_in_pool']      = false;
			} else {
				$tx['_block_height'] = null;
				$tx['_in_pool']      = true;
			}

			$tx['_double_spend_seen'] = ! empty( $tx['double_spend_seen'] );

			if ( isset( $tx['as_json'] ) && is_string( $tx['as_json'] ) ) {
				$decoded = json_decode( $tx['as_json'], true );
				if ( is_array( $decoded ) ) {
					$tx = array_merge( $tx, $decoded );
				}
			} elseif ( isset( $tx['json'] ) && is_string( $tx['json'] ) ) {
				$decoded = json_decode( $tx['json'], true );
				if ( is_array( $decoded ) ) {
					$tx = array_merge( $tx, $decoded );
				}
			}

			$out[] = $tx;
		}

		$this->log_debug( 'fetch_txs', 'decoded=' . count( $out ) );
		return $out;
	}

	/* ------------------------------------------------------------------ *
	 *  Crypto helpers
	 * ------------------------------------------------------------------ */

	/**
	 * Parse tx_extra into ['main'=>R_hex|null, 'additional'=>[index=>R_hex,...]].
	 *
	 * @param array|int[] $extra  Raw tx_extra as array of bytes (integers).
	 * @return array
	 */
	private function parse_extra( $extra ) {
		if ( ! is_array( $extra ) ) {
			$this->log_warn( 'parse_extra', 'extra is not an array: ' . gettype( $extra ) );
			return array( 'main' => null, 'additional' => array() );
		}

		// Convert to hex string.
		$hex = '';
		foreach ( $extra as $byte ) {
			$hex .= sprintf( '%02x', (int) $byte );
		}

		$main       = null;
		$additional = array();
		$pos        = 0;
		$len        = strlen( $hex );

		while ( $pos < $len ) {
			if ( $pos + 2 > $len ) { break; }
			$tag = hexdec( substr( $hex, $pos, 2 ) );
			$pos += 2;

			if ( 0x00 === $tag ) {
				break; // padding - rest is zeros
			} elseif ( 0x01 === $tag ) {
				// Tx public key (main): 32 bytes.
				if ( $pos + 64 > $len ) {
					$this->log_warn( 'parse_extra', 'tx pubkey truncated' );
					break;
				}
				$main = substr( $hex, $pos, 64 );
				$pos += 64;
				$this->log_debug( 'parse_extra', "main R={$main}" );
			} elseif ( 0x02 === $tag ) {
				// Extra nonce: VARINT length + data (mirrors xmr-pay; lengths ≥128
				// are encoded as two bytes - a single-byte read would misparse).
				$nlen = $this->read_varint_hex( $hex, $pos, $len );
				if ( $nlen < 0 ) { break; }
				$pos += $nlen * 2;
			} elseif ( 0x04 === $tag ) {
				// Additional pubkeys (subaddresses): VARINT count + N × 32 bytes.
				// A real tx has ≤ output-count keys; cap at 256 like xmr-pay.
				$n = min( $this->read_varint_hex( $hex, $pos, $len ), 256 );
				if ( $n < 0 ) { break; }
				for ( $i = 0; $i < $n; $i++ ) {
					if ( $pos + 64 > $len ) { break 2; }
					$additional[ $i ] = substr( $hex, $pos, 64 );
					$pos += 64;
				}
				$this->log_debug( 'parse_extra', "additional keys: {$n}" );
			} else {
				// Unknown tag - stop rather than misparse the rest.
				$this->log_debug( 'parse_extra', "unknown tag 0x" . sprintf( '%02x', $tag ) . " at pos {$pos}" );
				break;
			}
		}

		return array( 'main' => $main, 'additional' => $additional );
	}

	/**
	 * Read a Monero varint from a hex string at byte-position $pos (advanced past
	 * the consumed bytes). Returns -1 when malformed/truncated so callers can bail.
	 *
	 * @param string $hex  Full extra field as hex.
	 * @param int    $pos  Current BYTE position into $hex (2 chars per byte).
	 * @param int    $len  Total strlen( $hex ).
	 * @return int
	 */
	private function read_varint_hex( $hex, &$pos, $len ) {
		$value = 0;
		$shift = 0;
		while ( $pos + 2 <= $len ) {
			$byte = hexdec( substr( $hex, $pos, 2 ) );
			$pos += 2;
			$value |= ( $byte & 0x7f ) << $shift;
			if ( 0 === ( $byte & 0x80 ) ) {
				return $value;
			}
			$shift += 7;
			if ( $shift > 63 ) {
				return -1; // absurd varint - refuse to loop
			}
		}
		return -1; // truncated mid-varint
	}

	/**
	 * Decode a RingCT amount from ecdhInfo.
	 *
	 * Monero ecdhDecode (RingCT type 5/6 - Bulletproofs/Bulletproofs+):
	 *   1. sharedSec = Hs(derivation || varint(index))   [hash_to_scalar]
	 *   2. amount_key = cn_fast_hash("amount" || sharedSec)  [keccak_256, NO sc_reduce]
	 *   3. amount = ecdhInfo.amount XOR amount_key  (first 8 bytes, little-endian)
	 *
	 * @param string $derivation  Hex derivation (a·R, 32 bytes as hex).
	 * @param int    $index       Output index.
	 * @param string $amount_hex  Encrypted amount as hex string (from ecdhInfo).
	 * @return string  Atomic amount as decimal string.
	 */
	private function decode_amount( $derivation, $index, $amount_hex ) {
		// Step 1: sharedSec = Hs(derivation || varint(index)).
		$varint_hex = $this->cn->varint->encode_varint( $index );
		$shared_sec = $this->cn->hash_to_scalar( $derivation . $varint_hex );

		// Step 2: amount_key = keccak_256("amount" || sharedSec).
		$amount_prefix_hex = bin2hex( 'amount' );
		$amount_key_hex    = $this->cn->keccak_256( $amount_prefix_hex . $shared_sec );

		// Step 3: XOR first 8 bytes of amount_key with ecdhInfo.amount, then
		// interpret as little-endian uint64.
		$mask_8 = substr( $amount_key_hex, 0, 16 ); // first 8 bytes as hex
		$xored  = '';
		for ( $i = 0; $i < 16; $i += 2 ) {
			$mb = hexdec( substr( $mask_8, $i, 2 ) );
			$ab = hexdec( substr( $amount_hex, $i, 2 ) );
			$xored .= sprintf( '%02x', $mb ^ $ab );
		}
		// Reverse byte order (little-endian → big-endian for GMP).
		$xored_le = bin2hex( strrev( hex2bin( $xored ) ) );
		$decoded  = gmp_strval( gmp_init( $xored_le, 16 ), 10 );

		$this->log_debug( 'decode_amount', "index={$index} amount_hex={$amount_hex} sharedSec=" . substr( $shared_sec, 0, 16 ) . '... amount_key=' . substr( $amount_key_hex, 0, 16 ) . '... decoded=' . $decoded );
		return $decoded;
	}

	/**
	 * Derive the commitment mask scalar for an output.
	 *
	 * Monero ecdhDecode (RingCT type 5/6 - domain-separated hashing):
	 *   1. sharedSec = Hs(derivation || varint(index))   [hash_to_scalar]
	 *   2. mask = cn_fast_hash("commitment_mask" || sharedSec)  [keccak_256, NO sc_reduce]
	 *
	 * This is the scalar that blinds the amount in the Pedersen commitment C = x·G + a·H.
	 *
	 * @param string $derivation  Hex derivation (32 bytes as hex).
	 * @param int    $index       Output index.
	 * @return string  32-byte hex mask scalar.
	 */
	private function derive_commitment_mask( $derivation, $index ) {
		// Step 1: sharedSec = Hs(derivation || varint(index)).
		$varint_hex = $this->cn->varint->encode_varint( $index );
		$shared_sec = $this->cn->hash_to_scalar( $derivation . $varint_hex );

		// Step 2: mask = keccak_256("commitment_mask" || sharedSec).
		$cm_prefix_hex = bin2hex( 'commitment_mask' );
		return $this->cn->keccak_256( $cm_prefix_hex . $shared_sec );
	}

	/**
	 * Check the RingCT commitment: C = x·G + a·H, where x is the mask and a is the amount.
	 *
	 * @param string $amount_atomic  Decoded amount (decimal string).
	 * @param string $derivation     Hex derivation (32 bytes as hex).
	 * @param int    $index          Output index.
	 * @param string $commitment_hex 32-byte commitment as hex.
	 * @return bool
	 */
	private function check_commitment( $amount_atomic, $derivation, $index, $commitment_hex ) {
		try {
			// Derive the commitment mask scalar.
			$mask_hex = $this->derive_commitment_mask( $derivation, $index );
			$mask_int = $this->cn->ed25519->decodeint( hex2bin( $mask_hex ) );

			// C' = mask·G + amount·H.
			$maskG = $this->cn->ed25519->scalarmult_base( $mask_int );

			// H = hash_to_point(G) - the standard Monero secondary generator.
			// H is derived by hashing the generator point G to the curve.
			$G_bytes = $this->cn->ed25519->encodepoint( $this->cn->ed25519->B );
			$G_hex   = bin2hex( $G_bytes );
			$H       = $this->cn->hash_to_point( $G_hex );

			$amt_int = gmp_init( $amount_atomic, 10 );
			$amtH    = $this->cn->ed25519->scalarmult( $H, $amt_int );

			$C_prime = $this->cn->ed25519->edwards( $maskG, $amtH );
			$C       = $this->cn->ed25519->decodepoint( hex2bin( $commitment_hex ) );

			$C_prime_enc = $this->cn->ed25519->encodepoint( $C_prime );
			$C_enc       = $this->cn->ed25519->encodepoint( $C );

			$ok = ( $C_prime_enc === $C_enc );
			$this->log_debug( 'check_commitment', "index={$index} ok=" . ( $ok ? 'true' : 'false' ) );
			return $ok;
		} catch ( \Throwable $e ) {
			$this->log_warn( 'check_commitment', "index={$index} exception: " . $e->getMessage() );
			return false;
		}
	}

	/* ------------------------------------------------------------------ *
	 *  Payment detection
	 * ------------------------------------------------------------------ */

	/**
	 * Detect an output to $address inside one decoded tx and decode its amount.
	 *
	 * Returns ['output_index','amount_atomic','out_key','commitment_present','commitment_ok']
	 * or null if no output to this address.
	 *
	 * Subaddresses are handled: the additional pubkey (tag 04) is tried before the main R.
	 *
	 * @param array  $tx        Decoded transaction.
	 * @param string $address   Monero address/subaddress.
	 * @param string $view_key  Private view key (hex).
	 * @return array|null
	 */
	public function detect_in_tx( $tx, $address, $view_key ) {
		$this->metrics['txs_checked']++;

		try {
			$dec = $this->cn->decode_address( $address );
		} catch ( \Throwable $e ) {
			$this->log_error( 'detect', "decode_address failed: " . $e->getMessage() );
			return null;
		}
		if ( empty( $dec['spendKey'] ) ) {
			$this->log_warn( 'detect', 'decode_address returned empty spend key' );
			return null;
		}
		$C_spend = $dec['spendKey'];

		$extra = $this->parse_extra( isset( $tx['extra'] ) ? $tx['extra'] : array() );
		$vout  = isset( $tx['vout'] ) ? $tx['vout'] : array();
		if ( count( $vout ) > 256 ) {
			$this->log_warn( 'detect', 'too many outputs (' . count( $vout ) . '), skipping' );
			return null;
		}

		$ecdh  = isset( $tx['rct_signatures']['ecdhInfo'] ) ? $tx['rct_signatures']['ecdhInfo'] : array();
		$outpk = isset( $tx['rct_signatures']['outPk'] ) ? $tx['rct_signatures']['outPk'] :
			( isset( $tx['rctsig_prunable']['outPk'] ) ? $tx['rctsig_prunable']['outPk'] : array() );

		for ( $i = 0; $i < count( $vout ); $i++ ) {
			$this->metrics['outputs_checked']++;

			$t       = ( isset( $vout[ $i ]['target'] ) && is_array( $vout[ $i ]['target'] ) ) ? $vout[ $i ]['target'] : array();
			$out_key = isset( $t['key'] ) ? $t['key'] : ( isset( $t['tagged_key']['key'] ) ? $t['tagged_key']['key'] : null );
			if ( ! $out_key ) {
				$this->log_debug( 'detect', "output {$i}: no key, skipping" );
				continue;
			}

			// Build candidate tx pubkeys: additional[i] first (subaddress), then main R.
			$candidates = array();
			if ( isset( $extra['additional'][ $i ] ) ) { $candidates[] = $extra['additional'][ $i ]; }
			if ( $extra['main'] ) { $candidates[] = $extra['main']; }

			foreach ( $candidates as $R ) {
				// A tx pubkey that is not a valid curve point must NOT crash the scan.
				try {
					$derivation = $this->cn->gen_key_derivation( $R, $view_key );
					$owned      = ( $this->cn->derive_public_key( $derivation, $i, $C_spend ) === $out_key );
				} catch ( \Throwable $e ) {
					$this->log_debug( 'detect', "output {$i}: derivation/ownership check threw: " . $e->getMessage() );
					continue;
				}

				if ( ! $owned ) {
					$this->log_debug( 'detect', "output {$i}: not owned (R={$R})" );
					continue;
				}

				// OWNED! Decode amount + commitment.
				$this->log_info( 'detect', "output {$i}: OWNED (R={$R})" );
				try {
					$amt_hex       = isset( $ecdh[ $i ]['amount'] ) ? $ecdh[ $i ]['amount'] : '';
					$amount_atomic = '' !== $amt_hex ? $this->decode_amount( $derivation, $i, $amt_hex ) : '0';
					$commitment    = $this->outpk_mask( $outpk, $i );

					$commitment_present = ( '' !== (string) $commitment && null !== $commitment );
					$commitment_ok      = false;

					if ( $commitment_present ) {
						$commitment_ok = $this->check_commitment( $amount_atomic, $derivation, $i, $commitment );
						if ( $commitment_ok ) {
							$this->metrics['commitment_ok']++;
						} else {
							$this->metrics['commitment_fail']++;
						}
					}

					$this->metrics['matches_found']++;

					return array(
						'output_index'       => $i,
						'amount_atomic'      => $amount_atomic,
						'out_key'            => $out_key,
						'commitment_present' => $commitment_present,
						'commitment_ok'      => $commitment_ok,
					);
				} catch ( \Throwable $e ) {
					$this->log_warn( 'detect', "output {$i}: amount/commitment decode threw: " . $e->getMessage() );
					return array(
						'output_index'       => $i,
						'amount_atomic'      => '0',
						'out_key'            => $out_key,
						'commitment_present' => false,
						'commitment_ok'      => false,
						'errored'            => true,
					);
				}
			}
		}

		$this->log_debug( 'detect', 'no matching output found' );
		return null;
	}

	/**
	 * Verify a payment to $address by txid.
	 *
	 * @param string $txid
	 * @param string $address
	 * @param string $view_key  Private view key (hex).
	 * @param array  $opts      ['require_commitment'=>bool, 'tip'=>int|null]
	 * @return array  ['found'=>bool, 'amount_atomic'=>string, 'output_index'=>int,
	 *                 'confirmations'=>int|null, 'in_pool'=>bool, 'locked'=>bool,
	 *                 'commitment_ok'=>bool, 'reason'=>string]
	 */
	public function verify_payment( $txid, $address, $view_key, $opts = array() ) {
		$this->reset_metrics();
		$this->metrics['start_time'] = microtime( true );

		$require_commitment = isset( $opts['require_commitment'] ) ? (bool) $opts['require_commitment'] : true;
		$tip                = isset( $opts['tip'] ) ? (int) $opts['tip'] : null;
		$tx = $this->fetch_tx( $txid );
		if ( ! $tx ) {
			$this->log_error( 'verify', "txid={$txid} not returned by node" );
			return array( 'found' => false, 'reason' => 'node did not return the tx' );
		}
		return $this->classify_tx( $tx, $address, $view_key, $tip, $require_commitment );
	}

	/**
	 * Fold a per-tx match into the full result shape.
	 *
	 * @param array  $tx
	 * @param string $address
	 * @param string $view_key
	 * @param int|null $tip
	 * @param bool  $require_commitment
	 * @return array
	 */
	private function classify_tx( $tx, $address, $view_key, $tip, $require_commitment ) {
		$m = $this->detect_in_tx( $tx, $address, $view_key );
		if ( null === $m ) {
			$this->log_info( 'classify', 'no output to this address' );
			return array( 'found' => false, 'reason' => 'no output to this address' );
		}
		if ( $require_commitment && empty( $m['commitment_ok'] ) ) {
			$present = ! empty( $m['commitment_present'] );
			$this->log_warn( 'classify', 'commitment ' . ( $present ? 'mismatch' : 'unavailable' ) );
			return array(
				'found'              => true,
				'amount_atomic'      => $m['amount_atomic'],
				'output_index'       => $m['output_index'],
				'out_key'            => isset( $m['out_key'] ) ? $m['out_key'] : '',
				'commitment_ok'      => false,
				'commitment_present' => $present,
				'reason'             => $present
					? 'commitment mismatch - decoded amount not committed on-chain'
					: 'commitment unavailable - the node may be pruned; use a full (non-pruned) node',
			);
		}
		$bh   = isset( $tx['_block_height'] ) ? $tx['_block_height'] : null;
		$conf = ( null !== $bh && null !== $tip && $bh > 0 )
			? max( 0, $tip - $bh )
			: ( ! empty( $tx['_in_pool'] ) ? 0 : null );
		$locked = $this->is_locked(
			isset( $tx['unlock_time'] ) ? $tx['unlock_time'] : 0, $bh, $conf, $tip
		);
		$this->log_info( 'classify', "found: amount={$m['amount_atomic']} conf=" . ( null === $conf ? 'null' : $conf ) . ' locked=' . ( $locked ? 'yes' : 'no' ) );
		return array(
			'found'              => true,
			'amount_atomic'      => $m['amount_atomic'],
			'output_index'       => $m['output_index'],
			'confirmations'      => $conf,
			'in_pool'            => ! empty( $tx['_in_pool'] ),
			'double_spend_seen'  => ! empty( $tx['_double_spend_seen'] ),
			'locked'             => $locked,
			'out_key'            => isset( $m['out_key'] ) ? $m['out_key'] : '',
			'commitment_ok'      => $m['commitment_ok'],
			'reason'             => 'ok',
		);
	}

	/* ------------------------------------------------------------------ *
	 *  Subaddress derivation
	 * ------------------------------------------------------------------ */

	/**
	 * Credential self-check (ported from xmr-pay's XmrPay_Scanner::verify_keys):
	 * does this PRIVATE VIEW key actually belong to this address? Derives the
	 * public view key from the private one and compares it against the address -
	 * catching the #1 misconfiguration (a view key pasted for the wrong wallet),
	 * which otherwise means scanning runs forever and silently finds NOTHING.
	 *
	 * @param string $address   Primary Monero address.
	 * @param string $view_key  Private view key (hex).
	 * @return array  ['address_valid'=>bool, 'key_match'=>bool]
	 */
	public function verify_keys( $address, $view_key ) {
		try {
			$dec = $this->cn->decode_address( trim( (string) $address ) );
		} catch ( \Throwable $e ) {
			return array( 'address_valid' => false, 'key_match' => false );
		}
		if ( empty( $dec['viewKey'] ) || empty( $dec['spendKey'] ) ) {
			return array( 'address_valid' => false, 'key_match' => false );
		}
		try {
			$derived = $this->cn->pk_from_sk( strtolower( trim( (string) $view_key ) ) );
		} catch ( \Throwable $e ) {
			$derived = '';
		}
		return array(
			'address_valid' => true,
			'key_match'     => '' !== $derived && hash_equals( strtolower( (string) $dec['viewKey'] ), strtolower( $derived ) ),
		);
	}

	/**
	 * Derive the per-order subaddress (account $major, index $minor) from the merchant's
	 * primary address + private view key - no spend secret needed.
	 *
	 * @param int    $major
	 * @param int    $minor
	 * @param string $view_key         Private view key (hex).
	 * @param string $primary_address  Primary Monero address.
	 * @return array|null  ['address'=>string, 'spend_pub'=>hex] or null.
	 */
	public function subaddress( $major, $minor, $view_key, $primary_address ) {
		try {
			$dec = $this->cn->decode_address( $primary_address );
		} catch ( \Throwable $e ) {
			$this->log_error( 'subaddress', 'decode_address failed: ' . $e->getMessage() );
			return null;
		}
		if ( empty( $dec['spendKey'] ) ) { return null; }
		if ( 0 === (int) $major && 0 === (int) $minor ) {
			return array( 'address' => $primary_address, 'spend_pub' => $dec['spendKey'] );
		}
		try {
			$addr = $this->cn->generate_subaddress( (int) $major, (int) $minor, $view_key, $dec['spendKey'] );
			$sdec = $this->cn->decode_address( $addr );
			$this->log_info( 'subaddress', "derived {$major}/{$minor}: " . substr( $addr, 0, 12 ) . '...' );
			return array(
				'address'   => $addr,
				'spend_pub' => isset( $sdec['spendKey'] ) ? $sdec['spendKey'] : '',
			);
		} catch ( \Throwable $e ) {
			$this->log_error( 'subaddress', "generate_subaddress threw: " . $e->getMessage() );
			return null;
		}
	}

	/* ------------------------------------------------------------------ *
	 *  Block scanning (bounded, time-budgeted)
	 * ------------------------------------------------------------------ */

	/**
	 * Watch-mode block scan: look for a payment to $address across blocks [from..to],
	 * BOUNDED by max_blocks and a wall-clock budget.
	 *
	 * Returns the first match or ['found'=>false, 'scanned_to'=>height].
	 *
	 * @param string $address
	 * @param string $view_key
	 * @param int    $from_height
	 * @param int    $to_height
	 * @param array  $opts  ['max_blocks'=>int, 'time_budget'=>float, 'require_commitment'=>bool, 'tip'=>int]
	 * @return array
	 */
	public function scan( $address, $view_key, $from_height, $to_height, $opts = array() ) {
		$this->reset_metrics();
		$this->metrics['start_time'] = microtime( true );

		$max_blocks = isset( $opts['max_blocks'] ) ? max( 1, (int) $opts['max_blocks'] ) : 30;
		$budget_s   = isset( $opts['time_budget'] ) ? (float) $opts['time_budget'] : 8.0;
		$req_commit = isset( $opts['require_commitment'] ) ? (bool) $opts['require_commitment'] : true;
		$tip        = isset( $opts['tip'] ) ? (int) $opts['tip'] : (int) $to_height;
		$start      = microtime( true );
		$h          = (int) $from_height;
		$end        = min( (int) $to_height, $h + $max_blocks - 1 );
		$last       = $h - 1;

		$this->log_info( 'scan', "start height={$h} end={$end} max_blocks={$max_blocks} budget={$budget_s}s tip={$tip}" );

		for ( ; $h <= $end; $h++ ) {
			if ( ( microtime( true ) - $start ) > $budget_s ) {
				$this->log_warn( 'scan', "time budget exceeded at height={$h}" );
				break;
			}
			$this->metrics['blocks_scanned']++;

			$hashes = $this->block_tx_hashes( $h );
			if ( null === $hashes ) {
				$this->log_warn( 'scan', "block_tx_hashes returned null at height={$h}, stopping" );
				break;
			}

			if ( empty( $hashes ) ) {
				$this->log_debug( 'scan', "height={$h} no txs" );
				$last = $h;
				continue;
			}

			foreach ( array_chunk( $hashes, 50 ) as $batch ) {
				$txs = $this->fetch_txs( $batch );
				if ( null === $txs ) {
					$this->log_warn( 'scan', "fetch_txs returned null at height={$h}" );
					return array( 'found' => false, 'scanned_to' => $last );
				}
				foreach ( $txs as $tx ) {
					$m = $this->detect_in_tx( $tx, $address, $view_key );
					if ( null === $m ) { continue; }
					if ( $req_commit && empty( $m['commitment_ok'] ) ) {
						$this->log_warn( 'scan', "match at height={$h} but commitment failed, skipping" );
						continue;
					}
					$bh   = isset( $tx['_block_height'] ) ? (int) $tx['_block_height'] : $h;
					$conf = max( 0, $tip - $bh );
					$this->log_info( 'scan', "MATCH at height={$bh} txid=" . ( isset( $tx['_txid'] ) ? $tx['_txid'] : '?' ) . " amount={$m['amount_atomic']} conf={$conf}" );
					return array(
						'found'          => true,
						'txid'           => isset( $tx['_txid'] ) ? $tx['_txid'] : '',
						'amount_atomic'  => $m['amount_atomic'],
						'output_index'   => $m['output_index'],
						'confirmations'  => $conf,
						'in_pool'        => false,
						'locked'         => $this->is_locked(
							isset( $tx['unlock_time'] ) ? $tx['unlock_time'] : 0, $bh, $conf, $tip
						),
						'out_key'        => isset( $m['out_key'] ) ? $m['out_key'] : '',
						'commitment_ok'  => $m['commitment_ok'],
						'block_height'   => $bh,
					);
				}
			}
			$last = $h;
		}

		$this->log_info( 'scan', "no match, scanned_to={$last}" );
		return array( 'found' => false, 'scanned_to' => $last );
	}

	/**
	 * Same bounded block scan as scan(), but collects EVERY matching payment in the
	 * window instead of returning the first.
	 *
	 * @param string $address
	 * @param string $view_key
	 * @param int    $from_height
	 * @param int    $to_height
	 * @param array  $opts
	 * @return array  ['matches'=>[row,...], 'scanned_to'=>int]
	 */
	public function scan_all( $address, $view_key, $from_height, $to_height, $opts = array() ) {
		$this->reset_metrics();
		$this->metrics['start_time'] = microtime( true );

		$max_blocks = isset( $opts['max_blocks'] ) ? max( 1, (int) $opts['max_blocks'] ) : 30;
		$budget_s   = isset( $opts['time_budget'] ) ? (float) $opts['time_budget'] : 8.0;
		$req_commit = isset( $opts['require_commitment'] ) ? (bool) $opts['require_commitment'] : true;
		$tip        = isset( $opts['tip'] ) ? (int) $opts['tip'] : (int) $to_height;
		$start      = microtime( true );
		$h          = (int) $from_height;
		$end        = min( (int) $to_height, $h + $max_blocks - 1 );
		$last       = $h - 1;
		$matches    = array();

		$this->log_info( 'scan_all', "start height={$h} end={$end} max_blocks={$max_blocks} budget={$budget_s}s tip={$tip}" );

		for ( ; $h <= $end; $h++ ) {
			if ( ( microtime( true ) - $start ) > $budget_s ) {
				$this->log_warn( 'scan_all', "time budget exceeded at height={$h}" );
				break;
			}
			$this->metrics['blocks_scanned']++;

			$hashes = $this->block_tx_hashes( $h );
			if ( null === $hashes ) {
				$this->log_warn( 'scan_all', "block_tx_hashes returned null at height={$h}, stopping" );
				break;
			}

			if ( empty( $hashes ) ) {
				$last = $h;
				continue;
			}

			foreach ( array_chunk( $hashes, 50 ) as $batch ) {
				$txs = $this->fetch_txs( $batch );
				if ( null === $txs ) {
					$this->log_warn( 'scan_all', "fetch_txs returned null at height={$h}" );
					return array( 'matches' => $matches, 'scanned_to' => $last );
				}
				foreach ( $txs as $tx ) {
					$m = $this->detect_in_tx( $tx, $address, $view_key );
					if ( null === $m ) { continue; }
					if ( $req_commit && empty( $m['commitment_ok'] ) ) {
						$this->log_warn( 'scan_all', "match at height={$h} but commitment failed, skipping" );
						continue;
					}
					$bh   = isset( $tx['_block_height'] ) ? (int) $tx['_block_height'] : $h;
					$conf = max( 0, $tip - $bh );
					$this->log_info( 'scan_all', "MATCH at height={$bh} txid=" . ( isset( $tx['_txid'] ) ? $tx['_txid'] : '?' ) . " amount={$m['amount_atomic']} conf={$conf}" );
					$matches[] = array(
						'txid'           => isset( $tx['_txid'] ) ? $tx['_txid'] : '',
						'amount_atomic'  => $m['amount_atomic'],
						'output_index'   => $m['output_index'],
						'confirmations'  => $conf,
						'in_pool'        => false,
						'locked'         => $this->is_locked(
							isset( $tx['unlock_time'] ) ? $tx['unlock_time'] : 0, $bh, $conf, $tip
						),
						'out_key'        => isset( $m['out_key'] ) ? $m['out_key'] : '',
						'commitment_ok'  => $m['commitment_ok'],
						'block_height'   => $bh,
					);
				}
			}
			$last = $h;
		}

		$this->log_info( 'scan_all', "matches=" . count( $matches ) . " scanned_to={$last}" );
		return array( 'matches' => $matches, 'scanned_to' => $last );
	}

	/* ------------------------------------------------------------------ *
	 *  Helpers
	 * ------------------------------------------------------------------ */

	/**
	 * outPk[i] commitment as 32-byte hex.
	 *
	 * @param array $outpk
	 * @param int   $i
	 * @return string|null
	 */
	private function outpk_mask( $outpk, $i ) {
		if ( ! isset( $outpk[ $i ] ) ) { return null; }
		$v = $outpk[ $i ];
		if ( is_string( $v ) ) { return $v; }
		if ( is_array( $v ) && isset( $v['mask'] ) ) { return $v['mask']; }
		return null;
	}

	/**
	 * unlock_time gate (both Monero forms). <5e8 = block height; >=5e8 = unix time.
	 *
	 * @param int      $unlock_time
	 * @param int|null $block_height
	 * @param int|null $conf
	 * @param int|null $tip
	 * @return bool
	 */
	private function is_locked( $unlock_time, $block_height, $conf, $tip ) {
		$ut = (int) $unlock_time;
		if ( 0 === $ut ) { return false; }
		if ( $ut < 500000000 ) {
			if ( null === $tip ) { return true; }
			return $ut > ( $tip - 1 );
		}
		return $ut > ( time() - 1 );
	}

	/* ------------------------------------------------------------------ *
	 *  Logging (4 levels: ERROR=1, WARN=2, INFO=3, DEBUG=4)
	 * ------------------------------------------------------------------ */

	/**
	 * Log an ERROR message (level 1).
	 *
	 * @param string $tag     Short tag identifying the subsystem.
	 * @param string $message Human-readable message.
	 */
	private function log_error( $tag, $message ) {
		if ( $this->log_level < 1 ) { return; }
		$this->log( 'ERROR', $tag, $message );
	}

	/**
	 * Log a WARN message (level 2).
	 *
	 * @param string $tag
	 * @param string $message
	 */
	private function log_warn( $tag, $message ) {
		if ( $this->log_level < 2 ) { return; }
		$this->log( 'WARNING', $tag, $message );
	}

	/**
	 * Log an INFO message (level 3, default).
	 *
	 * @param string $tag
	 * @param string $message
	 */
	private function log_info( $tag, $message ) {
		if ( $this->log_level < 3 ) { return; }
		$this->log( 'INFO', $tag, $message );
	}

	/**
	 * Log a DEBUG message (level 4, most verbose).
	 *
	 * @param string $tag
	 * @param string $message
	 */
	private function log_debug( $tag, $message ) {
		if ( $this->log_level < 4 ) { return; }
		$this->log( 'DEBUG', $tag, $message );
	}

	/**
	 * Core log writer - routes to WC_Logger (in WP) or error_log (in CLI).
	 *
	 * @param string $level   One of: ERROR, WARNING, INFO, DEBUG
	 * @param string $tag     Short subsystem tag.
	 * @param string $message Human-readable message.
	 */
	private function log( $level, $tag, $message ) {
		$formatted = sprintf( '[%s] [%s] %s', $level, $tag, $message );

		// In WordPress context, use WC_Logger.
		if ( function_exists( 'wc_get_logger' ) ) {
			$logger = wc_get_logger();
			if ( $logger ) {
				$context = array( 'source' => 'wc-monero-native-scanner' );
				$wc_level = strtoupper( $level );
				// Map our levels to WC_Logger levels.
				$logger->log( $wc_level, $formatted, $context );
				return;
			}
		}

		// Fallback: error_log (works in CLI mode).
		error_log( $formatted );
	}
}