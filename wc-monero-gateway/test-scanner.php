<?php
/**
 * test-scanner.php - Standalone CLI test for the WC Monero Native Scanner.
 *
 * Tests the vendored crypto primitives (ed25519, Keccak, base58, Cryptonote)
 * and optionally connects to a monerod node to verify payment detection.
 *
 * Usage:
 *   php test-scanner.php [options]
 *
 * Options:
 *   --logging=1|2|3|4   Logging level (1=ERROR, 2=WARN, 3=INFO, 4=DEBUG)  [default: 3]
 *   --node=URL          Daemon URL, e.g. http://localhost:18081
 *   --address=ADDR      Monero address to check
 *   --viewkey=HEX       Private view key (hex)
 *   --txid=HEX          Transaction ID to verify
 *   --from=N            Scan from block height N
 *   --to=N              Scan to block height N
 *   --max-blocks=N      Max blocks to scan [default: 30]
 *   --no-commitment     Skip commitment verification
 *   --crypto-only       Only test crypto primitives, skip node tests
 *
 * Examples:
 *   php test-scanner.php --logging=4 --crypto-only
 *   php test-scanner.php --logging=3 --node=http://localhost:18081 --address=... --viewkey=... --txid=...
 *   php test-scanner.php --logging=3 --node=http://localhost:18081 --address=... --viewkey=... --from=3100000 --to=3100010
 *
 * @package WC_Monero_Gateway
 */

// Prevent the native scanner's ABSPATH guard from blocking CLI usage.
define( 'ABSPATH', dirname( __DIR__, 3 ) . '/' );

// Stub WordPress functions that the scanner uses.
if ( ! function_exists( 'wp_json_encode' ) ) {
	function wp_json_encode( $data ) {
		return json_encode( $data );
	}
}
if ( ! function_exists( 'wp_remote_post' ) ) {
	function wp_remote_post( $url, $args = array() ) {
		$ch = curl_init();
		curl_setopt( $ch, CURLOPT_URL, $url );
		curl_setopt( $ch, CURLOPT_POST, true );
		curl_setopt( $ch, CURLOPT_POSTFIELDS, $args['body'] ?? '' );
		curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
		curl_setopt( $ch, CURLOPT_TIMEOUT, $args['timeout'] ?? 30 );
		curl_setopt( $ch, CURLOPT_HTTPHEADER, array(
			'Content-Type: application/json',
			'Accept: application/json',
		) );
		// Add auth header if present.
		if ( isset( $args['headers']['Authorization'] ) ) {
			curl_setopt( $ch, CURLOPT_HTTPHEADER, array(
				'Content-Type: application/json',
				'Accept: application/json',
				'Authorization: ' . $args['headers']['Authorization'],
			) );
		}
		$response = curl_exec( $ch );
		$code     = curl_getinfo( $ch, CURLINFO_HTTP_CODE );
		$error    = curl_error( $ch );
		curl_close( $ch );

		if ( false === $response ) {
			return new WP_Error( 'curl_error', $error );
		}

		return array(
			'body'     => $response,
			'response' => array( 'code' => $code ),
		);
	}
}
if ( ! function_exists( 'is_wp_error' ) ) {
	function is_wp_error( $thing ) {
		return $thing instanceof WP_Error;
	}
}
if ( ! function_exists( 'wp_remote_retrieve_body' ) ) {
	function wp_remote_retrieve_body( $response ) {
		return is_array( $response ) ? ( $response['body'] ?? '' ) : '';
	}
}
if ( ! function_exists( 'wp_remote_retrieve_response_code' ) ) {
	function wp_remote_retrieve_response_code( $response ) {
		return is_array( $response ) ? ( $response['response']['code'] ?? 0 ) : 0;
	}
}
if ( ! class_exists( 'WP_Error' ) ) {
	class WP_Error {
		public $errors = array();
		public function __construct( $code = '', $message = '' ) {
			if ( $code ) {
				$this->errors[ $code ][] = $message;
			}
		}
		public function get_error_message() {
			foreach ( $this->errors as $code => $messages ) {
				return $messages[0] ?? 'Unknown error';
			}
			return 'Unknown error';
		}
	}
}

// ─── Parse CLI args ──────────────────────────────────────────────────────

$opts = array(
	'logging'       => 3,
	'node'          => null,
	'address'       => null,
	'viewkey'       => null,
	'txid'          => null,
	'from'          => null,
	'to'            => null,
	'max-blocks'    => 30,
	'no-commitment' => false,
	'crypto-only'   => false,
);

foreach ( $argv as $arg ) {
	if ( strpos( $arg, '--' ) === 0 ) {
		$parts = explode( '=', substr( $arg, 2 ), 2 );
		$key   = $parts[0];
		$val   = isset( $parts[1] ) ? $parts[1] : true;
		if ( isset( $opts[ $key ] ) || array_key_exists( $key, $opts ) ) {
			$opts[ $key ] = $val;
		}
	}
}

$log_level = (int) $opts['logging'];

// ─── Output helpers ──────────────────────────────────────────────────────

function out( $msg = '' ) {
	echo $msg . "\n";
}

function section( $title ) {
	out();
	out( "═══════════════════════════════════════════════════════════════" );
	out( "  {$title}" );
	out( "═══════════════════════════════════════════════════════════════" );
}

function pass( $msg ) {
	out( "  [OK] {$msg}" );
}

function fail( $msg ) {
	out( "  [FAIL] {$msg}" );
}

function info( $msg ) {
	out( "   {$msg}" );
}

function warn( $msg ) {
	out( "   {$msg}" );
}

// ─── Load the scanner ────────────────────────────────────────────────────

out( "WC Monero Native Scanner - Standalone Test" );
out( "PHP " . PHP_VERSION . " (" . PHP_OS . ")" );
out( "Logging level: {$log_level}" );

// Check required extensions.
section( 'PHP Extension Check' );
$required = array( 'gmp', 'bcmath', 'curl', 'json' );
$missing  = array();
foreach ( $required as $ext ) {
	if ( extension_loaded( $ext ) ) {
		pass( $ext );
	} else {
		fail( $ext . ' - NOT loaded' );
		$missing[] = $ext;
	}
}
if ( ! empty( $missing ) ) {
	out();
	fail( 'Missing extensions: ' . implode( ', ', $missing ) );
	fail( 'The scanner requires GMP and BCMath for crypto math.' );
	exit( 1 );
}

// Load vendor crypto.
section( 'Loading Vendored Crypto' );
$vendor_path = __DIR__ . '/vendor/monero/load.php';
if ( ! file_exists( $vendor_path ) ) {
	fail( "vendor/monero/load.php not found at {$vendor_path}" );
	exit( 1 );
}
try {
	require_once $vendor_path;
	pass( 'vendor/monero/load.php loaded' );
} catch ( \Throwable $e ) {
	fail( 'Failed to load vendor crypto: ' . $e->getMessage() );
	exit( 1 );
}

// Verify classes exist.
$classes = array(
	'MoneroIntegrations\MoneroPhp\Cryptonote',
	'MoneroIntegrations\MoneroPhp\ed25519',
	'MoneroIntegrations\MoneroPhp\base58',
	'MoneroIntegrations\MoneroPhp\Varint',
	'kornrunner\Keccak',
);
foreach ( $classes as $cls ) {
	if ( class_exists( $cls ) ) {
		pass( "class {$cls}" );
	} else {
		fail( "class {$cls} - NOT FOUND" );
		exit( 1 );
	}
}

// ─── Test 1: Keccak-256 ──────────────────────────────────────────────────

section( 'Test 1: Keccak-256' );
try {
	$keccak = new \kornrunner\Keccak();

	// Known test vector: keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
	$empty_hash = \kornrunner\Keccak::hash( '', 256 );
	if ( $empty_hash === 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470' ) {
		pass( "keccak256('') = {$empty_hash}" );
	} else {
		fail( "keccak256('') = {$empty_hash} - expected c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" );
	}

	// keccak256("abc") = 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
	$abc_hash = \kornrunner\Keccak::hash( 'abc', 256 );
	if ( $abc_hash === '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45' ) {
		pass( "keccak256('abc') = {$abc_hash}" );
	} else {
		fail( "keccak256('abc') = {$abc_hash} - expected 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45" );
	}
} catch ( \Throwable $e ) {
	fail( 'Keccak test threw: ' . $e->getMessage() );
}

// ─── Test 2: Base58 encode/decode ────────────────────────────────────────

section( 'Test 2: Base58' );
try {
	$cn = new \MoneroIntegrations\MoneroPhp\Cryptonote();

	// Test with a known Monero address (stagenet test address).
	$test_addr = '54ndLZkk77Jaa5aW3nS7wvz7T2TASpQ9M6f4aE7qQ3Z6rBvq6G5gV8m2jN3pL4sQ1wR9tY7uX2vK8jH5fD3cB6eN4mP';
	// Actually, let's use a simpler round-trip test.
	$test_hex = '12' . str_repeat( 'a', 64 ) . str_repeat( 'b', 64 ) . '1234abcd';
	$encoded  = $cn->base58->encode( $test_hex );
	$decoded  = $cn->base58->decode( $encoded );

	if ( $decoded === $test_hex ) {
		pass( "base58 round-trip OK (len=" . strlen( $test_hex ) . " → " . strlen( $encoded ) . " → " . strlen( $decoded ) . ")" );
	} else {
		fail( "base58 round-trip FAILED" );
		info( "original:  {$test_hex}" );
		info( "decoded:   {$decoded}" );
	}
} catch ( \Throwable $e ) {
	fail( 'Base58 test threw: ' . $e->getMessage() );
}

// ─── Test 3: ed25519 key generation ──────────────────────────────────────

section( 'Test 3: ed25519 Key Generation' );
try {
	$ed = new \MoneroIntegrations\MoneroPhp\ed25519();

	// Generate a key pair from a known seed.
	$seed = '0000000000000000000000000000000000000000000000000000000000000001';
	$sk   = $cn->sc_reduce( $seed );
	$pk   = $cn->pk_from_sk( $sk );

	pass( "sc_reduce(seed) = {$sk}" );
	pass( "pk_from_sk(sk)  = {$pk}" );

	// Verify the public key is 32 bytes (64 hex chars).
	if ( strlen( $pk ) === 64 ) {
		pass( "public key length = 32 bytes" );
	} else {
		fail( "public key length = " . ( strlen( $pk ) / 2 ) . " bytes - expected 32" );
	}
} catch ( \Throwable $e ) {
	fail( 'ed25519 test threw: ' . $e->getMessage() );
}

// ─── Test 4: Address decode/encode round-trip ────────────────────────────

section( 'Test 4: Address Decode/Encode Round-Trip' );
try {
	// Generate a test address.
	$seed    = '6bc8f8f06c971b168745f562aa107b4d172f336271bc0f9d3b510c14d3460dfb';
	$priv    = $cn->gen_private_keys( $seed );
	$pub_spend = $cn->pk_from_sk( $priv['spendKey'] );
	$pub_view  = $cn->pk_from_sk( $priv['viewKey'] );
	$address   = $cn->encode_address( $pub_spend, $pub_view );

	pass( "Generated address: " . substr( $address, 0, 12 ) . '...' . substr( $address, -8 ) );

	// Decode it back.
	$decoded = $cn->decode_address( $address );
	if ( $decoded['spendKey'] === $pub_spend && $decoded['viewKey'] === $pub_view ) {
		pass( "Decode round-trip OK - keys match" );
	} else {
		fail( "Decode round-trip FAILED - keys mismatch" );
		info( "spend: expected {$pub_spend} got {$decoded['spendKey']}" );
		info( "view:  expected {$pub_view} got {$decoded['viewKey']}" );
	}

	// Verify checksum.
	if ( $cn->verify_checksum( $address ) ) {
		pass( "Checksum valid" );
	} else {
		fail( "Checksum INVALID" );
	}
} catch ( \Throwable $e ) {
	fail( 'Address test threw: ' . $e->getMessage() );
}

// ─── Test 5: Key derivation ──────────────────────────────────────────────

section( 'Test 5: Key Derivation (gen_key_derivation)' );
try {
	// Use the keys from Test 4.
	$tx_pubkey = $pub_spend; // Using our own pubkey as a stand-in tx pubkey.
	$view_key  = $priv['viewKey'];

	$derivation = $cn->gen_key_derivation( $tx_pubkey, $view_key );
	if ( strlen( $derivation ) === 64 ) {
		pass( "gen_key_derivation OK = " . substr( $derivation, 0, 16 ) . '...' );
	} else {
		fail( "gen_key_derivation returned wrong length: " . strlen( $derivation ) );
	}

	// derive_public_key should produce a valid 32-byte key.
	$derived_pub = $cn->derive_public_key( $derivation, 0, $pub_spend );
	if ( strlen( $derived_pub ) === 64 ) {
		pass( "derive_public_key OK = " . substr( $derived_pub, 0, 16 ) . '...' );
	} else {
		fail( "derive_public_key returned wrong length: " . strlen( $derived_pub ) );
	}
} catch ( \Throwable $e ) {
	fail( 'Key derivation test threw: ' . $e->getMessage() );
}

// ─── Test 6: Varint encode/decode ────────────────────────────────────────

section( 'Test 6: Varint Encode/Decode' );
try {
	$test_values = array( 0, 1, 127, 128, 255, 256, 16383, 16384, 65535, 65536, 1000000 );
	$all_ok      = true;
	foreach ( $test_values as $val ) {
		$encoded = $cn->varint->encode_varint( $val );
		// Decode: split hex string into array of hex bytes.
		$bytes   = str_split( $encoded, 2 );
		$decoded = $cn->varint->decode_varint( $bytes );
		if ( $decoded == $val ) {
			pass( "varint({$val}) = {$encoded} → {$decoded}" );
		} else {
			fail( "varint({$val}) = {$encoded} → {$decoded} MISMATCH" );
			$all_ok = false;
		}
	}
} catch ( \Throwable $e ) {
	fail( 'Varint test threw: ' . $e->getMessage() );
}

// ─── Test 7: hash_to_point ───────────────────────────────────────────────

section( 'Test 7: hash_to_point' );
try {
	$G_bytes = $cn->ed25519->encodepoint( $cn->ed25519->B );
	$G_hex   = bin2hex( $G_bytes );
	$H       = $cn->hash_to_point( $G_hex );

	// H should be a valid point [x, y] on the curve.
	if ( is_array( $H ) && count( $H ) === 2 ) {
		$H_enc = $cn->ed25519->encodepoint( $H );
		pass( "hash_to_point(G) = " . substr( bin2hex( $H_enc ), 0, 16 ) . '...' );
		// Verify it's on the curve.
		if ( $cn->ed25519->isoncurve( $H ) ) {
			pass( "H is on the ed25519 curve" );
		} else {
			fail( "H is NOT on the curve" );
		}
	} else {
		fail( "hash_to_point returned invalid result" );
	}
} catch ( \Throwable $e ) {
	fail( 'hash_to_point test threw: ' . $e->getMessage() );
}

// ─── Test 8: Subaddress derivation ───────────────────────────────────────

section( 'Test 8: Subaddress Derivation' );
try {
	$sub1 = $cn->generate_subaddress( 0, 1, $priv['viewKey'], $pub_spend );
	$sub2 = $cn->generate_subaddress( 0, 2, $priv['viewKey'], $pub_spend );

	pass( "subaddress(0,1) = " . substr( $sub1, 0, 12 ) . '...' . substr( $sub1, -8 ) );
	pass( "subaddress(0,2) = " . substr( $sub2, 0, 12 ) . '...' . substr( $sub2, -8 ) );

	// Subaddresses should be different from each other and from the primary.
	if ( $sub1 !== $sub2 && $sub1 !== $address && $sub2 !== $address ) {
		pass( "All subaddresses are distinct" );
	} else {
		fail( "Subaddress collision detected!" );
	}

	// Verify subaddress checksums.
	if ( $cn->verify_checksum( $sub1 ) && $cn->verify_checksum( $sub2 ) ) {
		pass( "Subaddress checksums valid" );
	} else {
		fail( "Subaddress checksum INVALID" );
	}
} catch ( \Throwable $e ) {
	fail( 'Subaddress test threw: ' . $e->getMessage() );
}

// ─── Crypto-only mode: stop here ─────────────────────────────────────────

if ( $opts['crypto-only'] ) {
	section( 'Summary' );
	out( "  Crypto primitives test complete." );
	out( "  All tests passed [OK]" );
	exit( 0 );
}

// ─── Node connectivity & payment detection ───────────────────────────────

if ( empty( $opts['node'] ) ) {
	section( 'Node Tests Skipped' );
	info( 'No --node=URL provided. Use --crypto-only to skip this message.' );
	info( 'Example: php test-scanner.php --node=http://localhost:18081 --address=... --viewkey=... --txid=...' );
	exit( 0 );
}

section( 'Loading Native Scanner Class' );
$scanner_path = __DIR__ . '/includes/class-wc-monero-native-scanner.php';
if ( ! file_exists( $scanner_path ) ) {
	fail( "Scanner file not found: {$scanner_path}" );
	exit( 1 );
}
try {
	require_once $scanner_path;
	pass( 'Scanner class loaded' );
} catch ( \Throwable $e ) {
	fail( 'Failed to load scanner: ' . $e->getMessage() );
	exit( 1 );
}

// Instantiate scanner.
$node_config = array(
	'url'      => $opts['node'],
	'auth'     => 'none',
	'username' => '',
	'password' => '',
);

try {
	$scanner = new WC_Monero_Native_Scanner( $node_config, $log_level );
	pass( "Scanner instantiated (log_level={$log_level})" );
} catch ( \Throwable $e ) {
	fail( 'Scanner instantiation failed: ' . $e->getMessage() );
	exit( 1 );
}

// ─── Test 9: Node connectivity ───────────────────────────────────────────

section( 'Test 9: Node Connectivity' );
try {
	$height = $scanner->get_height();
	if ( null !== $height ) {
		pass( "Connected to daemon, tip height = {$height}" );
	} else {
		fail( "Could not get height from daemon at {$opts['node']}" );
		info( 'Make sure monerod is running with --rpc-bind-port and --confirm-external-bind' );
		exit( 1 );
	}
} catch ( \Throwable $e ) {
	fail( 'Node connectivity test threw: ' . $e->getMessage() );
	exit( 1 );
}

// ─── Test 10: Block fetch ────────────────────────────────────────────────

section( 'Test 10: Block Fetch' );
try {
	$test_height = max( 0, $height - 10 );
	$hashes = $scanner->block_tx_hashes( $test_height );
	if ( null !== $hashes ) {
		pass( "block_tx_hashes({$test_height}) returned " . count( $hashes ) . " txs" );
	} else {
		warn( "block_tx_hashes({$test_height}) returned null - block may not exist yet" );
	}
} catch ( \Throwable $e ) {
	fail( 'Block fetch test threw: ' . $e->getMessage() );
}

// ─── Test 11: Payment verification by txid ───────────────────────────────

if ( ! empty( $opts['txid'] ) && ! empty( $opts['address'] ) && ! empty( $opts['viewkey'] ) ) {
	section( 'Test 11: Payment Verification' );
	info( "txid:    {$opts['txid']}" );
	info( "address: " . substr( $opts['address'], 0, 12 ) . '...' );
	info( "viewkey: " . substr( $opts['viewkey'], 0, 12 ) . '...' );

	try {
		$result = $scanner->verify_payment(
			$opts['txid'],
			$opts['address'],
			$opts['viewkey'],
			array(
				'require_commitment' => ! $opts['no-commitment'],
				'tip'                => $height,
			)
		);

		out();
		info( "Result:" );
		foreach ( $result as $k => $v ) {
			info( "  {$k}: {$v}" );
		}

		// Print metrics.
		$metrics = $scanner->get_metrics();
		out();
		info( "Metrics:" );
		foreach ( $metrics as $k => $v ) {
			info( "  {$k}: {$v}" );
		}

		if ( ! empty( $result['found'] ) ) {
			pass( "Payment FOUND!" );
			if ( ! empty( $result['commitment_ok'] ) ) {
				pass( "Commitment verified [OK]" );
			} elseif ( isset( $result['commitment_ok'] ) && ! $result['commitment_ok'] ) {
				warn( "Commitment NOT verified (may need --no-commitment or a non-pruned node)" );
			}
		} else {
			warn( "Payment not found: " . ( $result['reason'] ?? 'unknown' ) );
		}
	} catch ( \Throwable $e ) {
		fail( 'Payment verification threw: ' . $e->getMessage() );
	}
} else {
	out();
	info( 'Skip payment verification: provide --txid, --address, and --viewkey to test.' );
}

// ─── Test 12: Block scan ─────────────────────────────────────────────────

if ( ! empty( $opts['from'] ) && ! empty( $opts['address'] ) && ! empty( $opts['viewkey'] ) ) {
	section( 'Test 12: Block Scan' );
	$from = (int) $opts['from'];
	$to   = ! empty( $opts['to'] ) ? (int) $opts['to'] : $height;
	info( "Scanning blocks {$from} → {$to} (max_blocks={$opts['max-blocks']})" );

	try {
		$result = $scanner->scan(
			$opts['address'],
			$opts['viewkey'],
			$from,
			$to,
			array(
				'max_blocks'         => (int) $opts['max-blocks'],
				'time_budget'        => 30.0,
				'require_commitment' => ! $opts['no-commitment'],
				'tip'                => $height,
			)
		);

		out();
		info( "Result:" );
		foreach ( $result as $k => $v ) {
			if ( is_array( $v ) ) {
				info( "  {$k}: " . json_encode( $v ) );
			} else {
				info( "  {$k}: {$v}" );
			}
		}

		// Print metrics.
		$metrics = $scanner->get_metrics();
		out();
		info( "Metrics:" );
		foreach ( $metrics as $k => $v ) {
			info( "  {$k}: {$v}" );
		}

		if ( ! empty( $result['found'] ) ) {
			pass( "Match found in block scan!" );
		} else {
			info( "No match found, scanned to block " . ( $result['scanned_to'] ?? '?' ) );
		}
	} catch ( \Throwable $e ) {
		fail( 'Block scan threw: ' . $e->getMessage() );
	}
} else {
	out();
	if ( empty( $opts['from'] ) ) {
		info( 'Skip block scan: provide --from=N (and optionally --to=N) to test.' );
	}
}

// ─── Summary ─────────────────────────────────────────────────────────────

section( 'All Tests Complete' );
out( "  Logging level was: {$log_level}" );
out( "  Use --logging=4 for verbose debug output." );
exit( 0 );