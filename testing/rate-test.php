<?php
/**
 * OFFLINE test of the new stale-while-revalidate rate logic in
 * class-wc-xmr-poller.php (price section). Stubs the WP API surface and
 * scripts WC_XMR_HTTP responses; asserts cache tiering, stampede lock,
 * cron refresh, alert suppression and timeout bounds.
 *
 *   php rate-test.php
 */

error_reporting( E_ALL & ~E_DEPRECATED );

if ( ! defined( 'ABSPATH' ) ) { define( 'ABSPATH', __DIR__ . '/' ); }
if ( ! defined( 'MINUTE_IN_SECONDS' ) ) { define( 'MINUTE_IN_SECONDS', 60 ); }
if ( ! defined( 'HOUR_IN_SECONDS' ) ) { define( 'HOUR_IN_SECONDS', 3600 ); }

$GLOBALS['__transients'] = array();
$GLOBALS['__options']    = array();
$GLOBALS['__scheduled']  = array();
$GLOBALS['__alerts']     = array();
$GLOBALS['__http']       = array();   // queue of scripted WC_XMR_HTTP::get results
$GLOBALS['__http_log']   = array();   // [url, timeout] of every request

function get_transient( $k ) { return $GLOBALS['__transients'][ $k ] ?? false; }
function set_transient( $k, $v, $e = 0 ) { $GLOBALS['__transients'][ $k ] = $v; return true; }
function delete_transient( $k ) { unset( $GLOBALS['__transients'][ $k ] ); return true; }
function update_option( $k, $v, $a = null ) { $GLOBALS['__options'][ $k ] = $v; return true; }
function get_option( $k, $d = false ) { return $GLOBALS['__options'][ $k ] ?? $d; }
function wp_schedule_single_event( $t, $h, $a = array() ) { $GLOBALS['__scheduled'][] = array( $h, $a ); return true; }
function wp_next_scheduled( $h ) { foreach ( $GLOBALS['__scheduled'] as $s ) { if ( $s[0] === $h && empty( $s[1] ) ) return 123; } return false; }
function wp_schedule_event( $t, $r, $h ) { $GLOBALS['__scheduled'][] = array( $h, array(), $r ); return true; }
function wp_clear_scheduled_hook( $h ) { return true; }
function add_action( ...$a ) {}
function add_filter( ...$a ) {}
$GLOBALS['__mails'] = array();
function wp_mail( $to, $subject, $body ) { $GLOBALS['__mails'][] = array( $to, $subject, $body ); return true; }
function is_email( $e ) { return is_string( $e ) && filter_var( $e, FILTER_VALIDATE_EMAIL ) ? $e : false; }
function get_woocommerce_currency() { return 'USD'; }

class WC_XMR_HTTP {
	public static function get( $url, $args = array() ) {
		$GLOBALS['__http_log'][] = array( $url, $args['timeout'] ?? null );
		$next = array_shift( $GLOBALS['__http'] );
		return $next === null ? new WP_Error_stub( 'no_script', 'no scripted response' ) : $next;
	}
}
class WP_Error_stub {
	public $errors = array();
	public function __construct( $c, $m ) { $this->errors[ $c ] = $m; }
	public function get_error_message() { return reset( $this->errors ); }
}
function is_wp_error( $t ) { return $t instanceof WP_Error_stub; }
function wp_remote_retrieve_response_code( $r ) { return is_array( $r ) ? ( $r['response']['code'] ?? 0 ) : 0; }
function wp_remote_retrieve_body( $r ) { return is_array( $r ) ? ( $r['body'] ?? '' ) : ''; }

// Minimal gateway stand-in so wc_xmr_settings() can resolve settings.
$GLOBALS['__gw_settings'] = array();
class WC_Gateway_Monero {
	public $settings = array();
	public function __construct() { $this->settings = &$GLOBALS['__gw_settings']; }
}

require_once dirname( __DIR__, 2 ) . '\\wc-monero-gateway\\class-wc-xmr-poller.php';

$pass = 0; $fail = 0;
function ok( $name, $cond ) { global $pass, $fail; if ( $cond ) { $pass++; echo "PASS  {$name}\n"; } else { $fail++; echo "FAIL  {$name}\n"; } }
function reset_state() { $GLOBALS['__transients'] = $GLOBALS['__options'] = $GLOBALS['__scheduled'] = $GLOBALS['__alerts'] = $GLOBALS['__http'] = $GLOBALS['__http_log'] = $GLOBALS['__mails'] = array(); }
function http_ok( $body, $timeout = null ) { $r = array( 'response' => array( 'code' => 200 ), 'body' => $body ); if ( $timeout !== null ) $r['_timeout'] = $timeout; return $r; }

$settings = array( 'price_source' => 'coingecko' );

// ── A. manual source ────────────────────────────────────────────────
reset_state();
ok( 'manual source returns instantly', wc_xmr_get_rate( 'usd', array( 'price_source' => 'manual', 'manual_rate' => '123.45' ) ) === 123.45 );
ok( 'manual made zero HTTP calls', count( $GLOBALS['__http_log'] ) === 0 );

// ── B. cold start success ───────────────────────────────────────────
reset_state();
$GLOBALS['__http'][] = http_ok( '{"monero":{"usd":170.5}}' );
$r = wc_xmr_get_rate( 'USD', $settings );
ok( 'cold start returns live rate', $r === 170.5 );
ok( 'fresh transient stored', get_transient( 'wc_xmr_rate_usd' ) === 170.5 );
ok( 'stale transient stored', get_transient( 'wc_xmr_rate_stale_usd' ) === 170.5 );
ok( 'last-good option stored', ( get_option( 'wc_xmr_last_good_rate_usd' )['rate'] ?? 0 ) === 170.5 );
ok( 'coingecko called with bounded timeout', end( $GLOBALS['__http_log'] )[1] === 5 );

// ── C. fresh hit makes no HTTP calls ────────────────────────────────
$n = count( $GLOBALS['__http_log'] );
ok( 'fresh hit is instant/no HTTP', wc_xmr_get_rate( 'usd', $settings ) === 170.5 && count( $GLOBALS['__http_log'] ) === $n );

// ── D. expired fresh + stale present → instant serve + ONE bg schedule
delete_transient( 'wc_xmr_rate_usd' );
$n = count( $GLOBALS['__http_log'] );
$r = wc_xmr_get_rate( 'usd', $settings );
ok( 'stale served instantly', $r === 170.5 && count( $GLOBALS['__http_log'] ) === $n );
ok( 'background refresh scheduled', count( $GLOBALS['__scheduled'] ) > 0 );
wc_xmr_get_rate( 'usd', $settings );
$scheduled_count = 0;
foreach ( $GLOBALS['__scheduled'] as $s ) { if ( $s[0] === 'wc_xmr_rate_refresh_event' ) $scheduled_count++; }
ok( 'stampede lock prevents double scheduling', $scheduled_count === 1 );

// ── E. background cron event performs the refresh ───────────────────
delete_transient( 'wc_xmr_rate_usd' ); // force refresh to hit sources
$GLOBALS['__http'][] = new WP_Error_stub( 'http', 'coingecko down' );
$GLOBALS['__http'][] = http_ok( '{"result":{"XXMRZUSD":{"c":["171.25","2.0"]}}}' );
wc_xmr_rate_refresh_event_cb( 'usd' );
ok( 'cron refresh wrote fresh rate from kraken', get_transient( 'wc_xmr_rate_usd' ) === 171.25 );
ok( 'kraken fallback used with bounded timeout', end( $GLOBALS['__http_log'] )[1] === 5 );

// ── F. total failure → last-good fallback + deduped admin alert ─────
reset_state();
$GLOBALS['__options']['admin_email'] = 'admin@test.local';
update_option( 'wc_xmr_last_good_rate_usd', array( 'rate' => 169.0, 'at' => time() - 600 ) );
$GLOBALS['__http'][] = new WP_Error_stub( 't', 'down' );
$GLOBALS['__http'][] = new WP_Error_stub( 't', 'down' );
$r = wc_xmr_get_rate( 'usd', $settings );
$pf_mails = count( array_filter( $GLOBALS['__mails'], function ( $m ) { return strpos( $m[1], 'price_fail' ) !== false; } ) );
ok( 'last-known-good returned on total failure', $r === 169.0 );
ok( 'price_fail alerted exactly once', $pf_mails === 1 );
$GLOBALS['__http'][] = new WP_Error_stub( 't', 'down' );
$GLOBALS['__http'][] = new WP_Error_stub( 't', 'down' );
wc_xmr_get_rate( 'usd', $settings );
$pf_mails2 = count( array_filter( $GLOBALS['__mails'], function ( $m ) { return strpos( $m[1], 'price_fail' ) !== false; } ) );
ok( 'built-in dedupe prevents repeat emails', $pf_mails2 === 1 );

// ── G. total failure, nothing cached → 0 (checkout shows retry notice)
reset_state();
$GLOBALS['__http'][] = new WP_Error_stub( 't', 'down' );
$GLOBALS['__http'][] = new WP_Error_stub( 't', 'down' );
ok( 'hard failure returns 0', wc_xmr_get_rate( 'usd', $settings ) === 0 );

// ── H. warmer respects manual mode ──────────────────────────────────
reset_state();
$GLOBALS['__gw_settings'] = array( 'price_source' => 'manual', 'manual_rate' => '100' );
wc_xmr_rate_warm_cb();
ok( 'warmer skips manual source without HTTP', count( $GLOBALS['__http_log'] ) === 0 );

// ── I. warmer populates cache on live sources ───────────────────────
reset_state();
$GLOBALS['__gw_settings'] = array( 'price_source' => 'coingecko' );
$GLOBALS['__http'][] = http_ok( '{"monero":{"usd":172.75}}' );
wc_xmr_rate_warm_cb();
ok( 'warmer populated fresh transient', get_transient( 'wc_xmr_rate_usd' ) === 172.75 );
ok( 'warmer populated stale transient', get_transient( 'wc_xmr_rate_stale_usd' ) === 172.75 );

echo "\n" . ( 0 === $fail ? 'ALL GREEN' : 'FAILED' ) . " - {$pass} passed, {$fail} failed\n";
exit( 0 === $fail ? 0 : 1 );
