<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/* ============ Helpers ============ */

function wc_xmr_gw() {
    static $g = null;
    if ( $g !== null ) return $g;
    try {
        $g = new WC_Gateway_Monero();
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: WC_Gateway_Monero construction threw: ' . $e->getMessage() );
        $g = new stdClass();
        $g->settings = array();
    }
    return $g;
}
function wc_xmr_settings() {
    try {
        $gw = wc_xmr_gw();
        if ( isset( $gw->settings ) && is_array( $gw->settings ) ) return $gw->settings;
        error_log( 'WC XMR: wc_xmr_gw()->settings is not an array: ' . gettype( $gw->settings ?? null ) );
        return array();
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: wc_xmr_settings threw: ' . $e->getMessage() );
        return array();
    }
}

/**
 * Builds block explorer link(s) for a tx hash, IF the admin has configured
 * any. Supports multiple URL templates (one per line) so a single dead
 * explorer doesn't leave you with zero working links - same reasoning as
 * the price-source fallback chain. We still don't ship a hardcoded
 * default: public Monero explorers are mainnet-only almost across the
 * board, and the few testnet/stagenet ones that exist tend to be
 * single-maintainer instances that go down without notice - baking one in
 * would just be a different flavor of the "guessed onion address" problem.
 * Returns an array of ['label' => ..., 'url' => ...], possibly empty.
 */
function wc_xmr_explorer_links( $txid ) {
    if ( ! $txid ) return array();
    $s = wc_xmr_settings();
    $is_testnet = ( function_exists( 'wc_xmr_test_mode' ) && wc_xmr_test_mode() === 'testnet' );
    $raw = trim( $s[ $is_testnet ? 'test_explorer_url' : 'explorer_url' ] ?? '' );
    if ( ! $raw ) return array();

    $links = array();
    $templates = array_filter( array_map( 'trim', preg_split( '/\r\n|\r|\n/', $raw ) ) );
    $n = 1;
    foreach ( $templates as $tpl ) {
        if ( strpos( $tpl, '{txid}' ) === false ) continue;
        $links[] = array(
            'label' => count( $templates ) > 1 ? ( 'Explorer ' . $n ) : 'View on explorer',
            'url'   => str_replace( '{txid}', rawurlencode( $txid ), $tpl ),
        );
        $n++;
    }
    return $links;
}

// Back-compat shim: kept in case anything still calls the old singular name.
function wc_xmr_explorer_link( $txid ) {
    $links = wc_xmr_explorer_links( $txid );
    return $links ? $links[0]['url'] : '';
}

/**
 * PHP's ?? only falls back on null, not on an empty string. WooCommerce
 * number-input settings that were ever saved blank (or never explicitly
 * set) are stored as '' - and (int) '' / (float) '' silently becomes 0,
 * which for several of our settings (conf_complete, rl_max_pool_pct, etc.)
 * has a special "disabled"/"always trigger" meaning. That turns a blank
 * field into a silent behavior change instead of "use the default".
 * WC_Settings_API::get_option() already guards against this
 * ('' !== $value ? $value : $default) - this does the same for the places
 * we read the settings array directly instead of through get_option().
 */
function wc_xmr_num( $settings, $key, $default ) {
    $v = $settings[ $key ] ?? null;
    return ( $v === null || $v === '' || ! is_numeric( $v ) ) ? $default : $v;
}

/**
 * Cloudflare's published edge IP ranges (https://www.cloudflare.com/ips/).
 * Used to verify a request ACTUALLY passed through Cloudflare before we
 * trust CF-Connecting-IP - presence of CF headers alone proves nothing,
 * since an attacker who reaches your origin directly (e.g. your server IP
 * leaked or is reachable directly) can set CF-Connecting-IP and CF-Ray to
 * whatever they like. Filterable so you can refresh the list if Cloudflare
 * changes it, or add another CDN's ranges if you're behind something else.
 */
function wc_xmr_cf_ip_ranges() {
    $ranges = array(
        // IPv4
        '173.245.48.0/20','103.21.244.0/22','103.22.200.0/22','103.31.4.0/22',
        '141.101.64.0/18','108.162.192.0/18','190.93.240.0/20','188.114.96.0/20',
        '197.234.240.0/22','198.41.128.0/17','162.158.0.0/15','104.16.0.0/13',
        '104.24.0.0/14','172.64.0.0/13','131.0.72.0/22',
        // IPv6
        '2400:cb00::/32','2606:4700::/32','2803:f800::/32','2405:b500::/32',
        '2405:8100::/32','2a06:98c0::/29','2c0f:f248::/32',
    );
    return apply_filters( 'wc_xmr_cf_ip_ranges', $ranges );
}

function wc_xmr_ip_in_cidr( $ip, $cidr ) {
    if ( strpos( $cidr, '/' ) === false ) return $ip === $cidr;
    list( $subnet, $bits ) = explode( '/', $cidr );
    $bits = (int) $bits;

    if ( strpos( $ip, ':' ) !== false || strpos( $subnet, ':' ) !== false ) {
        // IPv6
        $ip_bin     = @inet_pton( $ip );
        $subnet_bin = @inet_pton( $subnet );
        if ( $ip_bin === false || $subnet_bin === false ) return false;
        $bytes = (int) ( $bits / 8 );
        $rem   = $bits % 8;
        if ( $bytes > 0 && substr( $ip_bin, 0, $bytes ) !== substr( $subnet_bin, 0, $bytes ) ) return false;
        if ( $rem === 0 ) return true;
        $mask = chr( ( 0xFF << ( 8 - $rem ) ) & 0xFF );
        return ( ( $ip_bin[ $bytes ] ?? "\0" ) & $mask ) === ( ( $subnet_bin[ $bytes ] ?? "\0" ) & $mask );
    }

    $ip_long     = ip2long( $ip );
    $subnet_long = ip2long( $subnet );
    if ( $ip_long === false || $subnet_long === false ) return false;
    $mask = -1 << ( 32 - $bits );
    return ( $ip_long & $mask ) === ( $subnet_long & $mask );
}

function wc_xmr_request_is_from_cloudflare() {
    $remote = $_SERVER['REMOTE_ADDR'] ?? '';
    if ( ! $remote ) return false;
    foreach ( wc_xmr_cf_ip_ranges() as $cidr ) {
        if ( wc_xmr_ip_in_cidr( $remote, $cidr ) ) return true;
    }
    return false;
}

function wc_xmr_ip_hash() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    $settings = function_exists( 'wc_xmr_settings' ) ? wc_xmr_settings() : array();
    $trust_cf = ( $settings['trust_cf_ip'] ?? 'no' ) === 'yes';

    if ( $trust_cf && ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && wc_xmr_request_is_from_cloudflare() ) {
        $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    return hash( 'sha256', $ip . '|' . wp_salt() );
}

function wc_xmr_wallets( $settings ) {
    if ( ! is_array( $settings ) ) {
        error_log( 'WC XMR: wc_xmr_wallets got non-array settings: ' . gettype( $settings ) );
        return array();
    }
    // Testnet test-mode transparently swaps in the test wallet config - every
    // other function (RPC calls, the poller, hybrid fallback) is unaware
    // this happened and just works against whatever wc_xmr_wallets() returns.
    $test_mode = 'off';
    try { $test_mode = function_exists( 'wc_xmr_test_mode' ) ? wc_xmr_test_mode() : 'off'; } catch ( Throwable $e ) { error_log( 'WC XMR: wc_xmr_test_mode() threw in wc_xmr_wallets: ' . $e->getMessage() ); }
    if ( $test_mode === 'testnet' ) {
        $json = trim( (string) ( $settings['test_wallets_json'] ?? '' ) );
        if ( ! $json ) return array();
        $arr = json_decode( $json, true );
        if ( json_last_error() !== JSON_ERROR_NONE ) {
            error_log( 'WC XMR: test_wallets_json is not valid JSON: ' . json_last_error_msg() );
            return array();
        }
        $arr = is_array( $arr ) ? $arr : array();
    } else {
        $json = trim( (string) ( $settings['wallets_json'] ?? '' ) );
        if ( ! $json ) return array();
        $arr = json_decode( $json, true );
        if ( json_last_error() !== JSON_ERROR_NONE ) {
            error_log( 'WC XMR: wallets_json is not valid JSON: ' . json_last_error_msg() );
            return array();
        }
        $arr = is_array( $arr ) ? $arr : array();
    }

    // Rewrite .onion wallet URLs through a configured tor2web gateway here,
    // once, centrally - every consumer of wc_xmr_wallets() (the poller,
    // checkout-time address creation, the dashboard widget) gets the
    // rewritten URL automatically rather than each needing to remember to
    // apply it themselves at their own construction site.
    foreach ( $arr as &$w ) {
        if ( isset( $w['url'] ) ) {
            $w['url'] = wc_xmr_apply_onion_gateway( $w['url'], $settings );
        }
    }
    unset( $w );

    return $arr;
}

/**
 * If a wallet's configured URL points at a .onion address, rewrite it to go
 * through a tor2web gateway (e.g. "xyz...abc.onion" -> "https://xyz...abc.onion.<gateway>/json_rpc"),
 * since shared/ordinary WordPress hosting has no Tor client of its own and
 * can't resolve .onion addresses directly. Non-onion URLs, and onion URLs
 * when no gateway is configured (e.g. the host itself runs a local Tor
 * SOCKS proxy already), are returned unchanged.
 *
 * Note: tor2web gateways serve on their own standard HTTPS port and expect
 * the onion service itself to be listening on its *virtual* port 80/443
 * (configured via Tor's HiddenServicePort mapping on the wallet-rpc side,
 * independent of whatever internal port wallet-rpc actually binds to) -
 * so any custom port in the original URL is intentionally dropped here.
 */
function wc_xmr_apply_onion_gateway( $url, $settings ) {
    if ( ! is_string( $url ) || $url === '' ) return $url;
    $host = wp_parse_url( $url, PHP_URL_HOST );
    if ( $host === false ) { error_log( 'WC XMR: wc_xmr_apply_onion_gateway got unparseable URL: ' . substr( $url, 0, 120 ) ); return $url; }
    if ( ! $host || stripos( $host, '.onion' ) === false ) {
        return $url;
    }
    $gateway = trim( (string) ( $settings['onion_gateway'] ?? '' ) );
    if ( $gateway === '' ) return $url;
    if ( ! preg_match( '/^[a-z0-9.-]+$/i', $gateway ) ) {
        error_log( 'WC XMR: onion_gateway looks invalid: ' . substr( $gateway, 0, 80 ) );
        return $url;
    }
    $path = wp_parse_url( $url, PHP_URL_PATH );
    if ( $path === false || ! is_string( $path ) || $path === '' ) $path = '/json_rpc';
    return 'https://' . $host . '.' . ltrim( $gateway, '.' ) . $path;
}

function wc_xmr_rpc_for( $wallet_id, $settings ) {
    foreach ( wc_xmr_wallets( $settings ) as $w ) {
        if ( ($w['id'] ?? '') === $wallet_id ) {
            // 60s, not the checkout-time default of 15s -- this runs from
            // WP-Cron in the background, so there's no customer staring at
            // a page waiting on it, and get_transfers can genuinely take a
            // while if wallet-rpc is mid-rescan after new blocks landed.
            return array( new WC_XMR_RPC( $w['url'], $w['user'] ?? '', $w['pass'] ?? '', 60 ), $w );
        }
    }
    return null;
}

/**
 * Is this address owned by the Monero Push companion (i.e. present in one of
 * its pushed-address pools)? Such reservations are detected via confirmation
 * pushes from the remote device, not by this plugin's RPC polling.
 *
 * Reads the companion's option directly with graceful absence: if the push
 * plugin is inactive the options simply don't exist and every address is
 * "not push-owned", restoring pure-RPC behavior. Result is cached per request
 * (one cron run) - the pools only change on device pushes.
 */
function wc_xmr_address_is_push_owned( $addr ) {
    static $set = null;
    if ( $set === null ) {
        $set = array();
        foreach ( array( 'mainnet', 'testnet', 'stagenet' ) as $net ) {
            $pool = get_option( 'wc_xmr_push_' . $net . '_addresses', array() );
            if ( ! is_array( $pool ) ) continue;
            foreach ( $pool as $e ) {
                $a = is_array( $e ) ? ( $e['address'] ?? '' ) : (string) $e;
                if ( $a !== '' ) $set[ $a ] = true;
            }
        }
    }
    return isset( $set[ $addr ] );
}

/* ============ Rate limit ============ */

/**
 * Fingerprint = hash(ip_hash + hashed user-agent). We hash the UA rather
 * than storing it raw - we only need it to distinguish clients, not to
 * retain it.
 */
function wc_xmr_fingerprint() {
    $ip = wc_xmr_ip_hash();
    $ua = hash( 'sha256', ( $_SERVER['HTTP_USER_AGENT'] ?? '' ) . wp_salt() );
    return hash( 'sha256', $ip . '|' . $ua );
}

/**
 * A short signature of "what is this checkout actually for" - product ids
 * + quantities + total. Lets us tell apart "same fingerprint, genuinely
 * different cart, spaced out" (fine) from "same fingerprint, same cart,
 * rapid repeat address requests" (looks like probing/exhaustion, not
 * shopping).
 */
function wc_xmr_cart_signature( $order ) {
    $items = array();
    foreach ( $order->get_items() as $item ) {
        $items[] = $item->get_product_id() . ':' . $item->get_quantity();
    }
    sort( $items );
    $sig = implode( ',', $items ) . '|' . number_format( (float) $order->get_total(), 2, '.', '' );
    return substr( md5( $sig ), 0, 32 );
}

/**
 * Behavioral rate limiter. Maintains a decaying suspicion score per
 * fingerprint (IP+UA), rather than a flat per-IP counter:
 *
 *  - Requests in rapid succession from the same fingerprint raise the
 *    score sharply (near-simultaneous = looks automated).
 *  - Repeating the exact same cart within a short window raises it
 *    further (legit shoppers checking out distinct carts don't do this).
 *  - Score decays with a half-life, and genuinely spaced-out, distinct-cart
 *    behavior is actively rewarded (score nudged down) - so a real,
 *    patient customer isn't penalized for requesting a couple of
 *    subaddresses over several minutes.
 *  - Below the throttle threshold: no friction at all.
 *  - Above the throttle threshold: soft spacing requirement (must wait a
 *    bit longer between requests, scaling with score) rather than an
 *    outright block.
 *  - Above the block threshold: temporary hard block, like before.
 *  - The effective "max concurrent unpaid reservations" allowance also
 *    shrinks as the score rises, instead of being a flat number for
 *    everyone.
 */
function wc_xmr_check_behavior( $fingerprint, $cart_hash, $settings ) {
    global $wpdb;
    if ( ! is_string( $fingerprint ) || $fingerprint === '' ) { error_log( 'WC XMR: wc_xmr_check_behavior got empty fingerprint.' ); return array( 'ok' => true, 'error' => null, 'score' => 0, 'max_concurrent' => 2 ); }
    if ( ! is_array( $settings ) ) $settings = array();
    $t = $wpdb->prefix . 'wc_xmr_behavior';

    $now_ts    = time();
    try { $now_mysql = current_time( 'mysql', 1 ); } catch ( Throwable $e ) { error_log( 'WC XMR: current_time threw in check_behavior: ' . $e->getMessage() ); $now_mysql = gmdate( 'Y-m-d H:i:s' ); }

    $block_thresh    = (float) wc_xmr_num( $settings, 'rl_score_block', 80 );
    $throttle_thresh = (float) wc_xmr_num( $settings, 'rl_score_throttle', 40 );
    $half_life_min   = max( 1, (float) wc_xmr_num( $settings, 'rl_score_decay_min', 15 ) );
    $block_minutes   = (int) wc_xmr_num( $settings, 'rl_block_minutes', 10 );
    $msg             = (string) ( $settings['rl_alt_message'] ?? 'Rate limited. Try later.' );
    $base_concurrent = max( 1, (int) wc_xmr_num( $settings, 'rl_max_concurrent', 2 ) );

    try { $row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$t} WHERE fingerprint = %s", $fingerprint ) ); } catch ( Throwable $e ) { error_log( 'WC XMR: get_row behavior threw: ' . $e->getMessage() ); $row = null; }
    if ( $wpdb->last_error ) { error_log( 'WC XMR: check_behavior get_row failed: ' . $wpdb->last_error ); $row = null; }

    if ( $row && $row->blocked_until && strtotime( $row->blocked_until ) > $now_ts ) {
        return array( 'ok' => false, 'error' => $msg, 'max_concurrent' => 0 );
    }

    $prev_score   = $row ? (float) $row->score : 0.0;
    $last_seen_ts = $row ? strtotime( $row->last_seen ) : 0;
    $elapsed      = $row ? max( 0, $now_ts - $last_seen_ts ) : PHP_INT_MAX;

    // Decay toward zero on its own half-life, so a fingerprint that's been
    // quiet for a while returns to baseline rather than staying flagged.
    $score = $prev_score * pow( 0.5, min( $elapsed, 86400 ) / ( $half_life_min * 60 ) );

    // Burst penalty, scaled by how close together requests are.
    if ( $elapsed < 2 )        $score += 50;
    elseif ( $elapsed < 10 )   $score += 25;
    elseif ( $elapsed < 60 )   $score += 8;
    elseif ( $elapsed < 300 )  $score += 2;
    // else: spaced out enough that we don't add anything.

    // Repeating the SAME cart within a short window is the real tell -
    // a genuine shopper requesting several distinct carts quickly is not
    // penalized this way, only re-requesting an unchanged one.
    if ( $row && $row->last_cart_hash === $cart_hash && $elapsed < 300 ) {
        $score += 20;
    }

    // Reward clearly-legitimate patient behavior.
    if ( $elapsed >= 300 && ( ! $row || $row->last_cart_hash !== $cart_hash ) ) {
        $score = max( 0, $score - 10 );
    }

    $score = max( 0.0, min( 100.0, $score ) );

    $ok = true; $err = null; $blocked_until = null;

    if ( $score >= $block_thresh ) {
        $ok  = false;
        $err = $msg;
        // Scale the block duration up a bit the further over threshold we are.
        $mins = $block_minutes * ( 1 + ( $score - $block_thresh ) / 50 );
        $blocked_until = gmdate( 'Y-m-d H:i:s', $now_ts + (int) round( $mins * 60 ) );
    } elseif ( $score >= $throttle_thresh ) {
        $required_gap = ( $score - $throttle_thresh + 1 ) * 3; // seconds; grows with score
        if ( $elapsed < $required_gap ) {
            $ok  = false;
            $err = __( 'Please wait a few seconds before requesting another Monero address.', 'wc-xmr' );
        }
    }

    try {
        $ok = $wpdb->replace( $t, array(
            'fingerprint'    => $fingerprint,
            'score'          => $score,
            'req_count'      => $row ? (int) $row->req_count + 1 : 1,
            'last_seen'      => $now_mysql,
            'last_cart_hash' => $cart_hash,
            'blocked_until'  => $blocked_until,
        ) );
        if ( $ok === false ) error_log( 'WC XMR: behavior replace failed: ' . $wpdb->last_error );
    } catch ( Throwable $e ) { error_log( 'WC XMR: behavior replace threw: ' . $e->getMessage() ); }

    $max_concurrent = max( 1, (int) floor( $base_concurrent * ( 1 - min( 0.9, $score / 100 ) ) ) );

    return array( 'ok' => $ok, 'error' => $err, 'score' => $score, 'max_concurrent' => $max_concurrent );
}

function wc_xmr_check_rate_limit( $order, $ip_hash, $settings ) {
    if ( ! $order instanceof WC_Order ) { error_log( 'WC XMR: check_rate_limit got non-order: ' . gettype( $order ) ); return true; }
    if ( ! is_string( $ip_hash ) || $ip_hash === '' ) { error_log( 'WC XMR: check_rate_limit got empty ip_hash.' ); return true; }
    if ( ! is_array( $settings ) ) $settings = array();
    try {
        if ( function_exists( 'wc_xmr_test_mode' ) && wc_xmr_test_mode() !== 'off' ) return true;
    } catch ( Throwable $e ) { error_log( 'WC XMR: wc_xmr_test_mode threw in check_rate_limit: ' . $e->getMessage() ); }
    global $wpdb;
    $res_t = $wpdb->prefix . 'wc_xmr_reservations';
    $max_h = max( 1, (int) wc_xmr_num( $settings, 'rl_max_per_hour', 5 ) );
    $block = max( 1, (int) wc_xmr_num( $settings, 'rl_block_minutes', 10 ) );
    $msg   = (string) ( $settings['rl_alt_message'] ?? 'Rate limited. Try later.' );
    try { $now = current_time( 'mysql', 1 ); } catch ( Throwable $e ) { $now = gmdate( 'Y-m-d H:i:s' ); error_log( 'WC XMR: current_time threw in check_rate_limit: ' . $e->getMessage() ); }

    // Behavioral check (fingerprint = IP + UA, scored on timing + cart repetition).
    $fingerprint = wc_xmr_fingerprint();
    $cart_hash   = wc_xmr_cart_signature( $order );
    $behavior    = wc_xmr_check_behavior( $fingerprint, $cart_hash, $settings );
    if ( ! $behavior['ok'] ) return $behavior['error'];

    // Concurrent unpaid reservations - the allowance itself shrinks as the
    // fingerprint's behavior score rises, instead of being one flat number.
    try {
        $concurrent = (int) $wpdb->get_var( $wpdb->prepare(
            "SELECT COUNT(*) FROM {$res_t} WHERE ip_hash = %s AND status IN ('reserved','detected')", $ip_hash
        ) );
        if ( $wpdb->last_error ) error_log( 'WC XMR: concurrent count failed: ' . $wpdb->last_error );
    } catch ( Throwable $e ) { error_log( 'WC XMR: concurrent get_var threw: ' . $e->getMessage() ); $concurrent = 0; }
    if ( $concurrent >= $behavior['max_concurrent'] ) return $msg;

    $rl_t = $wpdb->prefix . 'wc_xmr_ratelimit';
    try { $row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$rl_t} WHERE ip_hash = %s", $ip_hash ) ); } catch ( Throwable $e ) { error_log( 'WC XMR: ratelimit get_row threw: ' . $e->getMessage() ); $row = null; }
    if ( $wpdb->last_error ) { error_log( 'WC XMR: ratelimit get_row failed: ' . $wpdb->last_error ); $row = null; }
    if ( $row && ! empty( $row->blocked_until ) && strtotime( $row->blocked_until ) > time() ) return $msg;

    if ( ! $row || empty( $row->window_start ) || strtotime( $row->window_start ) < time() - 3600 ) {
        try {
            $ok = $wpdb->replace( $rl_t, array(
                'ip_hash' => $ip_hash, 'attempts' => 1, 'window_start' => $now, 'blocked_until' => null,
            ) );
            if ( $ok === false ) error_log( 'WC XMR: ratelimit replace (new window) failed: ' . $wpdb->last_error );
        } catch ( Throwable $e ) { error_log( 'WC XMR: ratelimit replace threw: ' . $e->getMessage() ); }
        return true;
    }
    if ( (int) $row->attempts + 1 > $max_h ) {
        try {
            $ok = $wpdb->update( $rl_t, array(
                'blocked_until' => gmdate( 'Y-m-d H:i:s', time() + $block * 60 ),
            ), array( 'ip_hash' => $ip_hash ) );
            if ( $ok === false ) error_log( 'WC XMR: ratelimit block update failed: ' . $wpdb->last_error );
        } catch ( Throwable $e ) { error_log( 'WC XMR: ratelimit block update threw: ' . $e->getMessage() ); }
        return $msg;
    }
    try {
        $ok = $wpdb->update( $rl_t, array( 'attempts' => (int) $row->attempts + 1 ), array( 'ip_hash' => $ip_hash ) );
        if ( $ok === false ) error_log( 'WC XMR: ratelimit attempt increment failed: ' . $wpdb->last_error );
    } catch ( Throwable $e ) { error_log( 'WC XMR: ratelimit update threw: ' . $e->getMessage() ); }
    return true;
}

/* ============ Price ============ */

/**
 * Checkout-facing rate lookup - designed to NEVER block on a network call
 * except on a true cold start (first checkout ever, or after a cache flush).
 *
 *   1. fresh transient (< 5 min old)  → returned instantly
 *   2. stale transient (< 6 h old)    → returned instantly, refresh scheduled
 *                                        in the background (once per minute)
 *   3. neither                        → one bounded synchronous refresh
 *
 * Before this, an expired transient made Place Order block through
 * CoinGecko (8 s) → Kraken (8 s) → optional fallback URL (12 s), i.e. up
 * to ~28 s of dead air roughly every fifth customer.
 */
function wc_xmr_get_rate( $currency, $settings ) {
    $currency = strtolower( $currency );
    $src = $settings['price_source'] ?? 'coingecko';
    if ( $src === 'manual' ) return (float) wc_xmr_num( $settings, 'manual_rate', 0 );

    $ck = 'wc_xmr_rate_' . $currency;
    $c  = get_transient( $ck );
    if ( $c !== false ) return (float) $c;

    // Serve stale immediately; the background refresh keeps the fresh
    // copy warm so subsequent requests converge back onto tier 1.
    $stale = get_transient( 'wc_xmr_rate_stale_' . $currency );
    if ( $stale !== false && (float) $stale > 0 ) {
        wc_xmr_rate_refresh_async( $currency );
        return (float) $stale;
    }

    // Cold start: bounded synchronous attempt (see timeout notes below).
    $res = wc_xmr_rate_refresh( $currency, $settings );
    if ( $res['rate'] > 0 ) return $res['rate'];

    $note = $res['blocked'] > 0
        ? ' (received HTTP 403/blocked responses - likely Cloudflare/exchange blocking your proxy or Tor exit IP)'
        : '';
    wc_xmr_alert( 'price_fail', 'All XMR price sources failed for ' . $currency . $note );

    // Last resort: fall back to the most recent rate we successfully
    // fetched, rather than failing checkout outright - but only if it's
    // not too stale, and we clearly flag it as such via the order meta
    // (rate_stale_warn already surfaces this to the customer).
    $last = get_option( 'wc_xmr_last_good_rate_' . $currency );
    if ( is_array( $last ) && ! empty( $last['rate'] ) && ( time() - (int) $last['at'] ) < 6 * HOUR_IN_SECONDS ) {
        wc_xmr_alert( 'price_stale_fallback', sprintf(
            'Using last-known-good XMR/%s rate from %d minutes ago - all live sources are currently unreachable.',
            strtoupper( $currency ), (int) round( ( time() - (int) $last['at'] ) / 60 )
        ) );
        return (float) $last['rate'];
    }

    return 0;
}

/**
 * Attempt every configured price source once and cache the result.
 * Silent by design - callers decide whether a failure is alert-worthy
 * (the cron warmer calls this every few minutes and must not spam).
 *
 * @return array ['status'=>'ok'|'fail', 'rate'=>float, 'blocked'=>int]
 */
function wc_xmr_rate_refresh( $currency, $settings ) {
    $src  = $settings['price_source'] ?? 'coingecko';
    $sources = $src === 'kraken'
        ? array( 'wc_xmr_price_kraken', 'wc_xmr_price_coingecko' )
        : array( 'wc_xmr_price_coingecko', 'wc_xmr_price_kraken' );

    $blocked_count = 0;
    foreach ( $sources as $fn ) {
        $r = call_user_func( $fn, $currency );
        if ( is_array( $r ) && ! empty( $r['blocked'] ) ) $blocked_count++;
        $val = is_array( $r ) ? (float) ( $r['rate'] ?? 0 ) : (float) $r;
        if ( $val > 0 ) {
            wc_xmr_rate_store( $currency, $val );
            return array( 'status' => 'ok', 'rate' => $val, 'blocked' => $blocked_count );
        }
    }

    // Configurable fallback - for use over Tor/proxy where CoinGecko/Kraken
    // 403 you (Cloudflare and similar exchange-side blocks on Tor exits are
    // common). We do NOT hardcode any third-party onion address here -
    // paste your own verified source (a self-run price relay, or an onion
    // mirror you've independently confirmed). See settings description.
    if ( ! empty( trim( $settings['price_fallback_url'] ?? '' ) ) ) {
        $r = wc_xmr_price_fallback_custom( $currency, $settings );
        if ( $r > 0 ) {
            wc_xmr_rate_store( $currency, $r );
            return array( 'status' => 'ok', 'rate' => $r, 'blocked' => $blocked_count );
        }
    }

    return array( 'status' => 'fail', 'rate' => 0, 'blocked' => $blocked_count );
}

/** Write the fresh + stale copies and the last-known-good option in one place. */
function wc_xmr_rate_store( $currency, $val ) {
    set_transient( 'wc_xmr_rate_' . $currency, $val, 5 * MINUTE_IN_SECONDS );
    set_transient( 'wc_xmr_rate_stale_' . $currency, $val, 6 * HOUR_IN_SECONDS );
    update_option( 'wc_xmr_last_good_rate_' . $currency, array( 'rate' => $val, 'at' => time() ), false );
}

/**
 * Queue exactly one background refresh per currency per minute (stampede
 * guard), so a burst of stale-serving checkouts doesn't schedule a burst
 * of cron events.
 */
function wc_xmr_rate_refresh_async( $currency ) {
    $lock = 'wc_xmr_rate_bg_lock_' . $currency;
    if ( get_transient( $lock ) !== false ) return;
    set_transient( $lock, 1, 60 );
    wp_schedule_single_event( time() + 1, 'wc_xmr_rate_refresh_event', array( $currency ) );
}

add_action( 'wc_xmr_rate_refresh_event', 'wc_xmr_rate_refresh_event_cb' );
/** Cron target for the stale-while-revalidate path. Silent unless debug-worthy. */
function wc_xmr_rate_refresh_event_cb( $currency ) {
    try {
        $res = wc_xmr_rate_refresh( strtolower( (string) $currency ), wc_xmr_settings() );
        if ( $res['status'] !== 'ok' ) {
            error_log( sprintf( 'WC XMR: background rate refresh failed for %s (%d blocked responses).', (string) $currency, (int) $res['blocked'] ) );
        }
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: background rate refresh threw: ' . $e->getMessage() );
    }
}

add_action( 'wc_xmr_rate_warm', 'wc_xmr_rate_warm_cb' );
/**
 * Recurring warmer (wc_xmr_5min schedule): keeps the fresh transient
 * permanently populated so checkouts almost always take the instant path.
 */
function wc_xmr_rate_warm_cb() {
    try {
        $s = wc_xmr_settings();
        if ( ! is_array( $s ) || ( $s['price_source'] ?? 'coingecko' ) === 'manual' ) return;
        $cur = function_exists( 'get_woocommerce_currency' ) ? strtolower( (string) get_woocommerce_currency() ) : 'usd';
        wc_xmr_rate_refresh( $cur, $s );
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: rate warm-up threw: ' . $e->getMessage() );
    }
}

add_action( 'init', 'wc_xmr_maybe_schedule_rate_warm' );
/** Self-healing scheduler - survives transient cache flushes and missed crons. */
function wc_xmr_maybe_schedule_rate_warm() {
    try {
        if ( wp_next_scheduled( 'wc_xmr_rate_warm' ) ) return;
        wp_schedule_event( time() + 120, 'wc_xmr_5min', 'wc_xmr_rate_warm' );
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: scheduling rate warm-up failed: ' . $e->getMessage() );
    }
}

/**
 * User-configured fallback price endpoint. Routed through WC_XMR_HTTP so it
 * benefits from the same proxy/Tor settings as everything else. Response is
 * expected to be JSON; the value is pulled out via a simple dot-path
 * (e.g. "monero.usd" for a CoinGecko-shaped response, or "price" for a flat
 * {"price": 123.45} response). {currency} in the URL is replaced with the
 * lowercase currency code.
 */
function wc_xmr_price_fallback_custom( $currency, $settings ) {
    $url = trim( str_replace( '{currency}', $currency, $settings['price_fallback_url'] ?? '' ) );
    if ( ! $url ) return 0;

    $r = WC_XMR_HTTP::get( $url, array( 'timeout' => 8 ) );
    if ( is_wp_error( $r ) ) {
        error_log( 'WC XMR: Fallback price endpoint failed: ' . $r->get_error_message() );
        return 0;
    }

    $code = wp_remote_retrieve_response_code( $r );
    if ( $code !== 200 ) { error_log( 'WC XMR: fallback price got HTTP ' . $code . ' from ' . $url ); return 0; }

    $raw_body = wp_remote_retrieve_body( $r );
    $body = json_decode( $raw_body, true );
    if ( json_last_error() !== JSON_ERROR_NONE ) { error_log( 'WC XMR: fallback price JSON decode failed: ' . json_last_error_msg() . ' - raw: ' . substr( $raw_body, 0, 200 ) ); return 0; }
    if ( ! is_array( $body ) ) { error_log( 'WC XMR: fallback price body is not array: ' . gettype( $body ) ); return 0; }

    $path = trim( (string) ( $settings['price_fallback_json_path'] ?? 'monero.' . $currency ) );
    if ( $path === '' ) $path = 'monero.' . $currency;
    $path = str_replace( '{currency}', $currency, $path );
    $val  = $body;
    foreach ( explode( '.', $path ) as $key ) {
        if ( $key === '' ) continue;
        if ( is_array( $val ) && array_key_exists( $key, $val ) ) {
            $val = $val[ $key ];
        } else {
            error_log( 'WC XMR: fallback price path "' . $path . '" missing key "' . $key . '".' );
            return 0;
        }
    }
    if ( ! is_numeric( $val ) ) { error_log( 'WC XMR: fallback price value not numeric at path "' . $path . '": ' . var_export( $val, true ) ); return 0; }
    return (float) $val;
}

function wc_xmr_price_coingecko( $c ) {
        $r = WC_XMR_HTTP::get( "https://api.coingecko.com/api/v3/simple/price?ids=monero&vs_currencies={$c}", array( 'timeout' => 5 ) );
    if ( is_wp_error( $r ) ) {
        error_log( 'WC XMR: CoinGecko price lookup failed: ' . $r->get_error_message() );
        return 0;
    }
    $code = wp_remote_retrieve_response_code( $r );
    if ( in_array( $code, array( 403, 429, 503 ), true ) ) return array( 'blocked' => true, 'rate' => 0 );
    $raw = wp_remote_retrieve_body( $r );
    $d = json_decode( $raw, true );
    if ( json_last_error() !== JSON_ERROR_NONE ) { error_log( 'WC XMR: CoinGecko JSON decode failed: ' . json_last_error_msg() ); return 0; }
    return (float) ( $d['monero'][ $c ] ?? 0 );
}
function wc_xmr_price_kraken( $c ) {
    $pair = 'XMR' . strtoupper( $c );
    $r = WC_XMR_HTTP::get( "https://api.kraken.com/0/public/Ticker?pair={$pair}", array( 'timeout' => 5 ) );
    if ( is_wp_error( $r ) ) {
        error_log( 'WC XMR: Kraken price lookup failed: ' . $r->get_error_message() );
        return 0;
    }
    $code = wp_remote_retrieve_response_code( $r );
    if ( in_array( $code, array( 403, 429, 503 ), true ) ) return array( 'blocked' => true, 'rate' => 0 );
    $raw = wp_remote_retrieve_body( $r );
    $d = json_decode( $raw, true );
    if ( json_last_error() !== JSON_ERROR_NONE ) { error_log( 'WC XMR: Kraken JSON decode failed: ' . json_last_error_msg() ); return 0; }
    if ( ! empty( $d['error'] ) ) { error_log( 'WC XMR: Kraken API error: ' . json_encode( $d['error'] ) ); return 0; }
    foreach ( ( $d['result'] ?? array() ) as $v ) return (float) ( $v['c'][0] ?? 0 );
    return 0;
}

/* ============ Address picking (hybrid) ============ */

/**
 * Build a native PHP Monero scanner instance from gateway settings.
 *
 * Uses the pure-PHP WC_Monero_Native_Scanner class (no Node.js, no WASM).
 * Scanner detects incoming payments using only the private view key and
 * a Monero daemon's JSON-RPC API.
 *
 * Attribution: scanner logic adapted from xmr-pay by SlowBearDigger.
 *
 * @param array $settings  Gateway settings
 * @return WC_Monero_Native_Scanner|null  Null if scanner is not configured
 */
function wc_xmr_native_scanner( $settings ) {
    static $scanner = null;
    static $scanner_inited = false;
    if ( $scanner_inited ) return $scanner;
    $scanner_inited = true;

    $daemon_url = trim( (string) ( $settings['scanner_daemon_url'] ?? '' ) );
    if ( ! $daemon_url ) {
        error_log( 'WC XMR: Native scanner: scanner_daemon_url is not configured.' );
        return null;
    }

    $log_level = (int) wc_xmr_num( $settings, 'scanner_log_level', 3 );

    // Detect network from test mode so the scanner generates correct
    // network-prefixed subaddresses (testnet subaddresses start with 'B',
    // mainnet with '8' - Cryptonote.php's SUBADDRESS netbytes handle this;
    // see generate_subaddress()). Without this, Cryptonote defaults to
    // mainnet and produces mainnet addresses even in testnet mode.
    $network = 'mainnet';
    try {
        if ( function_exists( 'wc_xmr_test_mode' ) && wc_xmr_test_mode() === 'testnet' ) {
            $network = 'testnet';
        }
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: wc_xmr_test_mode() threw in native_scanner: ' . $e->getMessage() );
    }

    $node_config = array(
        'url'      => $daemon_url,
        'auth'     => 'none',
        'username' => '',
        'password' => '',
    );

    try {
        $scanner = new WC_Monero_Native_Scanner( $node_config, $log_level, $network );
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: Native scanner construction threw: ' . $e->getMessage() );
        return null;
    }
    return $scanner;
}

/**
 * Extract scanner credentials (view key + primary address) from settings.
 * Handles decryption of the view key if it's stored encrypted.
 *
 * @param array $settings  Gateway settings
 * @return array  ['view_key'=>string, 'primary_address'=>string]
 */
function wc_xmr_scanner_credentials( $settings ) {
    $view_key = trim( (string) ( $settings['scanner_view_key'] ?? '' ) );
    $primary  = trim( (string) ( $settings['scanner_primary_address'] ?? '' ) );

    // Decrypt view key if it looks encrypted (not a 64-char hex string)
    if ( $view_key && ! preg_match( '/^[0-9a-fA-F]{64}$/', $view_key ) ) {
        $decrypted = '';
        if ( function_exists( 'wc_xmr_decrypt' ) ) {
            try { $decrypted = wc_xmr_decrypt( $view_key ); } catch ( Throwable $e ) { $decrypted = ''; }
        }
        if ( $decrypted ) $view_key = $decrypted;
    }

    return array(
        'view_key'        => $view_key,
        'primary_address' => $primary,
    );
}

/**
 * Schedule the next poll cycle ONLY if there are open (unpaid) orders.
 * Uses wp_schedule_single_event() instead of wp_schedule_event() so the
 * cron doesn't fire 24/7 on shared hosting when there's nothing to check.
 * Reschedules itself after each poll via wc_xmr_poll_cb().
 *
 * @param int $offset  Seconds from now to schedule the next poll (default: interval setting)
 */
function wc_xmr_schedule_poll_if_needed( $offset = 0 ) {
    global $wpdb;
    $t = $wpdb->prefix . 'wc_xmr_reservations';

    // Check if there are any open (reserved/detected) reservations
    try {
        $count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$t} WHERE status IN ('reserved','detected')" );
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: schedule_poll_if_needed count query threw: ' . $e->getMessage() );
        $count = 0;
    }

    if ( $count <= 0 ) {
        // No open orders - clear any pending single event so we don't fire needlessly
        $ts = wp_next_scheduled( 'wc_xmr_poll' );
        if ( $ts ) {
            wp_clear_scheduled_hook( 'wc_xmr_poll' );
        }
        return;
    }

    // Determine interval from settings (default 5 minutes)
    try { $s = wc_xmr_settings(); } catch ( Throwable $e ) { $s = array(); }
    $interval = max( 60, (int) wc_xmr_num( $s, 'poll_interval', 300 ) );
    if ( $offset <= 0 ) $offset = $interval;

    // Clear any existing scheduled event, then schedule a fresh single event
    $ts = wp_next_scheduled( 'wc_xmr_poll' );
    if ( $ts ) {
        wp_clear_scheduled_hook( 'wc_xmr_poll' );
    }
    wp_schedule_single_event( time() + $offset, 'wc_xmr_poll' );
}

/**
 * Pick an address using the configured primary address source, with an
 * optional fallback source for redundancy.
 *
 * The optional "Fallback address source" setting (address_failover) lets
 * the operator run two independent address sources and automatically
 * serve from the second when the first fails for a checkout (wallet-rpc
 * down, scanner misconfigured, push plugin unreachable, manual pool
 * exhausted, etc.). The fallback MUST be a different effective source
 * from the primary to take effect - otherwise it would just re-run the
 * same failing code path. Each fallback use raises an admin alert so the
 * operator knows the primary source is having trouble and can fix it;
 * the store keeps accepting payments in the meantime.
 *
 * @param array $settings  Gateway settings
 * @return array|WP_Error  ['address'=>..., 'wallet_id'=>..., ...] or error
 */
function wc_xmr_pick_address( $settings ) {
    $primary  = $settings['address_mode'] ?? 'manual';
    $fallback = $settings['address_failover'] ?? 'off';

    // Try the primary source first.
    $pick = wc_xmr_pick_address_from_mode( $primary, $settings );
    if ( ! is_wp_error( $pick ) ) {
        return $pick;
    }

    // Primary failed. If a fallback is configured and it's a different
    // effective source, try it.
    if ( $fallback === 'off' || $fallback === $primary ) {
        return $pick;
    }
    // 'hybrid' already internally falls back to manual, so pairing it
    // with a 'manual' fallback would just re-run the same code path.
    if ( in_array( 'hybrid', array( $primary, $fallback ), true ) && in_array( 'manual', array( $primary, $fallback ), true ) ) {
        return $pick;
    }

    wc_xmr_alert( 'address_failover', sprintf(
        'Primary address source "%s" failed (%s) - falling back to "%s". Fix the primary source to restore redundancy.',
        $primary, $pick->get_error_message(), $fallback
    ) );

    $fb = wc_xmr_pick_address_from_mode( $fallback, $settings );
    if ( ! is_wp_error( $fb ) ) {
        return $fb;
    }

    // Both failed - report both errors so the operator sees the whole picture.
    $msg = $pick->get_error_message();
    if ( $fb->get_error_message() ) {
        $msg .= ' Fallback also failed: ' . $fb->get_error_message();
    }
    return new WP_Error( 'no_address_all_sources', $msg );
}

/**
 * Pick an address from a single named source mode.
 *
 * @param string $mode      'manual' | 'auto' | 'hybrid' | 'scanner' | 'push'
 * @param array  $settings  Gateway settings
 * @return array|WP_Error  ['address'=>..., 'wallet_id'=>..., ...] or error
 */
function wc_xmr_pick_address_from_mode( $mode, $settings ) {
    // Scanner mode: use the view-only scanner (no wallet-rpc needed)
    if ( $mode === 'scanner' ) {
        return wc_xmr_pick_from_scanner( $settings );
    }

    if ( in_array( $mode, array( 'auto', 'hybrid' ), true ) ) {
        $pick = wc_xmr_pick_from_rpc( $settings );
        if ( ! is_wp_error( $pick ) ) return $pick;
        if ( $mode === 'auto' ) return $pick; // hard fail
        // hybrid → fall through to manual
        wc_xmr_alert( 'rpc_fail', 'RPC unavailable, falling back to manual pool: ' . $pick->get_error_message() );
    }

    // Push mode: use ONLY addresses pushed from a remote device via the
    // Monero Push Companion plugin. The manual-pasted pool (addresses /
    // test_addresses settings fields) is deliberately EXCLUDED here - push
    // mode means the operator has chosen to give a paired remote device
    // full control of what addresses are served.
    //
    // The push plugin hooks the 'wc_xmr_manual_address_pool' filter below,
    // adding its stored batch. Since wc_xmr_pick_from_manual() applies that
    // filter, we simply zero out the local pool first so nothing but
    // pushed addresses can be picked.
    if ( $mode === 'push' ) {
        $s = $settings;
        if ( ! is_array( $s ) ) $s = array();
        $is_testnet = ( function_exists( 'wc_xmr_test_mode' ) && wc_xmr_test_mode() === 'testnet' );
        $s[ $is_testnet ? 'test_addresses' : 'addresses' ] = '';
        return wc_xmr_pick_from_manual( $s );
    }

    return wc_xmr_pick_from_manual( $settings );
}

/**
 * Pick an address using the native PHP scanner (pure-PHP, no Node.js/WASM).
 *
 * Derives a unique subaddress for each order using the primary address's
 * view key. The subaddress index is derived from a monotonically increasing
 * counter stored in the reservations table.
 *
 * LEAST SECURE - the private view key is held in PHP memory during scanning.
 * MAY AFFECT SERVER PERFORMANCE - each poll scans recent blocks via daemon RPC.
 *
 * Attribution: scanner logic adapted from xmr-pay by SlowBearDigger.
 *
 * @param array $settings  Gateway settings
 * @return array|WP_Error  ['address'=>..., 'wallet_id'=>'scanner', 'account_index'=>0, 'subaddress_index'=>int]
 */
function wc_xmr_pick_from_scanner( $settings ) {
    $scanner = wc_xmr_native_scanner( $settings );
    if ( ! $scanner ) {
        return new WP_Error( 'scanner_not_configured', 'Native scanner is not configured (daemon URL missing).' );
    }

    $creds = wc_xmr_scanner_credentials( $settings );
    if ( empty( $creds['view_key'] ) || empty( $creds['primary_address'] ) ) {
        return new WP_Error( 'scanner_no_creds', 'Scanner view key or primary address is not configured.' );
    }

    // Fail LOUDLY at address-issuance time when the view key does not belong to
    // the primary address (xmr-pay's verify_keys check). Without this, scanning
    // runs forever and silently finds nothing - the worst kind of failure.
    try {
        $vk_check = $scanner->verify_keys( $creds['primary_address'], $creds['view_key'] );
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: scanner verify_keys threw at pick: ' . $e->getMessage() );
        $vk_check = array( 'address_valid' => false, 'key_match' => false );
    }
    if ( empty( $vk_check['key_match'] ) ) {
        wc_xmr_alert( 'scanner_key_mismatch', 'Scanner view key does NOT belong to the scanner primary address. Scanner mode cannot detect payments until the Private view key / Primary Monero address settings are corrected.' );
        return new WP_Error( 'scanner_key_mismatch', 'Scanner view key does not match the primary address.' );
    }

    // Determine the next subaddress index: find the highest used index
    // in the reservations table and increment by 1.
    global $wpdb;
    $t = $wpdb->prefix . 'wc_xmr_reservations';
    try {
        $max_idx = (int) $wpdb->get_var( "SELECT MAX(subaddress_index) FROM {$t} WHERE wallet_id = 'scanner'" );
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: scanner pick MAX(subaddress_index) threw: ' . $e->getMessage() );
        $max_idx = 0;
    }
    $next_idx = $max_idx + 1;

    // Derive the subaddress using the native scanner
    try {
        $result = $scanner->subaddress( 0, $next_idx, $creds['view_key'], $creds['primary_address'] );
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: scanner subaddress() threw: ' . $e->getMessage() );
        wc_xmr_alert( 'scanner_subaddress_fail', 'Native scanner failed to derive subaddress: ' . $e->getMessage() );
        return new WP_Error( 'scanner_subaddress_fail', $e->getMessage() );
    }

    if ( ! is_array( $result ) || empty( $result['address'] ) ) {
        wc_xmr_alert( 'scanner_subaddress_fail', 'Native scanner returned no address for subaddress index ' . $next_idx );
        return new WP_Error( 'scanner_no_addr', 'Scanner returned no address.' );
    }

    return array(
        'address'          => $result['address'],
        'wallet_id'        => 'scanner',
        'account_index'    => 0,
        'subaddress_index' => $next_idx,
    );
}

function wc_xmr_pick_from_rpc( $settings ) {
    if ( ! is_array( $settings ) ) return new WP_Error( 'no_wallets', 'Invalid settings.' );
    $wallets = wc_xmr_wallets( $settings );
    if ( ! $wallets ) return new WP_Error( 'no_wallets', 'No wallets configured.' );
    if ( empty( $wallets ) ) return new WP_Error( 'no_wallets', 'No wallets configured.' );

    try { $wallet = wc_xmr_choose_wallet( $wallets, $settings ); } catch ( Throwable $e ) { error_log( 'WC XMR: wc_xmr_choose_wallet threw: ' . $e->getMessage() ); return new WP_Error( 'choose_wallet_fail', 'Failed to choose wallet: ' . $e->getMessage() ); }
    if ( empty( $wallet['url'] ) ) return new WP_Error( 'no_url', 'Chosen wallet has no URL configured: ' . ( $wallet['id'] ?? '?' ) );
    list( $rpc, $w ) = array( new WC_XMR_RPC( $wallet['url'], $wallet['user'] ?? '', $wallet['pass'] ?? '', 15 ), $wallet );

    $acct = (int) ( $w['account'] ?? 0 );
    $res  = $rpc->call( 'create_address', array( 'account_index' => $acct, 'label' => 'wc-order-' . time() ) );
    if ( is_wp_error( $res ) ) { error_log( 'WC XMR: create_address failed for wallet ' . ( $w['id'] ?? '?' ) . ': [' . $res->get_error_code() . '] ' . $res->get_error_message() ); return $res; }

    $addr = $res['address'] ?? '';
    $idx  = (int) ( $res['address_index'] ?? 0 );
    if ( ! $addr ) return new WP_Error( 'no_addr', 'RPC returned no address.' );

    $idx = max( 0, $idx );
    // Warn if approaching lookahead (default 200)
    $warn_at = 200 - (int) wc_xmr_num( $settings, 'lookahead_warn', 20 );
    $warn_at = max( 1, $warn_at );
    if ( $idx >= $warn_at ) {
        wc_xmr_alert( 'lookahead', "Wallet {$w['id']} account {$acct} subaddress index reached {$idx}. Bump lookahead soon." );
    }

    return array(
        'address' => $addr, 'wallet_id' => $w['id'],
        'account_index' => $acct, 'subaddress_index' => $idx,
    );
}

function wc_xmr_choose_wallet( $wallets, $settings ) {
    $mode = $settings['wallet_rotation'] ?? 'round_robin';
    $weighted = array();
    foreach ( $wallets as $w ) {
        $wt = max( 1, (int) ( $w['weight'] ?? 1 ) );
        for ( $i = 0; $i < $wt; $i++ ) $weighted[] = $w;
    }
    if ( $mode === 'random' ) return $weighted[ array_rand( $weighted ) ];
    if ( $mode === 'least_used' ) {
        global $wpdb;
        $t = $wpdb->prefix . 'wc_xmr_reservations';
        $usage = $wpdb->get_results( "SELECT wallet_id, MAX(reserved_at) AS last FROM {$t} GROUP BY wallet_id", OBJECT_K );
        usort( $wallets, function( $a, $b ) use ( $usage ) {
            $la = $usage[ $a['id'] ]->last ?? '0'; $lb = $usage[ $b['id'] ]->last ?? '0';
            return strcmp( $la, $lb );
        });
        return $wallets[0];
    }
    // round_robin
    $key = 'wc_xmr_rr';
    $i = (int) get_option( $key, 0 );
    $pick = $weighted[ $i % count( $weighted ) ];
    update_option( $key, $i + 1, false );
    return $pick;
}

function wc_xmr_pick_from_manual( $settings ) {
    global $wpdb;
    $t = $wpdb->prefix . 'wc_xmr_reservations';

    // Same swap as wc_xmr_wallets() for the RPC path - without this, testnet
    // mode would silently keep serving your real production mainnet
    // addresses out of the manual pool whenever address_mode is manual or
    // hybrid, since this pool is a separate settings field from wallets_json.
    $is_testnet = ( function_exists( 'wc_xmr_test_mode' ) && wc_xmr_test_mode() === 'testnet' );
    $addr_key = $is_testnet ? 'test_addresses' : 'addresses';
    $network  = $is_testnet ? 'testnet' : 'mainnet';
    $raw = $settings[ $addr_key ] ?? '';
    $pool = array_filter( array_map( 'trim', preg_split( '/\r\n|\r|\n/', $raw ) ),
        function( $l ) use ( $network ) { return $l && $l[0] !== '#' && wc_xmr_valid_addr( $l, $network ); } );
    $pool = array_values( array_unique( $pool ) );

    // Lets a separate companion plugin (e.g. one that receives pushed
    // addresses from a device this server can't reach inbound) extend the
    // pool without either plugin needing to know the other's storage
    // format -- just this one filter contract. Each entry can be either a
    // plain address string, or ['address'=>..., 'exact_amount'=>float] for
    // addresses meant to be shared concurrently across multiple orders and
    // disambiguated by precise amount rather than by reservation-exclusivity.
    $pool = apply_filters( 'wc_xmr_manual_address_pool', $pool, $network, $settings );

    if ( ! $pool ) return new WP_Error( 'no_pool', 'No addresses available.' );

    $now = current_time( 'mysql', 1 );
    $reserved = $wpdb->get_col( $wpdb->prepare(
        "SELECT DISTINCT address FROM {$t} WHERE status IN ('reserved','detected') AND expires_at > %s", $now
    ) );

    // Global (site-wide, not per-IP) exhaustion guard: a per-IP rate limit does
    // nothing against an attacker spreading requests across many IPs to eat the
    // whole pool as a DoS. Refuse new manual-pool reservations once too much of
    // the pool is tied up, regardless of who's asking. Skipped during test mode
    // for the same reason rate limiting is skipped - this guard exists for
    // live-store abuse, not your own repeated test checkouts.
    $max_pool_pct = (float) wc_xmr_num( $settings, 'rl_max_pool_pct', 80 );
    $reserved_pct = count( $reserved ) / max( 1, count( $pool ) ) * 100;
    if ( $reserved_pct >= $max_pool_pct && ( ! function_exists( 'wc_xmr_test_mode' ) || wc_xmr_test_mode() === 'off' ) ) {
        wc_xmr_alert( 'pool_exhausted', sprintf(
            'XMR manual pool at %.0f%% concurrently reserved (cap %.0f%%) - likely high demand or an exhaustion attempt. New manual-pool checkouts are being declined until reservations free up.',
            $reserved_pct, $max_pool_pct
        ) );
        return new WP_Error( 'pool_exhausted', $settings['rl_alt_message'] ?? 'Too many pending Monero orders right now. Please use an alternate payment method or try again shortly.' );
    }

    // Build available list, handling both plain-string entries and
    // concurrent-reuse array entries (['address'=>..., 'exact_amount'=>float])
    // that the wc_xmr_manual_address_pool filter contract supports.
    $avail = array();
    foreach ( $pool as $entry ) {
        $addr = is_array( $entry ) ? ( $entry['address'] ?? '' ) : (string) $entry;
        if ( $addr !== '' && ! in_array( $addr, $reserved, true ) ) {
            $avail[] = $entry;
        }
    }

    // Pool health warn
    $pct = count( $avail ) / max( 1, count( $pool ) ) * 100;
    if ( $pct < (float) wc_xmr_num( $settings, 'pool_low_pct', 20 ) ) {
        wc_xmr_alert( 'pool_low', sprintf( 'XMR pool low: %d/%d free (%.0f%%). Add more addresses.',
            count( $avail ), count( $pool ), $pct ) );
    }
    if ( ! $avail ) return new WP_Error( 'no_pool', 'All addresses currently in use. Try again shortly.' );

    $last = $wpdb->get_results( "SELECT address, MAX(reserved_at) AS l FROM {$t} GROUP BY address", OBJECT_K );
    usort( $avail, function( $a, $b ) use ( $last ) {
        $a_addr = is_array( $a ) ? ( $a['address'] ?? '' ) : (string) $a;
        $b_addr = is_array( $b ) ? ( $b['address'] ?? '' ) : (string) $b;
        return strcmp( $last[ $a_addr ]->l ?? '0', $last[ $b_addr ]->l ?? '0' );
    });

    // Unwrap concurrent-reuse array entries to extract the address string
    $pick = $avail[0];
    $addr_str = is_array( $pick ) ? ( $pick['address'] ?? '' ) : (string) $pick;
    if ( ! $addr_str ) return new WP_Error( 'no_pool', 'No addresses available.' );

    // A push-sourced entry (see class-wc-xmr-push-endpoint.php process_addresses())
    // carries the address's real wallet_id/account_index/subaddress_index -
    // exactly what that same device will report on a later confirmation push
    // (process_confirmation()'s reservation lookup matches on wallet_id +
    // subaddress_index). Without this, every push-pool reservation was
    // being created with a 'manual'/0 placeholder that could never match a
    // real confirmation, so payments on these addresses were silently never
    // applied to the order. Entries without real coordinates (hand-typed
    // textarea addresses, or ones pushed before this field existed) still
    // fall back to the placeholder - there's nothing else to key on for those.
    if ( is_array( $pick )
        && isset( $pick['wallet_id'], $pick['account_index'], $pick['subaddress_index'] )
        && is_string( $pick['wallet_id'] ) && preg_match( '/^[A-Za-z0-9_\-]{1,64}$/', $pick['wallet_id'] )
        && is_int( $pick['account_index'] ) && $pick['account_index'] >= 0
        && is_int( $pick['subaddress_index'] ) && $pick['subaddress_index'] >= 0 ) {
        return array(
            'address' => $addr_str, 'wallet_id' => $pick['wallet_id'],
            'account_index' => $pick['account_index'], 'subaddress_index' => $pick['subaddress_index'],
        );
    }

    return array(
        'address' => $addr_str, 'wallet_id' => 'manual',
        'account_index' => 0, 'subaddress_index' => 0,
    );
}

function wc_xmr_valid_addr( $a, $network = 'mainnet' ) {
    if ( ! is_string( $a ) || $a === '' ) return false;
    if ( $network === 'mainnet' ) {
        return (bool) preg_match( '/^8[1-9A-HJ-NP-Za-km-z]{94}$/', $a );
    }
    return (bool) preg_match( '/^[1-9A-HJ-NP-Za-km-z]{95}$/', $a );
}

/* ============ Alerts ============ */

function wc_xmr_alert( $key, $msg ) {
    if ( ! is_string( $key ) || $key === '' ) { error_log( 'WC XMR: wc_xmr_alert called with empty key: ' . var_export( $key, true ) ); return; }
    if ( ! is_string( $msg ) ) $msg = (string) $msg;
    try { $log = get_option( 'wc_xmr_alerts', array() ); } catch ( Throwable $e ) { error_log( 'WC XMR: get_option wc_xmr_alerts threw: ' . $e->getMessage() ); $log = array(); }
    if ( ! is_array( $log ) ) $log = array();
    $now = time();
    if ( isset( $log[ $key ] ) && is_int( $log[ $key ] ) && ( $now - $log[ $key ] ) < 3600 ) {
        $log[ $key . '_msg' ] = $msg;
        try { update_option( 'wc_xmr_alerts', $log, false ); } catch ( Throwable $e ) { error_log( 'WC XMR: update_option wc_xmr_alerts threw (dedupe): ' . $e->getMessage() ); }
        return;
    }
    $log[ $key ] = $now; $log[ $key . '_msg' ] = $msg;
    try { update_option( 'wc_xmr_alerts', $log, false ); } catch ( Throwable $e ) { error_log( 'WC XMR: update_option wc_xmr_alerts threw: ' . $e->getMessage() ); }

    try { $s = wc_xmr_settings(); } catch ( Throwable $e ) { error_log( 'WC XMR: wc_xmr_settings threw in wc_xmr_alert: ' . $e->getMessage() ); $s = array(); }
    if ( ! is_array( $s ) ) $s = array();
    $to = ! empty( $s['alert_email'] ) ? (string) $s['alert_email'] : (string) get_option( 'admin_email' );
    if ( $to === '' || ! is_email( $to ) ) { error_log( 'WC XMR: alert email recipient invalid (' . $to . ') for key=' . $key ); return; }
    try {
        $sent = wp_mail( $to, '[WC XMR] ' . $key, $msg );
    } catch ( Throwable $e ) { error_log( 'WC XMR: wp_mail threw for key=' . $key . ': ' . $e->getMessage() ); $sent = false; }
    if ( ! $sent ) error_log( sprintf( 'WC XMR: Alert email failed to send (key=%s, to=%s).', $key, $to ) );
}

/* ============ Poller ============ */

add_action( 'wc_xmr_poll', 'wc_xmr_poll_cb' );
function wc_xmr_poll_cb() {
    global $wpdb;
    try { $s = wc_xmr_settings(); } catch ( Throwable $e ) { error_log( 'WC XMR: wc_xmr_settings threw in poll_cb: ' . $e->getMessage() ); return; }
    if ( ! is_array( $s ) ) { error_log( 'WC XMR: wc_xmr_settings returned non-array in poll_cb.' ); return; }
    // Was checking $s['wallets_json'] directly (production-only) and
    // bailing out if empty - which meant the ENTIRE poller silently never
    // ran in testnet mode unless production wallets were ALSO configured,
    // since wc_xmr_wallets() already correctly swaps to test_wallets_json
    // during testnet mode but this guard ran before that logic got a
    // chance to matter. wc_xmr_wallets() is test-mode-aware, so check
    // through it instead of the raw field.
    // Allow scanner-only setups: if no wallets are configured but scanner
    // mode is active, we still need to poll scanner reservations.
    $scanner_active = ( ( $s['address_mode'] ?? '' ) === 'scanner' );
    if ( empty( wc_xmr_wallets( $s ) ) && ! $scanner_active ) return;

    $t = $wpdb->prefix . 'wc_xmr_reservations';
    if ( empty( $t ) || ! is_string( $t ) ) { error_log( 'WC XMR: poll_cb prefix produced empty table name.' ); return; }
    $batch_limit = max( 1, (int) wc_xmr_num( $s, 'poller_batch_limit', 200 ) );
    try {
        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT * FROM {$t} WHERE status IN ('reserved','detected') AND wallet_id <> 'manual' AND wallet_id <> '__test_simulate__' LIMIT %d", $batch_limit
        ) );
        if ( $wpdb->last_error ) { error_log( 'WC XMR: poll get_results failed: ' . $wpdb->last_error ); return; }
    } catch ( Throwable $e ) { error_log( 'WC XMR: poll get_results threw: ' . $e->getMessage() ); return; }
    if ( $rows === null ) { error_log( 'WC XMR: poll get_results returned null.' ); return; }
    if ( empty( $rows ) ) return;

    if ( count( $rows ) >= $batch_limit ) {
        wc_xmr_alert( 'poller_batch_full', sprintf(
            'The XMR poller hit its batch limit (%d) this run - some pending orders may not get checked until the next 5-minute cycle. Consider raising "Poller batch limit" in settings if this happens often.',
            $batch_limit
        ) );
    }

    // Group by wallet
    $by_wallet = array();
    foreach ( $rows as $r ) $by_wallet[ $r->wallet_id ][] = $r;

    foreach ( $by_wallet as $wid => $rs ) {
        if ( ! is_string( $wid ) || $wid === '' ) { error_log( 'WC XMR: poll_cb skipping entry with empty wallet_id.' ); continue; }
        if ( ! is_array( $rs ) || empty( $rs ) ) continue;

        // ── Scanner wallet_id: use the native PHP scanner ──────────────
        if ( $wid === 'scanner' ) {
            wc_xmr_poll_scanner_batch( $rs, $s );
            continue;
        }

        try { $pair = wc_xmr_rpc_for( $wid, $s ); } catch ( Throwable $e ) { error_log( 'WC XMR: wc_xmr_rpc_for threw for wallet ' . $wid . ': ' . $e->getMessage() ); $pair = null; }
        if ( ! $pair ) {
            // Reservations whose address lives in a pushed-address pool are
            // covered by the Monero Push companion: their detections arrive
            // via confirmation pushes, not RPC polling. In a pure-push store
            // the device's wallet_id is deliberately absent from wallets_json,
            // and alerting "wallet missing" every cron cycle for orders that
            // ARE being detected was pure noise. Only warn about reservations
            // that neither source covers.
            $uncovered = array_values( array_filter( $rs, function( $r ) {
                return ! wc_xmr_address_is_push_owned( $r->address );
            } ) );
            if ( empty( $uncovered ) ) {
                continue; // fully push-covered - nothing this poller can or should do
            }
            wc_xmr_alert( 'poll_wallet_missing_' . $wid, sprintf(
                'Wallet "%1$s" has %2$d pending reservation(s) not covered by the push companion but no matching wallet configuration - these orders will not be polled until the wallet is re-added or the reservations are released.',
                $wid, count( $uncovered )
            ) );
            continue;
        }
        if ( ! is_array( $pair ) || count( $pair ) < 2 ) { error_log( 'WC XMR: wc_xmr_rpc_for returned malformed pair for wallet ' . $wid ); continue; }
        list( $rpc, $w ) = $pair;
        if ( ! $rpc instanceof WC_XMR_RPC || ! is_array( $w ) ) { error_log( 'WC XMR: poll pair has wrong types for wallet ' . $wid ); continue; }

        $acct = (int) ( $w['account'] ?? 0 );
        $indices = array();
        foreach ( $rs as $r ) { if ( isset( $r->subaddress_index ) ) $indices[] = (int) $r->subaddress_index; else error_log( 'WC XMR: poll row missing subaddress_index for order #' . ( $r->order_id ?? '?' ) ); }
        $indices = array_values( array_unique( array_filter( $indices, function( $v ) { return $v >= 0; } ) ) );
        if ( empty( $indices ) ) { error_log( 'WC XMR: no valid subaddress indices for wallet ' . $wid ); continue; }

        try {
            $res = $rpc->call( 'get_transfers', array(
                'in' => true, 'pool' => true,
                'account_index' => $acct,
                'subaddr_indices' => $indices,
            ) );
        } catch ( Throwable $e ) {
            error_log( 'WC XMR: get_transfers threw for wallet ' . $wid . ': ' . $e->getMessage() );
            $res = new WP_Error( 'xmr_rpc_throw', $e->getMessage() );
        }
        if ( is_wp_error( $res ) ) {
            wc_xmr_alert( 'poll_fail_' . $wid, 'Poll failed for wallet ' . $wid . ': ' . $res->get_error_message() );
            continue;
        }

        try { $height_res = $rpc->call( 'get_height' ); } catch ( Throwable $e ) { error_log( 'WC XMR: get_height threw for wallet ' . $wid . ': ' . $e->getMessage() ); $height_res = new WP_Error( 'xmr_height_throw', $e->getMessage() ); }
        if ( is_wp_error( $height_res ) ) {
            // Don't silently treat this as height=0 -- that forces every
            // confirmed tx below into the "can't determine confirmations"
            // branch, which would write a false 0 over an already-correct
            // higher confirmation count. Skip this wallet's whole batch for
            // this cycle instead; it'll be retried next poll.
            wc_xmr_alert( 'poll_height_fail_' . $wid, 'get_height failed for wallet ' . $wid . ': ' . $height_res->get_error_message() . ' - confirmation counts for this cycle were skipped rather than risk reporting a false regression.' );
            continue;
        }
        $height = 0;
        if ( is_array( $height_res ) ) $height = max( 0, (int) ( $height_res['height'] ?? 0 ) );
        else error_log( 'WC XMR: get_height returned non-array for wallet ' . $wid . ': ' . gettype( $height_res ) );

        $in_txs   = ( is_array( $res ) && isset( $res['in'] ) && is_array( $res['in'] ) ) ? $res['in'] : array();
        $pool_txs = ( is_array( $res ) && isset( $res['pool'] ) && is_array( $res['pool'] ) ) ? $res['pool'] : array();
        $txs = array_merge( $in_txs, $pool_txs );

        foreach ( $rs as $r ) {
            $matched = array_filter( $txs, function( $tx ) use ( $r, $acct ) {
                return ( $tx['subaddr_index']['major'] ?? -1 ) == $acct
                    && ( $tx['subaddr_index']['minor'] ?? -1 ) == (int) $r->subaddress_index;
            });
            if ( ! $matched ) continue;

            $total = 0; $hashes = array(); $min_conf = PHP_INT_MAX; $has_pool = false;
            foreach ( $matched as $tx ) {
                $total += ( $tx['amount'] ?? 0 ) / 1e12;
                if ( ! empty( $tx['txid'] ) ) $hashes[] = $tx['txid'];
                if ( isset( $tx['confirmations'] ) ) {
                    $min_conf = min( $min_conf, (int) $tx['confirmations'] );
                } elseif ( ! empty( $tx['height'] ) && $height ) {
                    $min_conf = min( $min_conf, max( 0, $height - (int) $tx['height'] ) );
                } else {
                    // A genuinely-unconfirmed pool entry: 0 conf is correct
                    // for THIS entry, but must not clobber a higher value
                    // already computed from a different matched tx above --
                    // min(), not a bare overwrite.
                    $has_pool = true; $min_conf = min( $min_conf, 0 );
                }
            }
            if ( $min_conf === PHP_INT_MAX ) $min_conf = 0;

            try {
                wc_xmr_update_order( $r, $total, $min_conf, $hashes, $s );
            } catch ( Throwable $e ) {
                wc_xmr_alert( 'poll_update_crash_' . $wid, sprintf(
                    'wc_xmr_update_order threw an exception for order #%d (wallet %s, subaddr %d): %s',
                    $r->order_id, $wid, $r->subaddress_index, $e->getMessage()
                ) );
            }
        }
    }

    // Reschedule the next poll cycle only if there are still open orders.
    // This avoids 24/7 daemon RPC calls on shared hosting when all orders
    // are paid or expired.
    wc_xmr_schedule_poll_if_needed();
}

/**
 * Poll a batch of scanner reservations using the native PHP scanner.
 *
 * For each reservation, derives the subaddress and checks for incoming
 * payments via the daemon's JSON-RPC API. Uses verify_payment() for
 * already-known tx hashes and scan_all() to discover new payments.
 *
 * LEAST SECURE - the private view key is held in PHP memory during scanning.
 * MAY AFFECT SERVER PERFORMANCE - each poll scans recent blocks via daemon RPC.
 *
 * Attribution: scanner logic adapted from xmr-pay by SlowBearDigger.
 *
 * @param array $rs  Reservation rows from the DB
 * @param array $s   Gateway settings
 */
function wc_xmr_poll_scanner_batch( $rs, $s ) {
    $scanner = wc_xmr_native_scanner( $s );
    if ( ! $scanner ) {
        wc_xmr_alert( 'scanner_poll_no_scanner', 'Scanner poller cannot run: native scanner is not configured.' );
        return;
    }

    $creds = wc_xmr_scanner_credentials( $s );
    if ( empty( $creds['view_key'] ) || empty( $creds['primary_address'] ) ) {
        wc_xmr_alert( 'scanner_poll_no_creds', 'Scanner poller cannot run: view key or primary address is empty.' );
        return;
    }

    $view_key = $creds['view_key'];
    $primary  = $creds['primary_address'];

    // Once per cycle: credential + network sanity (ported concepts from xmr-pay).
    // Wrong view key = silent nothing; wrong network = addresses customers'
    // wallets refuse. Both used to fail with zero admin-visible signals.
    static $sanity_done = false;
    if ( ! $sanity_done ) {
        $sanity_done = true;
        try {
            $vk_check = $scanner->verify_keys( $primary, $view_key );
            if ( empty( $vk_check['key_match'] ) ) {
                wc_xmr_alert( 'scanner_creds_mismatch', 'Scanner poll: the configured private view key does NOT belong to the primary address - no payment can ever be detected. Fix the scanner settings.' );
                return;
            }
        } catch ( Throwable $e ) {
            error_log( 'WC XMR: scanner verify_keys threw in poll batch: ' . $e->getMessage() );
        }
        try {
            $net     = $scanner->get_network();
            $expect  = array(
                'mainnet'  => array( '12', '13', '2a' ),
                'stagenet' => array( '18', '19', '24' ),
                'testnet'  => array( '35', '36', '3f' ),
            );
            $cn_chk  = new \MoneroIntegrations\MoneroPhp\Cryptonote( $net );
            $dec_chk = $cn_chk->decode_address( $primary );
            $nbyte   = strtolower( (string) ( $dec_chk['networkByte'] ?? '' ) );
            if ( '' !== $nbyte && ! in_array( $nbyte, $expect[ $net ] ?? array(), true ) ) {
                wc_xmr_alert( 'scanner_network_mismatch', sprintf( 'Scanner network mismatch: test mode says "%s" but the primary address is from a different network (prefix byte %s). Customers may be shown addresses their wallet refuses to pay; detection itself still works because it keys on the address keys, not the prefix.', $net, $nbyte ) );
            }
        } catch ( Throwable $e ) {
            error_log( 'WC XMR: scanner network check threw in poll batch: ' . $e->getMessage() );
        }
    }

    // Get current daemon height - non-fatal: if the daemon is temporarily
    // unreachable, log a warning and skip this cycle. The poller will retry
    // on the next scheduled tick.
    $tip = $scanner->get_height();
    if ( null === $tip ) {
        error_log( 'WC XMR: scanner poll cannot get daemon height - daemon may be temporarily unreachable. Skipping this cycle, will retry next tick.' );
        return;
    }

    // scanner_restore_height is now a fallback floor for legacy orders that
    // have checkout_height=0 (orders placed before this feature existed).
    $restore_height = (int) wc_xmr_num( $s, 'scanner_restore_height', 0 );
    $min_conf       = (int) wc_xmr_num( $s, 'conf_processing', 1 );

    global $wpdb;
    $table = $wpdb->prefix . 'wc_xmr_reservations';

    foreach ( $rs as $r ) {
        if ( ! is_object( $r ) || ! isset( $r->order_id ) ) {
            error_log( 'WC XMR: scanner poll skipping invalid reservation row.' );
            continue;
        }

        $subaddr_idx = isset( $r->subaddress_index ) ? (int) $r->subaddress_index : 0;
        $expected    = isset( $r->amount_xmr ) ? (float) $r->amount_xmr : 0.0;

        // Per-order scan checkpoint: start from the block height recorded at
        // checkout (or the last scanned-to height from a previous cycle).
        // Falls back to scanner_restore_height for legacy orders (checkout_height=0).
        $checkout_height = isset( $r->checkout_height ) ? (int) $r->checkout_height : 0;
        if ( $checkout_height > 0 ) {
            $scan_from = $checkout_height;
        } else {
            // Legacy order: use scanner_restore_height as floor, or tip-30 as window
            $scan_from = max( $restore_height, max( 0, $tip - 30 ) );
        }

        // Derive the subaddress for this order
        try {
            $sub = $scanner->subaddress( 0, $subaddr_idx, $view_key, $primary );
        } catch ( Throwable $e ) {
            error_log( 'WC XMR: scanner poll subaddress() threw for order #' . $r->order_id . ': ' . $e->getMessage() );
            continue;
        }
        if ( ! is_array( $sub ) || empty( $sub['address'] ) ) {
            error_log( 'WC XMR: scanner poll could not derive subaddress for order #' . $r->order_id );
            continue;
        }
        $order_address = $sub['address'];

        // Check for existing tx hashes first (verify_payment for each known txid)
        $existing_hashes = array();
        if ( ! empty( $r->tx_hashes ) ) {
            $existing_hashes = array_filter( explode( ',', $r->tx_hashes ) );
        }

        $total_received = 0.0;
        $confs          = 0;
        $found_hashes   = array();

        foreach ( $existing_hashes as $txid ) {
            $txid = trim( $txid );
            if ( ! $txid ) continue;
            try {
                $vp = $scanner->verify_payment( $txid, $order_address, $view_key, array( 'tip' => $tip ) );
            } catch ( Throwable $e ) {
                error_log( 'WC XMR: scanner poll verify_payment threw for txid=' . $txid . ': ' . $e->getMessage() );
                continue;
            }
            if ( is_array( $vp ) && ! empty( $vp['found'] ) ) {
                $amount_atomic = (int) $vp['amount_atomic'];
                $total_received += $amount_atomic / 1e12;
                $confs = max( $confs, (int) ( $vp['confirmations'] ?? 0 ) );
                $found_hashes[] = $txid;
            }
        }

        // If no existing txs found, or to discover new payments, scan from
        // the per-order checkpoint to the current tip.
        if ( $confs < $min_conf || $total_received < $expected ) {
            try {
                $scan_result = $scanner->scan_all(
                    $order_address,
                    $view_key,
                    $scan_from,
                    $tip,
                    array(
                        'max_blocks'          => 30,
                        'require_commitment'  => true,
                        'tip'                 => $tip,
                    )
                );
            } catch ( Throwable $e ) {
                error_log( 'WC XMR: scanner poll scan_all() threw for order #' . $r->order_id . ': ' . $e->getMessage() );
                $scan_result = array( 'matches' => array(), 'scanned_to' => $scan_from );
            }

            if ( is_array( $scan_result ) && ! empty( $scan_result['matches'] ) ) {
                foreach ( $scan_result['matches'] as $match ) {
                    $amount_atomic = (int) $match['amount_atomic'];
                    $total_received += $amount_atomic / 1e12;
                    $confs = max( $confs, (int) ( $match['confirmations'] ?? 0 ) );
                    if ( ! empty( $match['txid'] ) ) {
                        $found_hashes[] = $match['txid'];
                    }
                }
            }
        }

        // Advance the per-order checkpoint to the actual scanned-to height
        // (or the tip if no scan was needed). Using scanned_to prevents
        // permanent gaps when scan_all is limited by max_blocks or throws.
        if ( isset( $scan_result['scanned_to'] ) ) {
            $new_checkpoint = max( (int) $scan_result['scanned_to'], $scan_from );
        } else {
            // scan_all was not called (order already fully paid/confirmed)
            $new_checkpoint = $tip;
        }
        $wpdb->query( $wpdb->prepare(
            "UPDATE {$table} SET checkout_height = %d WHERE id = %d",
            $new_checkpoint, $r->id
        ) );

        // Deduplicate tx hashes - verify_payment and scan_all may both
        // report the same txid, and duplicates would accumulate across cycles.
        $found_hashes = array_values( array_unique( $found_hashes ) );

        // Only update if there's a change
        $prev_recv = isset( $r->received_xmr ) ? (float) $r->received_xmr : 0.0;
        $prev_conf = isset( $r->confirmations ) ? (int) $r->confirmations : 0;
        if ( abs( $total_received - $prev_recv ) < 1e-12 && $confs === $prev_conf ) continue;

        try {
            wc_xmr_update_order( $r, $total_received, $confs, $found_hashes, $s );
        } catch ( Throwable $e ) {
            error_log( 'WC XMR: scanner poll update_order threw for order #' . $r->order_id . ': ' . $e->getMessage() );
        }
    }
}

function wc_xmr_update_order( $r, $received, $confs, $hashes, $s ) {
    if ( ! is_object( $r ) || ! isset( $r->order_id, $r->id ) ) { error_log( 'WC XMR: wc_xmr_update_order got invalid reservation object.' ); return; }
    if ( ! is_array( $hashes ) ) $hashes = array();
    if ( ! is_array( $s ) ) $s = array();
    $received = (float) $received;
    $confs    = max( 0, (int) $confs );
    global $wpdb;
    $t = $wpdb->prefix . 'wc_xmr_reservations';
    try { $order = wc_get_order( $r->order_id ); } catch ( Throwable $e ) { error_log( 'WC XMR: wc_get_order threw in update_order for #' . $r->order_id . ': ' . $e->getMessage() ); return; }
    if ( ! $order ) {
        error_log( sprintf( 'WC XMR: wc_xmr_update_order - order #%d not found, cannot update.', $r->order_id ) );
        return;
    }

    $prev_recv = isset( $r->received_xmr ) ? (float) $r->received_xmr : 0.0;
    $prev_conf = isset( $r->confirmations ) ? (int) $r->confirmations : 0;
    if ( abs( $received - $prev_recv ) < 1e-12 && (int) $confs === $prev_conf ) return;

    try { $first_seen = ! empty( $r->first_seen_at ) ? $r->first_seen_at : current_time( 'mysql', 1 ); } catch ( Throwable $e ) { $first_seen = gmdate( 'Y-m-d H:i:s' ); }
	$update_data = array(
		'received_xmr' => $received, 'confirmations' => $confs,
		'tx_hashes' => implode( ',', array_filter( array_map( 'strval', $hashes ) ) ),
		'first_seen_at' => $first_seen,
	);
	if ( isset( $r->status ) && $r->status === 'reserved' ) $update_data['status'] = 'detected';
	try {
		$affected = $wpdb->update( $t, $update_data, array( 'id' => (int) $r->id ) );
		if ( $affected === false ) error_log( sprintf( 'WC XMR: DB update failed for reservation id=%d: %s', $r->id, $wpdb->last_error ) );
	} catch ( Throwable $e ) { error_log( 'WC XMR: DB update threw for reservation id=' . $r->id . ': ' . $e->getMessage() ); }

    try {
        $order->update_meta_data( '_xmr_received', $received );
        $order->update_meta_data( '_xmr_confirmations', $confs );
        $order->update_meta_data( '_xmr_tx_hashes', implode( ',', array_filter( array_map( 'strval', $hashes ) ) ) );
        $order->save();
    } catch ( Throwable $e ) { error_log( 'WC XMR: order save threw for #' . $r->order_id . ': ' . $e->getMessage() ); }

    $min_ok  = isset( $r->min_amount_xmr ) ? (float) $r->min_amount_xmr : 0.0;
    $conf_p  = max( 0, (int) wc_xmr_num( $s, 'conf_processing', 1 ) );
    $conf_c  = max( 0, (int) wc_xmr_num( $s, 'conf_complete', 10 ) );

    if ( $prev_recv == 0 && $received > 0 ) {
        try { $order->add_order_note( sprintf( 'XMR payment detected: %s XMR (%d conf). Tx: %s', $received, $confs, implode( ',', array_filter( array_map( 'strval', $hashes ) ) ) ) ); } catch ( Throwable $e ) { error_log( 'WC XMR: add_order_note threw: ' . $e->getMessage() ); }
    }

    if ( $min_ok > 0 && $received + 1e-12 < $min_ok ) {
        // Note only when the shortfall amount itself changed - confirmation
        // ticks on an already-seen shortfall would otherwise spam a note
        // into the order every poll cycle.
        if ( $prev_recv + 1e-12 < $min_ok ) {
            try { $order->add_order_note( sprintf( 'Underpayment: received %s, expected min %s. Manual review needed.', $received, $min_ok ) ); } catch ( Throwable $e ) { error_log( 'WC XMR: add_order_note (underpayment) threw: ' . $e->getMessage() ); }
        }
        return;
    }

    try { $order_status = $order->get_status(); } catch ( Throwable $e ) { error_log( 'WC XMR: get_status threw for #' . $r->order_id . ': ' . $e->getMessage() ); $order_status = ''; }
    if ( $confs >= $conf_p && $order_status === 'on-hold' ) {
        try { $paid = $order->payment_complete( implode( ',', array_filter( array_map( 'strval', $hashes ) ) ) ); } catch ( Throwable $e ) { error_log( 'WC XMR: payment_complete threw for #' . $r->order_id . ': ' . $e->getMessage() ); $paid = false; }
        if ( ! empty( $paid ) ) {
            try { $order->add_order_note( "Auto-advanced to Processing at {$confs} confirmations." ); } catch ( Throwable $e ) { error_log( 'WC XMR: add_order_note threw: ' . $e->getMessage() ); }
            try { $wpdb->update( $t, array( 'status' => 'paid' ), array( 'id' => (int) $r->id ) ); if ( $wpdb->last_error ) error_log( 'WC XMR: status→paid update failed for id=' . $r->id . ': ' . $wpdb->last_error ); } catch ( Throwable $e ) { error_log( 'WC XMR: status→paid update threw: ' . $e->getMessage() ); }
        } else {
            try { $order->add_order_note( sprintf( 'XMR payment reached %d confirmations but payment_complete() returned false - order may need manual advancement.', $confs ) ); } catch ( Throwable $e ) { error_log( 'WC XMR: add_order_note (payment_complete false) threw: ' . $e->getMessage() ); }
            wc_xmr_alert( 'payment_complete_fail', sprintf( 'Order #%d: payment_complete() returned false at %d confirmations. The order may need manual advancement via "Mark XMR paid".', $r->order_id, $confs ) );
        }
    }
    try { $order_status2 = $order->get_status(); } catch ( Throwable $e ) { $order_status2 = $order_status; }
    if ( $conf_c > 0 && $confs >= $conf_c && $order_status2 === 'processing' ) {
        try { $order->update_status( 'completed', "Auto-completed at {$confs} confirmations." ); } catch ( Throwable $e ) { error_log( 'WC XMR: update_status completed threw for #' . $r->order_id . ': ' . $e->getMessage() ); }
    }
}

/* ============ Admin: RPC test + dashboard widget ============ */

add_action( 'wp_dashboard_setup', function() {
    if ( current_user_can( 'manage_woocommerce' ) ) {
        wp_add_dashboard_widget( 'wc_xmr_status', 'Monero Gateway', 'wc_xmr_dashboard' );
    }
});
function wc_xmr_dashboard() {
    try { $s = wc_xmr_settings(); } catch ( Throwable $e ) { error_log( 'WC XMR: dashboard wc_xmr_settings threw: ' . $e->getMessage() ); $s = array(); }
    if ( ! is_array( $s ) ) $s = array();
    global $wpdb;
    $t = $wpdb->prefix . 'wc_xmr_reservations';
    try {
        $active = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$t} WHERE status IN ('reserved','detected')" );
        if ( $wpdb->last_error ) { error_log( 'WC XMR: dashboard active count failed: ' . $wpdb->last_error ); $active = 0; }
        $detected = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$t} WHERE status = 'detected'" );
        if ( $wpdb->last_error ) { error_log( 'WC XMR: dashboard detected count failed: ' . $wpdb->last_error ); $detected = 0; }
    } catch ( Throwable $e ) { error_log( 'WC XMR: dashboard counts threw: ' . $e->getMessage() ); $active = 0; $detected = 0; }
    echo "<p><strong>Active reservations:</strong> {$active} ({$detected} with tx detected)</p>";

    try { $wallets = wc_xmr_wallets( $s ); } catch ( Throwable $e ) { error_log( 'WC XMR: dashboard wc_xmr_wallets threw: ' . $e->getMessage() ); $wallets = array(); }
    if ( ! is_array( $wallets ) ) $wallets = array();
    foreach ( $wallets as $w ) {
        if ( ! is_array( $w ) || empty( $w['url'] ) ) continue;
        $ck = 'wc_xmr_rpc_ver_' . md5( (string) $w['url'] );
        try { $cached = get_transient( $ck ); } catch ( Throwable $e ) { error_log( 'WC XMR: get_transient rpc ver threw: ' . $e->getMessage() ); $cached = false; }
        if ( $cached === false ) {
            try {
                $rpc = new WC_XMR_RPC( $w['url'], $w['user'] ?? '', $w['pass'] ?? '' );
                $r = $rpc->call( 'get_version' );
            } catch ( Throwable $e ) { error_log( 'WC XMR: RPC get_version threw for ' . ( $w['id'] ?? '?' ) . ': ' . $e->getMessage() ); $r = new WP_Error( 'xmr_rpc_throw', $e->getMessage() ); }
            $cached = is_wp_error( $r ) ? '[FAIL] ' . $r->get_error_message() : '[OK] OK (v' . ( is_array( $r ) ? ( $r['version'] ?? '?' ) : '?' ) . ')';
            try { set_transient( $ck, $cached, 5 * MINUTE_IN_SECONDS ); } catch ( Throwable $e ) { error_log( 'WC XMR: set_transient rpc ver threw: ' . $e->getMessage() ); }
        }
        echo '<p><strong>' . esc_html( $w['label'] ?? $w['id'] ?? '?' ) . ':</strong> ' . esc_html( $cached ) . '</p>';
    }

    // Proxy exit-IP check (cached 5 min so the widget doesn't hammer the check endpoint on every load).
    if ( ( $s['proxy_enabled'] ?? 'no' ) === 'yes' ) {
        $ck = 'wc_xmr_proxy_check';
        try { $info = get_transient( $ck ); } catch ( Throwable $e ) { error_log( 'WC XMR: get_transient proxy_check threw: ' . $e->getMessage() ); $info = false; }
        if ( $info === false ) {
            try { $info = WC_XMR_HTTP::check_exit( $s ); } catch ( Throwable $e ) { error_log( 'WC XMR: check_exit threw: ' . $e->getMessage() ); $info = new WP_Error( 'xmr_proxy_throw', $e->getMessage() ); }
            try { set_transient( $ck, $info, 5 * MINUTE_IN_SECONDS ); } catch ( Throwable $e ) { error_log( 'WC XMR: set_transient proxy_check threw: ' . $e->getMessage() ); }
        }
        echo '<hr><p><strong>Proxy exit check:</strong> ';
        if ( is_wp_error( $info ) ) {
            echo '[FAIL] ' . esc_html( $info->get_error_message() );
        } elseif ( ! is_array( $info ) ) {
            echo '[FAIL] Unexpected proxy check result type: ' . esc_html( gettype( $info ) );
        } else {
            $ip    = $info['ip'] ?? '?';
            $is_mv = ! empty( $info['mullvad_exit_ip'] );
            echo esc_html( $ip ) . ' - ' . ( $is_mv ? '[OK] confirmed Mullvad exit' : 'not a recognized Mullvad exit (fine if using a different proxy)' );
        }
        echo '</p>';
    }

    try { $alerts = get_option( 'wc_xmr_alerts', array() ); } catch ( Throwable $e ) { error_log( 'WC XMR: get_option wc_xmr_alerts threw in dashboard: ' . $e->getMessage() ); $alerts = array(); }
    if ( ! is_array( $alerts ) ) $alerts = array();
    // Respect x-dismissals from the admin notices so the widget agrees with
    // what the operator chose to hide.
    $dismissed = wc_xmr_alerts_dismissed();
    $recent = array_filter( $alerts, function( $v, $k ) use ( $dismissed ) {
        if ( ! is_int( $v ) || $v <= time() - 86400 ) return false;
        return !( isset( $dismissed[ $k ] ) && is_int( $dismissed[ $k ] ) && $dismissed[ $k ] >= $v );
    }, ARRAY_FILTER_USE_BOTH );
    if ( $recent ) {
        echo '<p style="color:#c00;"><strong>Recent alerts (24h):</strong></p><ul>';
        foreach ( $recent as $k => $ts ) {
            echo '<li>' . esc_html( $k ) . ': ' . esc_html( $alerts[ $k . '_msg' ] ?? '' ) . '</li>';
        }
        echo '</ul>';
    }
}

/**
 * Dismissal state for admin alert notices. Maps alert key → the FIRE timestamp
 * that was dismissed. wc_xmr_alert() bumps the key's timestamp on every new
 * firing, so a dismissed notice only stays hidden until that specific
 * occurrence is superseded - a genuinely new firing shows up again.
 */
function wc_xmr_alerts_dismissed() {
    try { $d = get_option( 'wc_xmr_alerts_dismissed', array() ); } catch ( Throwable $e ) { error_log( 'WC XMR: get_option wc_xmr_alerts_dismissed threw: ' . $e->getMessage() ); $d = array(); }
    if ( ! is_array( $d ) ) $d = array();
    return $d;
}

/* Admin notice for pool low / RPC fail - each notice gets an x that
 * persists dismissal (per firing instance) via AJAX. */
add_action( 'admin_notices', function() {
    try {
        if ( ! current_user_can( 'manage_woocommerce' ) ) return;
        try { $alerts = get_option( 'wc_xmr_alerts', array() ); } catch ( Throwable $e ) { error_log( 'WC XMR: get_option wc_xmr_alerts threw in admin_notices: ' . $e->getMessage() ); return; }
        if ( ! is_array( $alerts ) ) return;
        $dismissed = wc_xmr_alerts_dismissed();
        $shown = false;
        foreach ( $alerts as $k => $ts ) {
            if ( ! is_int( $ts ) || $ts < time() - 3600 ) continue;
            if ( isset( $dismissed[ $k ] ) && is_int( $dismissed[ $k ] ) && $dismissed[ $k ] >= $ts ) continue;
            $shown = true;
            echo '<div class="notice notice-warning wc-xmr-alert" data-key="' . esc_attr( $k ) . '">' .
                 '<button type="button" class="notice-dismiss" data-key="' . esc_attr( $k ) . '"><span class="screen-reader-text">' .
                 esc_html__( 'Dismiss this notice.', 'wc-xmr' ) . '</span></button>' .
                 '<p><strong>Monero gateway:</strong> ' .
                esc_html( $alerts[ $k . '_msg' ] ?? $k ) . '</p></div>';
        }
        if ( ! $shown ) return;
        $ajax  = admin_url( 'admin-ajax.php' );
        $nonce = wp_create_nonce( 'wc_xmr_dismiss_alert' );
        ?>
        <script>
        (function(){
            var ajaxUrl = <?php echo wp_json_encode( $ajax ); ?>;
            var nonce   = <?php echo wp_json_encode( $nonce ); ?>;
            document.querySelectorAll('.wc-xmr-alert button.notice-dismiss').forEach(function(btn){
                btn.addEventListener('click', function(){
                    var notice = btn.closest('.wc-xmr-alert');
                    var key    = btn.getAttribute('data-key') || (notice ? notice.getAttribute('data-key') : '');
                    if (notice) notice.remove();
                    // Persist best-effort: even if the request fails, the notice
                    // is gone for this page view and will re-show on reload.
                    if (!key || !window.fetch) return;
                    var body = new URLSearchParams();
                    body.append('action', 'wc_xmr_dismiss_alert');
                    body.append('nonce', nonce);
                    body.append('key', key);
                    fetch(ajaxUrl, { method: 'POST', credentials: 'same-origin', body: body })
                        .catch(function(){ /* transient - notice re-shows on next load */ });
                });
            });
        })();
        </script>
        <?php
    } catch ( Throwable $e ) { error_log( 'WC XMR: admin_notices alerts threw: ' . $e->getMessage() ); }
});

/* Persist an x click: records the alert's current fire timestamp as dismissed. */
add_action( 'wp_ajax_wc_xmr_dismiss_alert', function() {
    try {
        if ( ! current_user_can( 'manage_woocommerce' ) ) {
            wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
        }
        check_ajax_referer( 'wc_xmr_dismiss_alert', 'nonce' );
        $key = isset( $_POST['key'] ) ? (string) wp_unslash( $_POST['key'] ) : '';
        try { $alerts = get_option( 'wc_xmr_alerts', array() ); } catch ( Throwable $e ) { error_log( 'WC XMR: get_option wc_xmr_alerts threw in dismiss handler: ' . $e->getMessage() ); $alerts = array(); }
        if ( $key === '' || ! is_array( $alerts ) || ! isset( $alerts[ $key ] ) || ! is_int( $alerts[ $key ] ) ) {
            wp_send_json_error( array( 'message' => 'unknown alert.' ), 404 );
        }
        $dismissed = wc_xmr_alerts_dismissed();
        $dismissed[ $key ] = (int) $alerts[ $key ];
        // Bounded: a dismissal older than 25h can never match a displayed
        // notice anyway (notices live 1h, dashboard list 24h).
        foreach ( $dismissed as $dk => $dts ) {
            if ( ! is_int( $dts ) || $dts < time() - 90000 ) unset( $dismissed[ $dk ] );
        }
        $ok = update_option( 'wc_xmr_alerts_dismissed', $dismissed, false );
        if ( $ok === false && get_option( 'wc_xmr_alerts_dismissed' ) !== $dismissed ) {
            error_log( 'WC XMR: update_option wc_xmr_alerts_dismissed failed for key=' . $key );
        }
        wp_send_json_success();
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: dismiss_alert handler threw: ' . $e->getMessage() );
        wp_send_json_error( array( 'message' => 'Internal error.' ), 500 );
    }
});
/* ============ Live status endpoint for the customer-facing progress bar ============ */

/**
 * Lightweight polling endpoint so the payment page can show live progress
 * without a full page reload. Guest-accessible (nopriv), but gated by the
 * order's own order_key - the same token WooCommerce already uses to let
 * guests view their own order pages - so it can't be used to probe other
 * people's order data.
 */
add_action( 'wp_ajax_wc_xmr_status', 'wc_xmr_ajax_status' );
add_action( 'wp_ajax_nopriv_wc_xmr_status', 'wc_xmr_ajax_status' );
function wc_xmr_ajax_status() {
    try {
    $order_id = isset( $_GET['order_id'] ) ? absint( $_GET['order_id'] ) : 0;
    $key = isset( $_GET['key'] ) ? sanitize_text_field( wp_unslash( $_GET['key'] ) ) : '';
    try { $order = $order_id ? wc_get_order( $order_id ) : false; } catch ( Throwable $e ) { error_log( 'WC XMR: wc_get_order threw in ajax_status for #' . $order_id . ': ' . $e->getMessage() ); $order = false; }

    if ( ! $order || ! $key ) { wp_send_json_error( array( 'message' => 'Not found.' ), 404 ); }
    try { $order_key = (string) $order->get_order_key(); } catch ( Throwable $e ) { error_log( 'WC XMR: get_order_key threw in ajax_status: ' . $e->getMessage() ); wp_send_json_error( array( 'message' => 'Not found.' ), 404 ); }
    if ( ! hash_equals( $order_key, $key ) ) { wp_send_json_error( array( 'message' => 'Not found.' ), 404 ); }
    try { $pm = $order->get_payment_method(); } catch ( Throwable $e ) { error_log( 'WC XMR: get_payment_method threw in ajax_status: ' . $e->getMessage() ); wp_send_json_error( array( 'message' => 'Not found.' ), 404 ); }
    if ( $pm !== 'monero' ) { wp_send_json_error( array( 'message' => 'Not an XMR order.' ), 400 ); }

    try { $settings = wc_xmr_settings(); } catch ( Throwable $e ) { error_log( 'WC XMR: wc_xmr_settings threw in ajax_status: ' . $e->getMessage() ); $settings = array(); }
    if ( ! is_array( $settings ) ) $settings = array();
    try {
        $received = (float) $order->get_meta( '_xmr_received' );
        $amount   = (float) $order->get_meta( '_xmr_amount' );
        $min_amt  = (float) $order->get_meta( '_xmr_min_amount' );
        $confs    = (int) $order->get_meta( '_xmr_confirmations' );
        $status   = $order->get_status();
        $tx_raw   = (string) $order->get_meta( '_xmr_tx_hashes' );
    } catch ( Throwable $e ) { error_log( 'WC XMR: get_meta threw in ajax_status: ' . $e->getMessage() ); $received = 0; $amount = 0; $min_amt = 0; $confs = 0; $status = 'pending'; $tx_raw = ''; }
    $conf_p   = max( 0, (int) wc_xmr_num( $settings, 'conf_processing', 1 ) );
    $conf_c   = max( 0, (int) wc_xmr_num( $settings, 'conf_complete', 10 ) );

    // Underpayment awareness. Without this, ANY payment that reached
    // processing confirmations reported stage 'confirmed' - the customer saw
    // "[OK] Payment confirmed" while wc_xmr_update_order() correctly refused to
    // advance an underpaid order, leaving it on-hold forever with the page
    // showing green and polling stopped. A dedicated 'underpaid' stage keeps
    // the page honest and still polling, so a top-up flips it to confirmed.
    $terminal = in_array( $status, array( 'processing', 'completed', 'cancelled', 'failed', 'refunded' ), true );
    $underpaid = ( $received > 0 && $min_amt > 0 && ( $received + 1e-12 ) < $min_amt && ! $terminal );

    $stage = 'awaiting';
    if ( $received > 0 && $confs < $conf_p ) $stage = 'detected';
    if ( $received > 0 && $confs >= $conf_p ) $stage = 'confirmed';
    if ( $underpaid ) $stage = 'underpaid';
    if ( in_array( $status, array( 'processing', 'completed' ), true ) ) $stage = 'confirmed';
    if ( in_array( $status, array( 'cancelled', 'failed', 'refunded' ), true ) ) $stage = 'closed';

    $tx_hashes = array_filter( explode( ',', $tx_raw ) );
    $tx_hashes = array_filter( $tx_hashes, 'is_string' );
    try {
        $tx_links = array_map( function( $tx ) {
            try { $links = wc_xmr_explorer_links( $tx ); } catch ( Throwable $e ) { error_log( 'WC XMR: wc_xmr_explorer_links threw: ' . $e->getMessage() ); $links = array(); }
            return array( 'hash' => $tx, 'links' => is_array( $links ) ? $links : array() );
        }, array_values( $tx_hashes ) );
    } catch ( Throwable $e ) { error_log( 'WC XMR: tx_links map threw: ' . $e->getMessage() ); $tx_links = array(); }

    try {
        wp_send_json_success( array(
            'order_status'  => $status,
            'stage'         => $stage,
            'received'      => $received,
            'amount'        => $amount,
            'min'           => $min_amt,
            'underpaid'     => $underpaid,
            'confirmations' => $confs,
            'conf_processing' => $conf_p,
            'conf_complete'   => $conf_c,
            'tx_links'        => $tx_links,
        ) );
    } catch ( Throwable $e ) { error_log( 'WC XMR: wp_send_json_success threw in ajax_status: ' . $e->getMessage() ); wp_send_json_error( array( 'message' => 'Internal error.' ), 500 ); }
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: wc_xmr_ajax_status crashed: ' . $e->getMessage() );
        wp_send_json_error( array( 'message' => 'Internal error.' ), 500 );
    }
}
