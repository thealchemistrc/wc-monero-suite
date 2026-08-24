<?php
if ( ! defined( 'ABSPATH' ) ) exit;

function wc_xmr_test_mode() {
    static $mode = null;
    if ( $mode !== null ) return $mode;

    try {
        if ( ! function_exists( 'wc_xmr_settings' ) ) {
            error_log( 'WC XMR: wc_xmr_settings() not available in wc_xmr_test_mode() - returning off.' );
            return $mode = 'off';
        }
        $s = wc_xmr_settings();
        if ( ! is_array( $s ) ) {
            error_log( 'WC XMR: wc_xmr_settings() did not return array in wc_xmr_test_mode() - type: ' . gettype( $s ) );
            return $mode = 'off';
        }
        $requested = $s['test_mode'] ?? 'off';
        if ( ! is_string( $requested ) ) {
            error_log( 'WC XMR: test_mode setting is not a string: ' . var_export( $requested, true ) );
            $requested = 'off';
        }
        if ( ! in_array( $requested, array( 'simulate', 'testnet' ), true ) ) {
            return $mode = 'off';
        }

        $env = 'production';
        try {
            $env = function_exists( 'wp_get_environment_type' ) ? wp_get_environment_type() : 'production';
            if ( ! is_string( $env ) || $env === '' ) $env = 'production';
        } catch ( Throwable $e ) {
            error_log( 'WC XMR: wp_get_environment_type() threw: ' . $e->getMessage() );
            $env = 'production';
        }
        $override = ( $s['test_mode_env_override'] ?? 'no' ) === 'yes';

        if ( $env === 'production' && ! $override ) {
            $ok = set_transient( 'wc_xmr_test_mode_blocked', $requested, HOUR_IN_SECONDS );
            if ( ! $ok ) error_log( 'WC XMR: set_transient wc_xmr_test_mode_blocked failed.' );
            return $mode = 'off';
        }
        $deleted = delete_transient( 'wc_xmr_test_mode_blocked' );
        if ( ! $deleted && get_transient( 'wc_xmr_test_mode_blocked' ) !== false ) {
            error_log( 'WC XMR: delete_transient wc_xmr_test_mode_blocked failed.' );
        }
        return $mode = $requested;
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: wc_xmr_test_mode() crashed: ' . $e->getMessage() );
        return $mode = 'off';
    }
}

add_action( 'admin_notices', function() {
    if ( ! current_user_can( 'manage_woocommerce' ) ) return;

    $blocked = get_transient( 'wc_xmr_test_mode_blocked' );
    if ( $blocked ) {
        echo '<div class="notice notice-warning"><p><strong>Monero gateway:</strong> Test mode ("' . esc_html( $blocked ) . '") is configured but was NOT activated because this environment is detected as production (WP_ENVIRONMENT_TYPE). If this really is a staging/test site, tick "I understand this looks like production" in the gateway\'s test mode settings, or set <code>define(\'WP_ENVIRONMENT_TYPE\', \'staging\');</code> in wp-config.php.</p></div>';
        return;
    }

    try {
        $mode = wc_xmr_test_mode();
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: wc_xmr_test_mode() threw in admin_notices: ' . $e->getMessage() );
        return;
    }
    if ( $mode === 'off' ) return;
    echo '<div class="notice notice-error"><p><strong style="font-size:1.1em;">Monero gateway TEST MODE is ACTIVE (' . esc_html( strtoupper( $mode ) ) . ')</strong> - ' .
        ( $mode === 'simulate'
            ? 'no real wallet-rpc calls are made; addresses shown to customers are fake placeholders.'
            : 'real wallet-rpc calls ARE being made, against the testnet wallet configured below - verify that\'s really a testnet/stagenet endpoint, not your production wallet.' ) .
        ' Turn this off before taking real orders.</p></div>';
});

add_filter( 'woocommerce_gateway_title', function( $title, $id ) {
    if ( $id !== 'monero' ) return $title;
    try {
        $mode = wc_xmr_test_mode();
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: wc_xmr_test_mode() threw in gateway_title filter: ' . $e->getMessage() );
        return $title;
    }
    if ( $mode === 'off' ) return $title;
    return $title . ' -  TEST MODE (' . strtoupper( $mode ) . ', not a real payment)';
}, 10, 2 );

add_action( 'woocommerce_before_checkout_form', 'wc_xmr_test_mode_checkout_banner' );
add_action( 'woocommerce_before_thankyou',      'wc_xmr_test_mode_checkout_banner' );
function wc_xmr_test_mode_checkout_banner() {
    try {
        $mode = wc_xmr_test_mode();
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: checkout banner wc_xmr_test_mode() threw: ' . $e->getMessage() );
        return;
    }
    if ( $mode === 'off' ) return;
    echo '<div style="background:#b32d2e;color:#fff;padding:12px 16px;text-align:center;font-weight:bold;border-radius:4px;margin-bottom:16px;">
         MONERO TEST MODE ACTIVE (' . esc_html( strtoupper( $mode ) ) . ') - this is not a real payment' .
        ( $mode === 'testnet' ? ', it uses testnet XMR with no real value' : '' ) . '.
    </div>';
}

function wc_xmr_simulate_fake_address( $order_id ) {
    if ( ! is_scalar( $order_id ) ) {
        error_log( 'WC XMR: wc_xmr_simulate_fake_address got non-scalar order_id: ' . gettype( $order_id ) );
        $order_id = (string) time() . wp_rand();
    }
    try {
        $rand = wp_rand();
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: wp_rand() failed in simulate_fake_address: ' . $e->getMessage() );
        $rand = random_int( 0, PHP_INT_MAX );
    }
    return 'TEST-SIMULATED-NOT-A-REAL-ADDRESS-' . substr( md5( (string) $order_id . (string) $rand ), 0, 16 );
}

add_action( 'add_meta_boxes', function() {
    try {
        if ( wc_xmr_test_mode() !== 'simulate' ) return;
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: wc_xmr_test_mode() threw in add_meta_boxes: ' . $e->getMessage() );
        return;
    }
    $screens = array( 'shop_order' );
    if ( function_exists( 'wc_get_page_screen_id' ) ) {
        try { $screens[] = wc_get_page_screen_id( 'shop-order' ); } catch ( Throwable $e ) { error_log( 'WC XMR: wc_get_page_screen_id threw: ' . $e->getMessage() ); }
    }
    foreach ( array_unique( array_filter( $screens ) ) as $s ) {
        add_meta_box( 'wc_xmr_test_cheat', ' XMR Test Mode - Simulate Payment', 'wc_xmr_test_cheat_box', $s, 'side', 'high' );
    }
});

function wc_xmr_test_cheat_box( $post_or_order ) {
    try {
        $order = ( $post_or_order instanceof WP_Post ) ? wc_get_order( $post_or_order->ID ) : $post_or_order;
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: wc_get_order threw in cheat_box: ' . $e->getMessage() );
        echo '<p style="color:#b71c1c;">Error loading order.</p>'; return;
    }
    if ( ! $order || $order->get_payment_method() !== 'monero' ) {
        echo '<p style="color:#999;">Not an XMR order.</p>'; return;
    }
    $id = $order->get_id();
    $actions = array(
        'detected_partial' => 'Simulate: partial payment seen (0 conf)',
        'confirmed_exact'  => 'Simulate: paid in full, confirmed → mark paid',
        'underpaid'        => 'Simulate: underpaid (below tolerance)',
        'overpaid'         => 'Simulate: overpaid',
        'expired'          => 'Simulate: reservation expired unpaid',
    );
    echo '<p style="font-size:11px;color:#666;">These buttons never touch a real wallet - pure UI/flow simulation.</p>';
    foreach ( $actions as $action => $label ) {
        $url = wp_nonce_url( admin_url( 'admin-post.php?action=wc_xmr_test_simulate&sim=' . $action . '&order_id=' . $id ), 'wc_xmr_test_simulate_' . $id );
        echo '<p><a href="' . esc_url( $url ) . '" class="button" style="width:100%;text-align:center;">' . esc_html( $label ) . '</a></p>';
    }
}

add_action( 'admin_post_wc_xmr_test_simulate', function() {
    try {
        if ( wc_xmr_test_mode() !== 'simulate' ) wp_die( 'Test mode is not active.' );
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: wc_xmr_test_mode() threw in test_simulate handler: ' . $e->getMessage() );
        wp_die( 'Test mode check failed.' );
    }
    $order_id = isset( $_GET['order_id'] ) ? absint( $_GET['order_id'] ) : 0;
    $sim = sanitize_key( $_GET['sim'] ?? '' );
    if ( ! $order_id || ! current_user_can( 'edit_shop_orders' ) ) wp_die( 'no' );
    check_admin_referer( 'wc_xmr_test_simulate_' . $order_id );

    try {
        $order = wc_get_order( $order_id );
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: wc_get_order threw in test_simulate: ' . $e->getMessage() );
        wp_die( 'Failed to load order.' );
    }
    if ( ! $order || $order->get_payment_method() !== 'monero' ) wp_die( 'not an XMR order' );

    global $wpdb;
    $t = $wpdb->prefix . 'wc_xmr_reservations';
    $amount = (float) $order->get_meta( '_xmr_amount' );
    if ( $amount <= 0 ) {
        error_log( 'WC XMR: test_simulate order #' . $order_id . ' has invalid amount: ' . $amount );
        wp_die( 'Order has no XMR amount.' );
    }
    $now = current_time( 'mysql', 1 );
    try { $s = wc_xmr_settings(); } catch ( Throwable $e ) { error_log( 'WC XMR: wc_xmr_settings threw in test_simulate: ' . $e->getMessage() ); $s = array(); }

    if ( $sim === 'expired' ) {
        $result = $wpdb->update( $t, array( 'status' => 'released' ), array( 'order_id' => $order_id ) );
        if ( $result === false ) error_log( 'WC XMR: test_simulate expired update failed for order #' . $order_id . ': ' . $wpdb->last_error );
        $order->update_status( 'cancelled', '[TEST MODE] Simulated: reservation expired unpaid, address released.' );
        wp_safe_redirect( wp_get_referer() ?: admin_url( 'admin.php?page=wc-orders' ) );
        exit;
    }

    $row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$t} WHERE order_id = %d", $order_id ) );
    if ( $wpdb->last_error ) error_log( 'WC XMR: test_simulate get_row failed: ' . $wpdb->last_error );
    if ( ! $row ) wp_die( 'No reservation found for this order.' );

    $conf_complete = max( 1, (int) wc_xmr_num( $s, 'conf_complete', 10 ) );
    switch ( $sim ) {
        case 'detected_partial':
            $received = round( $amount * 0.4, 12 ); $confs = 0;
            break;
        case 'confirmed_exact':
            $received = $amount; $confs = $conf_complete;
            break;
        case 'underpaid':
            $received = round( $amount * 0.5, 12 ); $confs = $conf_complete;
            break;
        case 'overpaid':
            $received = round( $amount * 1.5, 12 ); $confs = $conf_complete;
            break;
        default:
            wp_die( 'Unknown simulation action.' );
    }

    try {
        wc_xmr_update_order( $row, $received, $confs, array( 'sim-tx-' . wp_rand() ), $s );
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: wc_xmr_update_order threw in test_simulate: ' . $e->getMessage() );
        wp_die( 'Failed to update order: ' . $e->getMessage() );
    }
    $order->add_order_note( '[TEST MODE] Simulated: ' . str_replace( '_', ' ', $sim ) . '.' );

    wp_safe_redirect( wp_get_referer() ?: admin_url( 'admin.php?page=wc-orders' ) );
    exit;
});

add_action( 'admin_bar_menu', function( $bar ) {
    if ( ! current_user_can( 'manage_woocommerce' ) ) return;
    try {
        $bar->add_node( array(
            'id'    => 'wc-xmr-unstick',
            'title' => ' Clear my XMR rate-limit',
            'href'  => wp_nonce_url( admin_url( 'admin-post.php?action=wc_xmr_clear_my_rate_limit' ), 'wc_xmr_clear_my_rate_limit' ),
        ) );
    } catch ( Throwable $e ) {
        error_log( 'WC XMR: admin_bar_menu add_node threw: ' . $e->getMessage() );
    }
}, 100 );

add_action( 'admin_post_wc_xmr_clear_my_rate_limit', function() {
    if ( ! current_user_can( 'manage_woocommerce' ) ) wp_die( 'no' );
    check_admin_referer( 'wc_xmr_clear_my_rate_limit' );

    global $wpdb;
    try { $ip_hash = wc_xmr_ip_hash(); } catch ( Throwable $e ) { error_log( 'WC XMR: wc_xmr_ip_hash threw in clear_rate_limit: ' . $e->getMessage() ); wp_die( 'Failed to compute IP hash.' ); }
    try { $fingerprint = wc_xmr_fingerprint(); } catch ( Throwable $e ) { error_log( 'WC XMR: wc_xmr_fingerprint threw in clear_rate_limit: ' . $e->getMessage() ); wp_die( 'Failed to compute fingerprint.' ); }

    $r1 = $wpdb->delete( $wpdb->prefix . 'wc_xmr_ratelimit', array( 'ip_hash' => $ip_hash ) );
    if ( $r1 === false ) error_log( 'WC XMR: delete ratelimit failed: ' . $wpdb->last_error );
    $r2 = $wpdb->delete( $wpdb->prefix . 'wc_xmr_behavior', array( 'fingerprint' => $fingerprint ) );
    if ( $r2 === false ) error_log( 'WC XMR: delete behavior failed: ' . $wpdb->last_error );

    wp_safe_redirect( add_query_arg( 'wc_xmr_unstuck', '1', wp_get_referer() ?: admin_url() ) );
    exit;
});

add_action( 'admin_notices', function() {
    if ( empty( $_GET['wc_xmr_unstuck'] ) ) return;
    if ( ! current_user_can( 'manage_woocommerce' ) ) return;
    echo '<div class="notice notice-success is-dismissible"><p>Your XMR rate-limit/behavior-score record has been cleared - the next checkout attempt starts fresh.</p></div>';
});
