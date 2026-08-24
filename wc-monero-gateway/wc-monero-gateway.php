<?php
/**
 * Plugin Name: WooCommerce Monero Gateway
 * Description: Accept Monero (XMR) payments in WooCommerce via rotating subaddresses, wallet-rpc polling, and optional push companion.
 * Version:     1.0.0
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Author:      WC Monero Suite contributors
 * License:     GPL-2.0-or-later
 * Text Domain: wc-xmr
 */

if ( ! defined( 'ABSPATH' ) ) exit;

define( 'WC_XMR_PLUGIN_FILE', __FILE__ );
define( 'WC_XMR_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'WC_XMR_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

define( 'WC_XMR_DB_VERSION', '2' );

add_action( 'plugins_loaded', 'wc_xmr_init_gateway', 11 );
add_action( 'plugins_loaded', 'wc_xmr_maybe_upgrade_db', 5 );
add_action( 'plugins_loaded', 'wc_xmr_ensure_checkout_height_column', 4 );
/**
 * Ensure the checkout_height column exists in the reservations table.
 * Runs on every plugins_loaded (before the version-gated upgrade) so that
 * if a previous ALTER TABLE failed or the column was missed, it gets added.
 */
function wc_xmr_ensure_checkout_height_column() {
	try {
		global $wpdb;
		$table = $wpdb->prefix . 'wc_xmr_reservations';
		$col_exists = $wpdb->get_results( $wpdb->prepare(
			"SHOW COLUMNS FROM `{$table}` LIKE %s",
			'checkout_height'
		) );
		if ( empty( $col_exists ) ) {
			$result = $wpdb->query( "ALTER TABLE `{$table}` ADD COLUMN `checkout_height` INT UNSIGNED NOT NULL DEFAULT 0" );
			if ( $result === false ) {
				error_log( 'WC XMR: wc_xmr_ensure_checkout_height_column failed to add column: ' . $wpdb->last_error );
			} else {
				error_log( 'WC XMR: Added missing checkout_height column to reservations table.' );
			}
		}
	} catch ( Throwable $e ) {
		error_log( 'WC XMR: wc_xmr_ensure_checkout_height_column crashed: ' . $e->getMessage() );
	}
}

function wc_xmr_maybe_upgrade_db() {
	try {
		$current = get_option( 'wc_xmr_db_version', '0' );
		if ( $current === WC_XMR_DB_VERSION ) return;

		// v1 → v2: add checkout_height column for per-order scan checkpoints
		if ( version_compare( $current, '2', '<' ) ) {
			global $wpdb;
			$table = $wpdb->prefix . 'wc_xmr_reservations';
			// Check if column already exists (in case of partial upgrade)
			$col_exists = $wpdb->get_results( $wpdb->prepare(
				"SHOW COLUMNS FROM `{$table}` LIKE %s",
				'checkout_height'
			) );
			if ( empty( $col_exists ) ) {
				$result = $wpdb->query( "ALTER TABLE `{$table}` ADD COLUMN `checkout_height` INT UNSIGNED NOT NULL DEFAULT 0" );
				if ( $result === false ) {
					error_log( 'WC XMR: upgrade v1→v2 failed to add checkout_height column: ' . $wpdb->last_error );
				}
			}
		}

		wc_xmr_activate();
		$ok = update_option( 'wc_xmr_db_version', WC_XMR_DB_VERSION, false );
		if ( ! $ok ) error_log( 'WC XMR: update_option wc_xmr_db_version failed in wc_xmr_maybe_upgrade_db().' );
	} catch ( Throwable $e ) {
		error_log( 'WC XMR: wc_xmr_maybe_upgrade_db crashed: ' . $e->getMessage() );
	}
}
add_action( 'before_woocommerce_init', function() {
	try {
		if ( class_exists( \Automattic\WooCommerce\Utilities\FeaturesUtil::class ) ) {
			\Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility( 'custom_order_tables', WC_XMR_PLUGIN_FILE, true );
			\Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility( 'cart_checkout_blocks', WC_XMR_PLUGIN_FILE, true );
		}
	} catch ( Throwable $e ) {
		error_log( 'WC XMR: declare_compatibility threw: ' . $e->getMessage() );
	}
});

function wc_xmr_register_blocks_integration() {
	if ( ! class_exists( 'Automattic\WooCommerce\Blocks\Payments\Integrations\AbstractPaymentMethodType' ) ) return;
	$path = WC_XMR_PLUGIN_DIR . 'class-wc-xmr-blocks.php';
	if ( ! file_exists( $path ) ) { error_log( 'WC XMR: blocks file missing: ' . $path ); return; }
	try {
		require_once $path;
		add_action( 'woocommerce_blocks_payment_method_type_registration', function( $reg ) {
			try { $reg->register( new WC_XMR_Blocks() ); } catch ( Throwable $e ) { error_log( 'WC XMR: register WC_XMR_Blocks threw: ' . $e->getMessage() ); }
		});
	} catch ( Throwable $e ) {
		error_log( 'WC XMR: loading blocks integration threw: ' . $e->getMessage() );
	}
}
add_action( 'woocommerce_blocks_loaded', 'wc_xmr_register_blocks_integration' );
if ( did_action( 'woocommerce_blocks_loaded' ) ) {
	wc_xmr_register_blocks_integration();
}

function wc_xmr_init_gateway() {
	if ( ! class_exists( 'WC_Payment_Gateway' ) ) return;
	$files = array(
		'class-wc-xmr-crypto.php',
		'class-wc-xmr-http.php',
		'class-wc-xmr-testmode.php',
		'class-wc-gateway-monero.php',
		'class-wc-xmr-rpc.php',
		'class-wc-xmr-poller.php',
		'vendor/monero/load.php',
		'includes/class-wc-monero-native-scanner.php',
	);
	foreach ( $files as $f ) {
		$p = WC_XMR_PLUGIN_DIR . $f;
		if ( ! file_exists( $p ) ) { error_log( 'WC XMR: required file missing: ' . $p ); return; }
		try { require_once $p; } catch ( Throwable $e ) { error_log( 'WC XMR: require ' . $f . ' threw: ' . $e->getMessage() ); return; }
	}
	try {
		add_filter( 'woocommerce_payment_gateways', function( $gateways ) {
			if ( ! is_array( $gateways ) ) { error_log( 'WC XMR: woocommerce_payment_gateways filter got non-array.' ); $gateways = array(); }
			$gateways[] = 'WC_Gateway_Monero';
			return $gateways;
		});
	} catch ( Throwable $e ) {
		error_log( 'WC XMR: add_filter woocommerce_payment_gateways threw: ' . $e->getMessage() );
	}
}

register_activation_hook( __FILE__, 'wc_xmr_activate' );
function wc_xmr_activate() {
	global $wpdb;
	try {
		$table   = $wpdb->prefix . 'wc_xmr_reservations';
		$charset = $wpdb->get_charset_collate();
		$sql = "CREATE TABLE {$table} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			address VARCHAR(191) NOT NULL,
			order_id BIGINT UNSIGNED NOT NULL,
			wallet_id VARCHAR(64) NOT NULL DEFAULT 'default',
			account_index INT NOT NULL DEFAULT 0,
			subaddress_index INT NOT NULL DEFAULT 0,
			amount_xmr DECIMAL(20,12) NOT NULL DEFAULT 0,
			min_amount_xmr DECIMAL(20,12) NOT NULL DEFAULT 0,
			received_xmr DECIMAL(20,12) NOT NULL DEFAULT 0,
			tx_hashes TEXT NULL,
			confirmations INT NOT NULL DEFAULT 0,
			first_seen_at DATETIME NULL,
			reserved_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL,
			status VARCHAR(20) NOT NULL DEFAULT 'reserved',
			ip_hash VARCHAR(64) NULL,
			checkout_height INT UNSIGNED NOT NULL DEFAULT 0,
			PRIMARY KEY (id),
			UNIQUE KEY order_id (order_id),
			KEY address (address),
			KEY status_expires (status, expires_at),
			KEY wallet_id (wallet_id),
			KEY ip_hash (ip_hash)
		) {$charset};";
		if ( ! file_exists( ABSPATH . 'wp-admin/includes/upgrade.php' ) ) {
			error_log( 'WC XMR: upgrade.php not found at ' . ABSPATH . 'wp-admin/includes/upgrade.php' );
			return;
		}
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$r1 = dbDelta( $sql );
		if ( $wpdb->last_error ) error_log( 'WC XMR: dbDelta reservations failed: ' . $wpdb->last_error );

		$rl_table = $wpdb->prefix . 'wc_xmr_ratelimit';
		$sql2 = "CREATE TABLE {$rl_table} (
			ip_hash VARCHAR(64) NOT NULL,
			attempts INT NOT NULL DEFAULT 0,
			window_start DATETIME NOT NULL,
			blocked_until DATETIME NULL,
			PRIMARY KEY (ip_hash)
		) {$charset};";
		$r2 = dbDelta( $sql2 );
		if ( $wpdb->last_error ) error_log( 'WC XMR: dbDelta ratelimit failed: ' . $wpdb->last_error );

		$bh_table = $wpdb->prefix . 'wc_xmr_behavior';
		$sql3 = "CREATE TABLE {$bh_table} (
			fingerprint VARCHAR(64) NOT NULL,
			score FLOAT NOT NULL DEFAULT 0,
			req_count INT NOT NULL DEFAULT 0,
			last_seen DATETIME NOT NULL,
			last_cart_hash VARCHAR(32) NULL,
			blocked_until DATETIME NULL,
			PRIMARY KEY (fingerprint),
			KEY blocked_until (blocked_until)
		) {$charset};";
		$r3 = dbDelta( $sql3 );
		if ( $wpdb->last_error ) error_log( 'WC XMR: dbDelta behavior failed: ' . $wpdb->last_error );

		if ( ! wp_next_scheduled( 'wc_xmr_release_expired' ) ) {
			$ok = wp_schedule_event( time() + 300, 'hourly', 'wc_xmr_release_expired' );
			if ( $ok === false ) error_log( 'WC XMR: wp_schedule_event wc_xmr_release_expired failed.' );
		}
		// Polling is now scheduled on-demand only when open orders exist.
		// See wc_xmr_schedule_poll_if_needed() in class-wc-xmr-poller.php.
	} catch ( Throwable $e ) {
		error_log( 'WC XMR: wc_xmr_activate crashed: ' . $e->getMessage() );
	}
}

register_deactivation_hook( __FILE__, function() {
	try {
		wp_clear_scheduled_hook( 'wc_xmr_release_expired' );
		wp_clear_scheduled_hook( 'wc_xmr_poll' );
		wp_clear_scheduled_hook( 'wc_xmr_rate_warm' );
		wp_clear_scheduled_hook( 'wc_xmr_rate_refresh_event' );
	} catch ( Throwable $e ) {
		error_log( 'WC XMR: deactivation clear hooks threw: ' . $e->getMessage() );
	}
});

add_filter( 'cron_schedules', function( $s ) {
	if ( ! is_array( $s ) ) { error_log( 'WC XMR: cron_schedules filter got non-array.' ); $s = array(); }
	$minutes = 5;
	try {
		if ( function_exists( 'wc_xmr_settings' ) && function_exists( 'wc_xmr_num' ) ) {
			$minutes = (int) wc_xmr_num( wc_xmr_settings(), 'poll_interval', 5 );
		}
	} catch ( Throwable $e ) {
		error_log( 'WC XMR: cron_schedules wc_xmr_settings threw: ' . $e->getMessage() );
	}
	$minutes = max( 2, min( 60, $minutes ) );
	$s['wc_xmr_5min'] = array( 'interval' => $minutes * 60, 'display' => sprintf( '%d min (XMR poll)', $minutes ) );
	return $s;
});

add_action( 'wc_xmr_release_expired', 'wc_xmr_release_expired_cb' );
function wc_xmr_release_expired_cb() {
	global $wpdb;
	try {
		$table = $wpdb->prefix . 'wc_xmr_reservations';
		$now   = current_time( 'mysql', 1 );
		$expired = $wpdb->get_results( $wpdb->prepare(
			"SELECT id, order_id FROM {$table} WHERE status = 'reserved' AND expires_at < %s",
			$now
		) );
		if ( $wpdb->last_error ) { error_log( 'WC XMR: release_expired get_results failed: ' . $wpdb->last_error ); return; }
		if ( ! is_array( $expired ) ) { error_log( 'WC XMR: release_expired get_results returned non-array: ' . gettype( $expired ) ); return; }
		if ( empty( $expired ) ) return;
		foreach ( $expired as $row ) {
			if ( ! isset( $row->id, $row->order_id ) ) { error_log( 'WC XMR: release_expired row missing id/order_id.' ); continue; }
			try { $order = wc_get_order( $row->order_id ); } catch ( Throwable $e ) { error_log( 'WC XMR: wc_get_order threw in release_expired for order #' . $row->order_id . ': ' . $e->getMessage() ); continue; }
			if ( $order && in_array( $order->get_status(), array( 'pending', 'failed', 'cancelled' ), true ) ) {
				$result = $wpdb->update( $table, array( 'status' => 'released' ), array( 'id' => $row->id ) );
				if ( $result === false ) error_log( sprintf( 'WC XMR: Failed to release expired reservation id=%d: %s', $row->id, $wpdb->last_error ) );
			} elseif ( ! $order ) {
				$result = $wpdb->update( $table, array( 'status' => 'released' ), array( 'id' => $row->id ) );
				if ( $result === false ) error_log( sprintf( 'WC XMR: Failed to release expired reservation id=%d (order missing): %s', $row->id, $wpdb->last_error ) );
			}
		}
	} catch ( Throwable $e ) {
		error_log( 'WC XMR: wc_xmr_release_expired_cb crashed: ' . $e->getMessage() );
	}
}

add_action( 'woocommerce_order_status_cancelled', 'wc_xmr_release_on_cancel' );
add_action( 'woocommerce_order_status_failed',    'wc_xmr_release_on_cancel' );

/**
 * When an order goes to 'on-hold' (awaiting Monero payment), kick off
 * conditional polling.  The poller reschedules itself after each run as
 * long as open orders remain - so we never poll 24/7 on idle stores.
 */
add_action( 'woocommerce_order_status_on-hold', 'wc_xmr_schedule_poll_on_new_order' );
function wc_xmr_schedule_poll_on_new_order( $order_id ) {
	if ( ! function_exists( 'wc_xmr_schedule_poll_if_needed' ) ) return;
	try {
		wc_xmr_schedule_poll_if_needed( 60 ); // first poll ~1 min after order placed
	} catch ( Throwable $e ) {
		error_log( 'WC XMR: wc_xmr_schedule_poll_on_new_order threw for order #' . $order_id . ': ' . $e->getMessage() );
	}
}

function wc_xmr_release_on_cancel( $order_id ) {
	global $wpdb;
	try {
		$table = $wpdb->prefix . 'wc_xmr_reservations';
		$res = $wpdb->query( $wpdb->prepare(
			"UPDATE {$table} SET status = 'released' WHERE order_id = %d AND status IN ('reserved','detected')",
			$order_id
		) );
		if ( $res === false ) error_log( 'WC XMR: release_on_cancel query failed for order #' . $order_id . ': ' . $wpdb->last_error );
	} catch ( Throwable $e ) {
		error_log( 'WC XMR: wc_xmr_release_on_cancel threw for order #' . $order_id . ': ' . $e->getMessage() );
	}
}

add_filter( 'manage_woocommerce_page_wc-orders_columns', 'wc_xmr_add_col' );
add_filter( 'manage_edit-shop_order_columns',            'wc_xmr_add_col' );
function wc_xmr_add_col( $cols ) {
	if ( ! is_array( $cols ) ) { error_log( 'WC XMR: wc_xmr_add_col got non-array: ' . gettype( $cols ) ); return array( 'xmr_address' => __( 'XMR', 'wc-xmr' ) ); }
	$out = array();
	foreach ( $cols as $k => $v ) {
		$out[ $k ] = $v;
		if ( $k === 'order_status' ) $out['xmr_address'] = __( 'XMR', 'wc-xmr' );
	}
	if ( ! isset( $out['xmr_address'] ) ) $out['xmr_address'] = __( 'XMR', 'wc-xmr' );
	return $out;
}

add_action( 'manage_woocommerce_page_wc-orders_custom_column', 'wc_xmr_render_col', 10, 2 );
add_action( 'manage_shop_order_posts_custom_column', function( $col, $post_id ) {
	try { wc_xmr_render_col( $col, wc_get_order( $post_id ) ); } catch ( Throwable $e ) { error_log( 'WC XMR: render_col (legacy) threw: ' . $e->getMessage() ); }
}, 10, 2 );

function wc_xmr_render_col( $col, $order ) {
	try {
		if ( $col !== 'xmr_address' ) return;
		if ( ! $order instanceof WC_Order ) return;
		if ( $order->get_payment_method() !== 'monero' ) { echo '-'; return; }
		$addr = $order->get_meta( '_xmr_address' );
		$amt  = $order->get_meta( '_xmr_amount' );
		if ( ! $addr ) { echo '-'; return; }
		if ( ! is_string( $addr ) ) $addr = (string) $addr;
		$short = esc_html( substr( $addr, 0, 6 ) . '...' . substr( $addr, -4 ) );
		echo '<code title="' . esc_attr( $addr ) . '" style="font-size:11px;">' . $short . '</code>';
		if ( $amt !== '' && $amt !== null ) {
			$s = rtrim( rtrim( number_format( (float) $amt, 12, '.', '' ), '0' ), '.' );
			echo '<br><small>' . esc_html( $s ) . ' XMR</small>';
		}
	} catch ( Throwable $e ) {
		error_log( 'WC XMR: wc_xmr_render_col threw: ' . $e->getMessage() );
		echo '-';
	}
}

add_filter( 'woocommerce_admin_order_actions', 'wc_xmr_row_actions', 10, 2 );
function wc_xmr_row_actions( $actions, $order ) {
	try {
		if ( ! $order instanceof WC_Order ) return $actions;
		if ( $order->get_payment_method() !== 'monero' ) return $actions;
		if ( $order->get_status() !== 'on-hold' )        return $actions;
		$url = wp_nonce_url(
			admin_url( 'admin-post.php?action=wc_xmr_mark_paid&order_id=' . $order->get_id() ),
			'wc_xmr_mark_paid_' . $order->get_id()
		);
		$actions['wc_xmr_paid'] = array(
			'url'    => $url,
			'name'   => __( 'Mark XMR paid', 'wc-xmr' ),
			'action' => 'wc-xmr-paid',
		);
	} catch ( Throwable $e ) {
		error_log( 'WC XMR: wc_xmr_row_actions threw: ' . $e->getMessage() );
	}
	return $actions;
}

/**
 * WooCommerce's orders-list JS binds a click handler to every
 * `.wc-action-button` element (the little row-action icons) to drive the
 * built-in status buttons ("Processing", "Complete", ...) via AJAX. For any
 * CUSTOM action it still calls preventDefault() and then does nothing -
 * which is exactly why our "Mark XMR paid" row action renders like a link
 * but appears completely dead when clicked. We re-bind it here so the
 * nonce-protected admin-post URL is actually followed.
 */
add_action( 'admin_footer', function() {
	try {
		if ( ! is_admin() ) return;
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen ) return;
		$is_orders_screen = in_array( $screen->id, array( 'edit-shop_order', 'woocommerce_page_wc-orders' ), true );
		if ( ! $is_orders_screen ) return;
		?>
		<script>
		/**
		 * WooCommerce's own JS binds a click handler to every
		 * `.wc-action-button` element that calls preventDefault() for
		 * ALL actions - including custom ones like ours - which makes
		 * the "Mark XMR paid" row action appear completely dead.
		 *
		 * We intercept the click in the CAPTURING phase (before any
		 * bubbling-phase jQuery handler can run) using native
		 * addEventListener. This is the only reliable way to beat
		 * WooCommerce's handler regardless of binding order, since
		 * capturing-phase listeners always fire first.
		 *
		 * Match BOTH the dash-form class WooCommerce emits from the
		 * 'action' key (wc-xmr-paid) and the underscore form emitted from
		 * the array key (wc_xmr_paid) - older/newer WC versions differ.
		 * No one-shot guard: every click must navigate, or an interrupted
		 * first click would permanently kill the action.
		 */
		(function(){
			document.addEventListener( 'click', function( e ) {
				var link = e.target.closest( 'a.wc-action-button-wc-xmr-paid, a.wc-action-button-wc_xmr_paid' );
				if ( ! link ) return;
				e.stopImmediatePropagation();
				e.preventDefault();
				window.location.assign( link.getAttribute( 'href' ) );
			}, true ); // capture phase - fires before any bubbling handler
		})();
		</script>
		<?php
	} catch ( Throwable $e ) {
		error_log( 'WC XMR: admin_footer row-action JS threw: ' . $e->getMessage() );
	}
}, 99 );

add_action( 'admin_post_wc_xmr_mark_paid', 'wc_xmr_do_mark_paid' );
function wc_xmr_do_mark_paid() {
	try {
		// Support both GET (orders-list row action) and POST (meta box form).
		$order_id = isset( $_POST['order_id'] ) ? absint( $_POST['order_id'] ) : ( isset( $_GET['order_id'] ) ? absint( $_GET['order_id'] ) : 0 );
		if ( ! $order_id || ! current_user_can( 'edit_shop_orders' ) ) wp_die( 'no' );
		check_admin_referer( 'wc_xmr_mark_paid_' . $order_id );

		try { $order = wc_get_order( $order_id ); } catch ( Throwable $e ) { error_log( 'WC XMR: wc_get_order threw in mark_paid for #' . $order_id . ': ' . $e->getMessage() ); wp_die( 'Failed to load order.' ); }
		if ( $order ) {
			try { $order->add_order_note( __( 'XMR payment confirmed manually.', 'wc-xmr' ) ); } catch ( Throwable $e ) { error_log( 'WC XMR: add_order_note threw in mark_paid: ' . $e->getMessage() ); }
			try { $paid = $order->payment_complete(); } catch ( Throwable $e ) { error_log( 'WC XMR: payment_complete threw in mark_paid for #' . $order_id . ': ' . $e->getMessage() ); $paid = false; }
			if ( ! $paid ) {
				// payment_complete() returned false (e.g. order not in a
				// payable state, or WC considered there was nothing to
				// transition). Never leave the click as a silent no-op:
				// force the order to Processing so the admin sees a result.
				try {
					$recheck = wc_get_order( $order_id );
					if ( $recheck && in_array( $recheck->get_status(), array( 'on-hold', 'pending', 'failed' ), true ) ) {
						$recheck->update_status( 'processing', __( 'XMR payment confirmed manually (fallback).', 'wc-xmr' ) );
					}
				} catch ( Throwable $e ) { error_log( 'WC XMR: mark_paid fallback update_status threw for #' . $order_id . ': ' . $e->getMessage() ); }
				try { $order->add_order_note( 'payment_complete() returned false - fell back to manual status change.' ); } catch ( Throwable $e ) { error_log( 'WC XMR: add_order_note (payment_complete false) threw: ' . $e->getMessage() ); }
			}
			global $wpdb;
			$affected = $wpdb->query( $wpdb->prepare(
				"UPDATE {$wpdb->prefix}wc_xmr_reservations SET status = 'paid' WHERE order_id = %d AND status IN ('reserved','detected')",
				$order_id
			) );
			if ( $affected === false ) error_log( sprintf( 'WC XMR: Mark paid - DB update failed for order #%d: %s', $order_id, $wpdb->last_error ) );
		} else {
			error_log( sprintf( 'WC XMR: Mark paid - order #%d not found.', $order_id ) );
		}
		wp_safe_redirect( wp_get_referer() ?: admin_url( 'admin.php?page=wc-orders' ) );
		exit;
	} catch ( Throwable $e ) {
		error_log( 'WC XMR: wc_xmr_do_mark_paid crashed: ' . $e->getMessage() );
		wp_die( 'Mark paid failed: ' . esc_html( $e->getMessage() ) );
	}
}

add_action( 'add_meta_boxes', function() {
	try {
		$screens = array( 'shop_order' );
		if ( function_exists( 'wc_get_page_screen_id' ) ) {
			try { $screens[] = wc_get_page_screen_id( 'shop-order' ); } catch ( Throwable $e ) { error_log( 'WC XMR: wc_get_page_screen_id threw: ' . $e->getMessage() ); }
		}
		foreach ( array_unique( array_filter( $screens ) ) as $s ) {
			add_meta_box( 'wc_xmr_meta', __( 'Monero', 'wc-xmr' ), 'wc_xmr_meta_box', $s, 'side', 'default' );
		}
	} catch ( Throwable $e ) {
		error_log( 'WC XMR: add_meta_boxes hook threw: ' . $e->getMessage() );
	}
});

function wc_xmr_meta_box( $post_or_order ) {
	try {
		$order = ( $post_or_order instanceof WP_Post ) ? wc_get_order( $post_or_order->ID ) : $post_or_order;
	} catch ( Throwable $e ) { error_log( 'WC XMR: wc_get_order threw in meta_box: ' . $e->getMessage() ); echo '<p style="color:#b71c1c;">Error loading order.</p>'; return; }
	if ( ! $order || ! $order instanceof WC_Order || $order->get_payment_method() !== 'monero' ) {
		echo '<p style="color:#999;">Not XMR.</p>'; return;
	}
	try {
		$addr = $order->get_meta( '_xmr_address' );
		$amt  = $order->get_meta( '_xmr_amount' );
		$min  = $order->get_meta( '_xmr_min_amount' );
		$exp  = $order->get_meta( '_xmr_expires_at' );
		$txs_raw = $order->get_meta( '_xmr_tx_hashes' );
	} catch ( Throwable $e ) { error_log( 'WC XMR: get_meta threw in meta_box for order #' . $order->get_id() . ': ' . $e->getMessage() ); echo '<p style="color:#b71c1c;">Error loading order meta.</p>'; return; }
	$txs  = array_filter( explode( ',', (string) $txs_raw ) );

	echo '<p><strong>Address:</strong><br><code style="word-break:break-all;font-size:11px;">' . esc_html( $addr ?: '-' ) . '</code></p>';
	echo '<p><strong>Amount:</strong> ' . esc_html( $amt !== '' && $amt !== null ? $amt . ' XMR' : '-' ) . '</p>';
	echo '<p><strong>Min OK:</strong> ' . esc_html( $min !== '' && $min !== null ? $min . ' XMR' : '-' ) . '</p>';
	echo '<p><strong>Expires:</strong> ' . esc_html( $exp ?: '-' ) . '</p>';
	if ( $txs ) {
		echo '<p><strong>Tx:</strong><br>';
		foreach ( $txs as $tx ) {
			try { $links = function_exists( 'wc_xmr_explorer_links' ) ? wc_xmr_explorer_links( $tx ) : array(); } catch ( Throwable $e ) { $links = array(); error_log( 'WC XMR: wc_xmr_explorer_links threw in meta_box: ' . $e->getMessage() ); }
			$short = esc_html( substr( (string) $tx, 0, 10 ) . '...' );
			if ( $links && is_array( $links ) ) {
				echo '<code style="font-size:11px;" title="' . esc_attr( $tx ) . '">' . $short . '</code> ';
				foreach ( $links as $l ) {
					if ( ! is_array( $l ) || empty( $l['url'] ) ) continue;
					echo '<a href="' . esc_url( $l['url'] ) . '" target="_blank" rel="noopener noreferrer" style="font-size:11px;">' . esc_html( $l['label'] ?? 'View' ) . ' </a> ';
				}
				echo '<br>';
			} else {
				echo '<code style="font-size:11px;" title="' . esc_attr( $tx ) . '">' . $short . '</code><br>';
			}
		}
		echo '</p>';
	}

	global $wpdb;
	try {
		$row = $wpdb->get_row( $wpdb->prepare(
			"SELECT status FROM {$wpdb->prefix}wc_xmr_reservations WHERE order_id = %d",
			$order->get_id()
		) );
		if ( $wpdb->last_error ) error_log( 'WC XMR: meta_box get_row failed for order #' . $order->get_id() . ': ' . $wpdb->last_error );
	} catch ( Throwable $e ) { error_log( 'WC XMR: get_row threw in meta_box: ' . $e->getMessage() ); $row = null; }
	if ( $row ) {
		echo '<p><strong>Reservation:</strong> ' . esc_html( $row->status ) . '</p>';
		if ( $row->status === 'reserved' ) {
			// Real form submission - cannot be hijacked/preventDefault'd by
			// any JS. The row action icons need a capture-phase re-bind (see
			// admin_footer above) because WC's list JS swallows custom action
			// clicks, but a plain form always works on the order page.
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="margin-top:8px;">';
			echo '<input type="hidden" name="action" value="wc_xmr_release">';
			echo '<input type="hidden" name="order_id" value="' . esc_attr( (string) $order->get_id() ) . '">';
			wp_nonce_field( 'wc_xmr_release_' . $order->get_id() );
			echo '<button type="submit" class="button" onclick="return confirm(\'Release address back to pool?\');">Release reservation</button>';
			echo '</form>';
		}
	}

	if ( $order->get_status() === 'on-hold' ) {
		// Real form submission - guaranteed to work even if some JS calls
		// preventDefault() on plain anchors in the meta box.
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="margin-top:8px;">';
		echo '<input type="hidden" name="action" value="wc_xmr_mark_paid">';
		echo '<input type="hidden" name="order_id" value="' . esc_attr( (string) $order->get_id() ) . '">';
		wp_nonce_field( 'wc_xmr_mark_paid_' . $order->get_id() );
		echo '<button type="submit" class="button button-primary">Confirm order - Mark XMR paid</button>';
		echo '</form>';
	}
}

add_action( 'admin_post_wc_xmr_release', 'wc_xmr_do_release' );
function wc_xmr_do_release() {
	try {
		// Support both GET (legacy links) and POST (meta box form).
		$order_id = isset( $_POST['order_id'] ) ? absint( $_POST['order_id'] ) : ( isset( $_GET['order_id'] ) ? absint( $_GET['order_id'] ) : 0 );
		if ( ! $order_id || ! current_user_can( 'edit_shop_orders' ) ) wp_die( 'no' );
		check_admin_referer( 'wc_xmr_release_' . $order_id );

		global $wpdb;
		$affected = $wpdb->query( $wpdb->prepare(
			"UPDATE {$wpdb->prefix}wc_xmr_reservations SET status = 'released' WHERE order_id = %d AND status IN ('reserved','detected')",
			$order_id
		) );
		if ( $affected === false ) error_log( sprintf( 'WC XMR: Release - DB update failed for order #%d: %s', $order_id, $wpdb->last_error ) );
		try { $order = wc_get_order( $order_id ); } catch ( Throwable $e ) { error_log( 'WC XMR: wc_get_order threw in do_release for #' . $order_id . ': ' . $e->getMessage() ); $order = null; }
		if ( $order ) { try { $order->add_order_note( __( 'XMR reservation released manually. Address back in pool.', 'wc-xmr' ) ); } catch ( Throwable $e ) { error_log( 'WC XMR: add_order_note threw in do_release: ' . $e->getMessage() ); } }

		wp_safe_redirect( wp_get_referer() ?: admin_url( 'admin.php?page=wc-orders' ) );
		exit;
	} catch ( Throwable $e ) {
		error_log( 'WC XMR: wc_xmr_do_release crashed: ' . $e->getMessage() );
		wp_die( 'Release failed: ' . esc_html( $e->getMessage() ) );
	}
}
