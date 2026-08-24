<?php
/**
 * Plugin Name: Monero Push Companion
 * Description: Receives confirmation pushes and address submissions from a remote monero-wallet-rpc device. Companion to WooCommerce Monero Gateway.
 * Version: 1.0.0
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Author:      WC Monero Suite contributors
 * License:     GPL-2.0-or-later
 * Text Domain: wc-xmr-push
 */

if ( ! defined( 'ABSPATH' ) ) exit;

define( 'WC_XMR_PUSH_PLUGIN_FILE', __FILE__ );
define( 'WC_XMR_PUSH_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'WC_XMR_PUSH_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

require_once WC_XMR_PUSH_PLUGIN_DIR . 'class-wc-xmr-push-crypto.php';
require_once WC_XMR_PUSH_PLUGIN_DIR . 'class-wc-xmr-push-sig.php';
require_once WC_XMR_PUSH_PLUGIN_DIR . 'class-wc-xmr-push-pairing.php';
require_once WC_XMR_PUSH_PLUGIN_DIR . 'class-wc-xmr-push-audit.php';
require_once WC_XMR_PUSH_PLUGIN_DIR . 'class-wc-xmr-push-endpoint.php';

function wc_xmr_push_can_manage() {
	return current_user_can( 'manage_woocommerce' ) || current_user_can( 'manage_options' );
}

add_action( 'admin_notices', 'wc_xmr_push_dependency_notices' );
function wc_xmr_push_dependency_notices() {
	if ( ! wc_xmr_push_can_manage() ) return;

	if ( ! WC_XMR_Push_Crypto::available() ) {
		echo '<div class="notice notice-error"><p><strong>Monero Push Companion:</strong> The PHP sodium extension is required (libsodium / sodium_crypto_secretbox). This extension is bundled with PHP 7.2+ but may be disabled on some hosts. Contact your host to enable it, or switch to a host that includes it.</p></div>';
	}
	if ( ! class_exists( 'WC_Payment_Gateway' ) ) {
		echo '<div class="notice notice-warning"><p><strong>Monero Push Companion:</strong> WooCommerce must be active for the gateway integration - but Push settings are still available below under <em>Settings → Monero Push</em>.</p></div>';
	}
	if ( ! function_exists( 'wc_xmr_gw' ) ) {
		echo '<div class="notice notice-warning"><p><strong>Monero Push Companion:</strong> The WooCommerce Monero Gateway plugin must be installed and active for address injection - Push endpoint still works standalone.</p></div>';
	}
}

add_action( 'plugins_loaded', 'wc_xmr_push_init', 20 );
function wc_xmr_push_init() {
	add_action( 'admin_menu', 'wc_xmr_push_add_settings_page' );
	add_action( 'admin_init', 'wc_xmr_push_register_settings' );

	$missing = array();
	if ( ! WC_XMR_Push_Crypto::available() ) $missing[] = 'sodium';
	if ( ! class_exists( 'WC_Payment_Gateway' ) ) $missing[] = 'WooCommerce';
	if ( ! function_exists( 'wc_xmr_gw' ) ) $missing[] = 'WC Monero Gateway';
	if ( $missing ) {
		error_log( 'WC XMR Push: endpoint/filter not fully initialised - missing: ' . implode( ', ', $missing ) . ' (settings page still available).' );
		if ( WC_XMR_Push_Crypto::available() ) {
			try { WC_XMR_Push_Endpoint::init(); } catch ( Throwable $e ) { error_log( 'WC XMR Push: WC_XMR_Push_Endpoint::init threw: ' . $e->getMessage() ); }
		}
		return;
	}

	add_filter( 'wc_xmr_manual_address_pool', 'wc_xmr_push_inject_addresses', 10, 3 );

	try { WC_XMR_Push_Endpoint::init(); } catch ( Throwable $e ) { error_log( 'WC XMR Push: WC_XMR_Push_Endpoint::init threw: ' . $e->getMessage() ); }
}

function wc_xmr_push_add_settings_page() {
	add_options_page(
		'Monero Push',
		'Monero Push',
		'manage_options',
		'wc-xmr-push',
		'wc_xmr_push_settings_page_html'
	);
}

add_action( 'admin_head', 'wc_xmr_push_admin_head' );
function wc_xmr_push_admin_head() {
	if ( ! function_exists( 'get_current_screen' ) ) return;
	$screen = get_current_screen();
	if ( ! $screen || $screen->id !== 'settings_page_wc-xmr-push' ) return;
	?>
	<style>
	.wc-xmr-status-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:12px; margin:16px 0; }
	.wc-xmr-status-card { background:#fff; border:1px solid #c3c4c7; border-radius:4px; padding:12px 14px; box-shadow:0 1px 1px rgba(0,0,0,.04); border-top:3px solid #c3c4c7; }
	.wc-xmr-status-card.is-ok    { border-top-color:#00a32a; }
	.wc-xmr-status-card.is-bad   { border-top-color:#d63638; }
	.wc-xmr-status-card.is-warn  { border-top-color:#dba617; }
	.wc-xmr-status-label  { font-size:11px; text-transform:uppercase; letter-spacing:.4px; color:#646970; margin-bottom:4px; }
	.wc-xmr-status-value  { font-size:14px; font-weight:600; color:#1d2327; margin-bottom:4px; }
	.wc-xmr-status-detail { font-size:12px; color:#646970; }
	.wc-xmr-collapsible { background:#fff; border:1px solid #c3c4c7; border-radius:4px; margin:12px 0; box-shadow:0 1px 1px rgba(0,0,0,.04); }
	.wc-xmr-collapsible > summary { cursor:pointer; padding:12px 16px; list-style:none; display:flex; align-items:center; gap:10px; flex-wrap:wrap; user-select:none; }
	.wc-xmr-collapsible > summary::-webkit-details-marker { display:none; }
	.wc-xmr-collapsible > summary:hover { background:#f6f7f7; }
	.wc-xmr-caret { display:inline-block; width:0; height:0; border-left:6px solid #787c82; border-top:5px solid transparent; border-bottom:5px solid transparent; transition:transform .15s ease; flex:0 0 auto; }
	.wc-xmr-collapsible[open] > summary .wc-xmr-caret { transform:rotate(90deg); }
	.wc-xmr-summary-title { font-size:14px; font-weight:600; color:#1d2327; }
	.wc-xmr-summary-desc { font-size:12px; color:#646970; margin-left:auto; text-align:right; }
	.wc-xmr-collapsible-body { padding: 16px; border-top:1px solid #f0f0f1; }
	@media (max-width:782px){ .wc-xmr-summary-desc { display:none; } }
	</style>
	<script>
	(function(){
		try {
			var KEY = 'wc_xmr_collapsed_';
			document.querySelectorAll('.wc-xmr-collapsible').forEach(function(d){
				if (!d.id) return;
				if (localStorage.getItem(KEY + d.id) === '1') d.removeAttribute('open');
			});
			document.querySelectorAll('.wc-xmr-collapsible > summary').forEach(function(s){
				s.addEventListener('toggle', function(){
					var d = s.parentElement;
					if (!d.id) return;
					if (d.open) localStorage.removeItem(KEY + d.id);
					else localStorage.setItem(KEY + d.id, '1');
				});
			});
		} catch(e){}
	})();
	</script>
	<?php
}

function wc_xmr_push_register_settings() {
	register_setting( 'wc_xmr_push', 'wc_xmr_push_secret', array(
		'sanitize_callback' => 'wc_xmr_push_sanitize_secret',
		'default'           => '',
	) );
	register_setting( 'wc_xmr_push', 'wc_xmr_push_post_field', array(
		'sanitize_callback' => 'sanitize_text_field',
		'default'           => 'msg',
	) );
	register_setting( 'wc_xmr_push', 'wc_xmr_push_status_param', array(
		'sanitize_callback' => 'sanitize_text_field',
		'default'           => 't',
	) );
	register_setting( 'wc_xmr_push', 'wc_xmr_push_debug_log_enabled', array(
		'sanitize_callback' => function( $v ) { return $v === 'yes' ? 'yes' : 'no'; },
		'default'           => 'no',
	) );

	add_settings_section(
		'wc_xmr_push_main',
		'Shared secret &amp; endpoint configuration',
		'__return_empty_string',
		'wc-xmr-push'
	);

	add_settings_section(
		'wc_xmr_push_phones',
		'Authorized devices (Ed25519)',
		'wc_xmr_push_phones_section_html',
		'wc-xmr-push'
	);
	add_settings_field(
		'wc_xmr_push_phones_list',
		'Authorized devices',
		'wc_xmr_push_phones_field_html',
		'wc-xmr-push',
		'wc_xmr_push_phones'
	);

	add_settings_field(
		'wc_xmr_push_secret',
		'Shared secret (hex)',
		'wc_xmr_push_secret_field_html',
		'wc-xmr-push',
		'wc_xmr_push_main'
	);
	add_settings_field(
		'wc_xmr_push_post_field',
		'POST field name',
		'wc_xmr_push_post_field_html',
		'wc-xmr-push',
		'wc_xmr_push_main'
	);
	add_settings_field(
		'wc_xmr_push_status_param',
		'Status query param',
		'wc_xmr_push_status_param_html',
		'wc-xmr-push',
		'wc_xmr_push_main'
	);
	add_settings_field(
		'wc_xmr_push_debug_log_enabled',
		'Debug logging',
		'wc_xmr_push_debug_log_field_html',
		'wc-xmr-push',
		'wc_xmr_push_main'
	);
}

function wc_xmr_push_sanitize_secret( $value ) {
	try {
		$value = trim( (string) $value );
		if ( $value === '' ) return $value;
		$bin = @hex2bin( $value );
		if ( ! $bin || strlen( $bin ) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES ) {
			add_settings_error( 'wc_xmr_push_secret', 'bad_secret',
				'Key must be 64 hex characters (32 bytes for sodium_secretbox). Use the Generate button.' );
			try { $old = get_option( 'wc_xmr_push_secret' ); } catch ( Throwable $e ) { error_log( 'WC XMR Push: get_option wc_xmr_push_secret threw in sanitize: ' . $e->getMessage() ); $old = ''; }
			return is_string( $old ) ? $old : '';
		}
		if ( class_exists( 'WC_XMR_Crypto' ) && WC_XMR_Crypto::enabled() ) {
			try { $enc = WC_XMR_Crypto::encrypt( $value ); } catch ( Throwable $e ) { error_log( 'WC XMR Push: WC_XMR_Crypto::encrypt threw: ' . $e->getMessage() ); return $value; }
			if ( $enc === '' || $enc === false ) { error_log( 'WC XMR Push: WC_XMR_Crypto::encrypt returned empty/false - storing plaintext fail-open.' ); return $value; }
			return $enc;
		}
		return $value;
	} catch ( Throwable $e ) {
		error_log( 'WC XMR Push: wc_xmr_push_sanitize_secret crashed: ' . $e->getMessage() );
		return is_string( $value ) ? $value : '';
	}
}

function wc_xmr_push_get_secret_plain() {
	$raw = get_option( 'wc_xmr_push_secret', '' );
	if ( ! is_string( $raw ) || $raw === '' ) return '';
	if ( class_exists( 'WC_XMR_Crypto' ) && strpos( $raw, 'enc:v1:' ) === 0 ) {
		try { $decrypted = WC_XMR_Crypto::decrypt( $raw ); } catch ( Throwable $e ) { error_log( 'WC XMR Push: WC_XMR_Crypto::decrypt threw in get_secret_plain: ' . $e->getMessage() ); return $raw; }
		if ( $decrypted !== '' && $decrypted !== null ) return $decrypted;
		if ( get_transient( 'wc_xmr_enc_key_lost' ) ) return '';
	}
	return $raw;
}

function wc_xmr_push_secret_field_html() {
	$display = wc_xmr_push_get_secret_plain();
	if ( $display === '' ) {
		$raw_opt = get_option( 'wc_xmr_push_secret', '' );
		if ( $raw_opt !== '' && strpos( $raw_opt, 'enc:v1:' ) === 0 ) {
			echo '<p style="color:#b71c1c;"><strong>Stored secret is encrypted but cannot be decrypted</strong> - WC_XMR_ENC_KEY in wp-config.php is missing/changed. Re-generate and save a new key, then copy it to the device.</p>';
		}
	}
	$masked = ( $display && strlen( $display ) >= 12 )
		? substr( $display, 0, 8 ) . '...' . substr( $display, -4 )
		: ( $display ?: '(not set - click Generate then Save)' );
	$is_not_set = ( $display === '' );
	?>
	<input type="hidden" id="wc_xmr_push_secret" name="wc_xmr_push_secret"
		value="<?php echo esc_attr( $display ); ?>" autocomplete="off">
	<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px;">
		<code style="font-size:13px;max-width:520px;word-break:break-all;" id="wc-xmr-push-secret-display"><?php echo esc_html( $is_not_set ? $masked : $masked ); ?></code>
		<button type="button" class="button" id="wc-xmr-push-gen-key">Generate new key</button>
		<button type="button" class="button" id="wc-xmr-push-show-key" style="margin-left:0;"><?php echo $display ? 'Reveal' : 'Reveal'; ?></button>
		<button type="button" class="button" id="wc-xmr-push-copy-key" style="display:<?php echo $display ? 'inline-block' : 'none'; ?>;">Copy</button>
		<span id="wc-xmr-copy-ok" style="color:#2e7d32;font-size:12px;display:none;">Copied!</span>
	</div>
	<div id="wc-xmr-secret-full" style="display:none;margin:8px 0;">
		<input type="text" readonly id="wc-xmr-secret-full-input" value="<?php echo esc_attr( $display ); ?>" style="width:100%;max-width:620px;font-family:monospace;font-size:12px;padding:6px;" placeholder="64 hex chars - Generate then Save">
		<p class="description" style="margin-top:4px;"><strong>Local testing:</strong> copy this 64-char hex value into <code>daemon/xmr-pushd.conf</code> → <code>"shared_secret_hex"</code> and into the daemon config. Click <em>Save Changes</em> below to persist before testing.</p>
	</div>
	<p class="description">Anyone with this key can push confirmations and addresses - keep it secret. <strong>Most important for local testing:</strong> click <em>Generate</em> → <em>Save Changes</em>, then copy the revealed value to your <code>xmr-pushd.conf</code>.</p>
	<?php if ( $is_not_set ) : ?>
	<p style="color:#e65100;font-size:12px;">No secret set - endpoint will reject all pushes (decrypt_fail) until you generate and save one.</p>
	<?php endif; ?>
	<script>
	(function(){
		var field = document.getElementById('wc_xmr_push_secret');
		var display = document.getElementById('wc-xmr-push-secret-display');
		var fullWrap = document.getElementById('wc-xmr-secret-full');
		var fullInput = document.getElementById('wc-xmr-secret-full-input');
		var genBtn = document.getElementById('wc-xmr-push-gen-key');
		var showBtn = document.getElementById('wc-xmr-push-show-key');
		var copyBtn = document.getElementById('wc-xmr-push-copy-key');
		var copyOk = document.getElementById('wc-xmr-copy-ok');
		var revealed = false;

		function mask(v) {
			if (!v || v.length < 12) return v || '(not set - click Generate then Save)';
			return v.slice(0, 8) + '\u2026' + v.slice(-4);
		}
		function sync() {
			display.textContent = revealed ? (field.value || '(not set)') : mask(field.value);
			fullInput.value = field.value;
			fullWrap.style.display = revealed ? 'block' : 'none';
			showBtn.textContent = revealed ? 'Hide' : 'Reveal';
			copyBtn.style.display = field.value ? 'inline-block' : 'none';
		}
		genBtn.addEventListener('click', function(){
			var arr = new Uint8Array(32);
			crypto.getRandomValues(arr);
			var hex = Array.from(arr).map(function(b){ return ('0' + b.toString(16)).slice(-2); }).join('');
			field.value = hex;
			revealed = true;
			sync();
			if (!showBtn.textContent) showBtn.textContent = 'Hide';
		});
		showBtn.addEventListener('click', function(){
			revealed = !revealed;
			sync();
		});
		copyBtn.addEventListener('click', function(){
			var v = field.value;
			if (!v) return;
			if (navigator.clipboard && window.isSecureContext) {
				navigator.clipboard.writeText(v).then(function(){
					copyOk.style.display='inline'; setTimeout(function(){copyOk.style.display='none';},1500);
				});
			} else {
				fullInput.focus(); fullInput.select();
				try { document.execCommand('copy'); copyOk.style.display='inline'; setTimeout(function(){copyOk.style.display='none';},1500); } catch(e){}
			}
		});
		fullInput.addEventListener('focus', function(){ fullInput.select(); });
	})();
	</script>
	<?php
}

function wc_xmr_push_post_field_html() {
	$v = get_option( 'wc_xmr_push_post_field', 'msg' );
	echo '<input type="text" name="wc_xmr_push_post_field" value="' . esc_attr( $v ) . '" class="regular-text">';
	echo '<p class="description">The POST field name the device uses when pushing data. Use something mundane (e.g. <code>msg</code>, <code>comment</code>, <code>body</code>) so the traffic doesn\'t look like a payment API.</p>';
}

function wc_xmr_push_status_param_html() {
	$v = get_option( 'wc_xmr_push_status_param', 't' );
	echo '<input type="text" name="wc_xmr_push_status_param" value="' . esc_attr( $v ) . '" class="regular-text">';
	echo '<p class="description">The query parameter the device uses when requesting pool status. Use something short and generic (e.g. <code>t</code>, <code>ref</code>, <code>id</code>).</p>';
}

function wc_xmr_push_debug_log_field_html() {
	$v = get_option( 'wc_xmr_push_debug_log_enabled', 'no' );
	$clear_url = wp_nonce_url( add_query_arg( 'wc_xmr_push_clear_log', '1' ), 'wc_xmr_push_clear_log' );
	echo '<label><input type="checkbox" name="wc_xmr_push_debug_log_enabled" value="yes" ' . checked( $v, 'yes', false ) . '> ';
	echo 'Record every push and status request for debugging (last 200 entries). <a href="' . esc_url( $clear_url ) . '" style="margin-left:12px;color:#b32d2e;" onclick="return confirm(\'Clear the debug log?\');">Clear log now</a></label>';
}

function wc_xmr_push_phones_section_html() {
	echo '<p>Devices prove their identity with Ed25519 signatures. Paste a device\'s public key (shown during pairing or via <code>python3 xmr-pushd.py --show-pubkey</code>) to authorize it. When any device is authorized, unsigned pushes are rejected. Funding-critical pushes (confirmations, addresses) from unknown keys are rejected.</p>';
	if ( isset( $_GET['wc_xmr_push_msg'] ) ) {
		$m = sanitize_text_field( wp_unslash( $_GET['wc_xmr_push_msg'] ) );
		if ( $m === 'phone_added' ) echo '<div class="notice notice-success inline"><p>Device authorized.</p></div>';
		if ( $m === 'phone_removed' ) echo '<div class="notice notice-success inline"><p>Device removed.</p></div>';
		if ( $m === 'phone_exists' ) echo '<div class="notice notice-info inline"><p>That device was already authorized.</p></div>';
	}
	if ( isset( $_GET['wc_xmr_push_err'] ) ) {
		echo '<div class="notice notice-error inline"><p>' . esc_html( sanitize_text_field( wp_unslash( $_GET['wc_xmr_push_err'] ) ) ) . '</p></div>';
	}
}
function wc_xmr_push_phones_field_html() {
	if ( ! class_exists( 'WC_XMR_Push_Sig' ) ) { echo '<p><em>Sig class not loaded.</em></p>'; return; }
	$phones = WC_XMR_Push_Sig::get_phones();
	echo '<div style="margin-bottom:10px;">';
	if ( empty( $phones ) ) {
		echo '<p style="color:#666;"><em>No devices authorized yet - all pushes accepted (legacy mode). Add your device\'s public key to require signatures.</em></p>';
	} else {
		echo '<table class="widefat striped" style="max-width:760px;"><thead><tr><th>Label</th><th>Public key (pk)</th><th>Added</th><th>Last seen</th><th></th></tr></thead><tbody>';
		foreach ( $phones as $pk => $row ) {
			$label = $row['label'] !== '' ? $row['label'] : '<em>-</em>';
			$added = $row['added'] ? human_time_diff( $row['added'] ) . ' ago' : '-';
			$seen  = $row['last_seen'] ? human_time_diff( $row['last_seen'] ) . ' ago' : 'never';
			$rm = wp_nonce_url( add_query_arg( array( 'wc_xmr_push_remove_phone' => $pk ) ), 'wc_xmr_push_remove_' . $pk );
			echo '<tr><td>' . esc_html( $label ) . '</td><td><code style="font-size:11px;word-break:break-all;">' . esc_html( substr( $pk, 0, 16 ) . '...' . substr( $pk, -8 ) ) . '</code><br><code style="font-size:10px;color:#666;">' . esc_html( $pk ) . '</code></td><td style="white-space:nowrap;">' . esc_html( $added ) . '</td><td style="white-space:nowrap;">' . esc_html( $seen ) . '</td><td><a href="' . esc_url( $rm ) . '" class="button button-small" onclick="return confirm(\'Remove this device? Its pushes will be rejected.\');">Remove</a></td></tr>';
		}
		echo '</tbody></table>';
	}
	echo '</div>';
	echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;">';
	echo '<input type="hidden" name="action" value="wc_xmr_push_add_phone">';
	echo wp_nonce_field( 'wc_xmr_push_add_phone', '_wpnonce', true, false );
	echo '<label>Public key (64 hex)<br><input type="text" name="wc_xmr_phone_pk" style="width:420px;font-family:monospace;font-size:11px;" placeholder="64 hex chars"></label>';
	echo '<label>Label (optional)<br><input type="text" name="wc_xmr_phone_label" style="width:180px;" placeholder="e.g. Alice\'s laptop"></label>';
	echo '<button type="submit" class="button button-primary">Authorize device</button>';
	echo '</form>';
	echo '<p class="description">Get the key from the device: <code>python3 xmr-pushd.py --show-pubkey</code> or scan the QR shown during first run/pairing. Multiple devices and multiple servers are supported - each server holds its own authorized list.</p>';

	// Insecure word-based pairing UI.
	wc_xmr_push_pairing_ui_html();
}

add_action( 'admin_post_wc_xmr_push_add_phone', function() {
	if ( ! wc_xmr_push_can_manage() ) wp_die( 'no' );
	check_admin_referer( 'wc_xmr_push_add_phone' );
	$pk = isset( $_POST['wc_xmr_phone_pk'] ) ? (string) wp_unslash( $_POST['wc_xmr_phone_pk'] ) : '';
	$label = isset( $_POST['wc_xmr_phone_label'] ) ? sanitize_text_field( wp_unslash( $_POST['wc_xmr_phone_label'] ) ) : '';
	$res = class_exists( 'WC_XMR_Push_Sig' ) ? WC_XMR_Push_Sig::add_phone( $pk, $label ) : new WP_Error( 'no_class', 'Sig class missing' );
	if ( is_wp_error( $res ) ) {
		wp_safe_redirect( add_query_arg( array( 'wc_xmr_push_err' => $res->get_error_message() ), admin_url( 'options-general.php?page=wc-xmr-push' ) ) ); exit;
	}
	$phones = class_exists( 'WC_XMR_Push_Sig' ) ? WC_XMR_Push_Sig::get_phones() : array();
	$msg = count( $phones ) === 1 && ! is_wp_error( $res ) ? 'phone_added' : 'phone_added';
	wp_safe_redirect( add_query_arg( array( 'wc_xmr_push_msg' => $msg ), admin_url( 'options-general.php?page=wc-xmr-push' ) ) ); exit;
});
add_action( 'admin_init', function() {
	try {
		if ( isset( $_GET['wc_xmr_push_remove_phone'] ) && wc_xmr_push_can_manage() ) {
			$pk = (string) wp_unslash( $_GET['wc_xmr_push_remove_phone'] );
			check_admin_referer( 'wc_xmr_push_remove_' . $pk );
			$res = class_exists( 'WC_XMR_Push_Sig' ) ? WC_XMR_Push_Sig::remove_phone( $pk ) : new WP_Error( 'no_class', 'Sig class missing' );
			if ( is_wp_error( $res ) ) {
				wp_safe_redirect( add_query_arg( array( 'wc_xmr_push_err' => $res->get_error_message() ), admin_url( 'options-general.php?page=wc-xmr-push' ) ) ); exit;
			}
			wp_safe_redirect( add_query_arg( array( 'wc_xmr_push_msg' => 'phone_removed' ), admin_url( 'options-general.php?page=wc-xmr-push' ) ) ); exit;
		}
	} catch ( Throwable $e ) { error_log( 'WC XMR Push: remove_phone handler threw: ' . $e->getMessage() ); wp_safe_redirect( admin_url( 'options-general.php?page=wc-xmr-push' ) ); exit; }
});

add_action( 'admin_init', function() {
	try {
		if ( isset( $_GET['wc_xmr_push_clear_log'] ) && wc_xmr_push_can_manage() ) {
			check_admin_referer( 'wc_xmr_push_clear_log' );
			try { WC_XMR_Push_Logger::clear(); } catch ( Throwable $e ) { error_log( 'WC XMR Push: clear log threw: ' . $e->getMessage() ); }
			wp_safe_redirect( remove_query_arg( array( 'wc_xmr_push_clear_log', '_wpnonce' ) ) );
			exit;
		}
		if ( isset( $_GET['wc_xmr_push_request_phone_log'] ) && wc_xmr_push_can_manage() ) {
			check_admin_referer( 'wc_xmr_push_request_phone_log' );
			$ok = set_transient( 'wc_xmr_push_request_phone_log', true, 15 * MINUTE_IN_SECONDS );
			if ( $ok === false ) error_log( 'WC XMR Push: set_transient wc_xmr_push_request_phone_log failed.' );
			try { delete_option( 'wc_xmr_push_phone_log' ); } catch ( Throwable $e ) { error_log( 'WC XMR Push: delete_option wc_xmr_push_phone_log threw: ' . $e->getMessage() ); }
			wp_safe_redirect( remove_query_arg( array( 'wc_xmr_push_request_phone_log', '_wpnonce' ) ) );
			exit;
		}
	} catch ( Throwable $e ) {
		error_log( 'WC XMR Push: admin_init handler crashed: ' . $e->getMessage() );
	}
});

function wc_xmr_push_pairing_payload( $phone_pk, $label = '' ) {
	$payload = array( 'pk' => strtolower( trim( (string) $phone_pk ) ), 'label' => (string) $label );
	return base64_encode( wp_json_encode( $payload ) );
}

function wc_xmr_push_settings_page_html() {
	if ( ! wc_xmr_push_can_manage() ) { echo '<div class="wrap"><p>You do not have permission to manage Monero Push settings.</p></div>'; return; }
	$secret_plain = wc_xmr_push_get_secret_plain();
	$secret_set = ( $secret_plain !== '' );
	$sodium_ok = WC_XMR_Push_Crypto::available();
	$woo_ok = class_exists( 'WC_Payment_Gateway' );
	$gw_ok = function_exists( 'wc_xmr_gw' );
	$all_ok = $sodium_ok && $woo_ok && $gw_ok && $secret_set;

	$entries           = WC_XMR_Push_Logger::get_entries();
	$debug_log_enabled = ( get_option( 'wc_xmr_push_debug_log_enabled', 'no' ) === 'yes' );

	$last_ip  = '';
	$last_ts  = 0;
	$counts   = array(
		'confirm' => 0, 'addresses' => 0, 'status' => 0, 'orphan' => 0,
		'addr_reject' => 0, 'phone_log' => 0,
		'no_crypto' => 0, 'bad_field' => 0, 'decrypt_fail' => 0,
		'bad_payload' => 0, 'bad_timestamp' => 0, 'bad_type' => 0,
		'encrypt_fail' => 0, 'bad_confirm' => 0, 'addr_empty' => 0,
		'no_update_fn' => 0, 'no_settings_fn' => 0, 'phone_log_empty' => 0,
	);
	foreach ( $entries as $e ) {
		$t = $e['type'] ?? '';
		if ( isset( $counts[ $t ] ) ) $counts[ $t ]++;
		if ( ! $last_ts ) { $last_ts = $e['t'] ?? 0; $last_ip = $e['ip'] ?? ''; }
	}

	$home = home_url( '/' );
	$post_field = get_option( 'wc_xmr_push_post_field', 'msg' );
	$status_param = get_option( 'wc_xmr_push_status_param', 't' );

	?>
	<div class="wrap">
		<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>

		<div class="wc-xmr-status-grid">
			<div class="wc-xmr-status-card <?php echo $sodium_ok ? 'is-ok' : 'is-bad'; ?>">
				<div class="wc-xmr-status-label">Sodium (libsodium)</div>
				<div class="wc-xmr-status-value"><?php echo $sodium_ok ? 'Available' : 'Missing'; ?></div>
				<div class="wc-xmr-status-detail"><?php echo $sodium_ok ? 'Encryption ready' : 'Enable the PHP sodium extension'; ?></div>
			</div>
			<div class="wc-xmr-status-card <?php echo $woo_ok ? 'is-ok' : 'is-bad'; ?>">
				<div class="wc-xmr-status-label">WooCommerce</div>
				<div class="wc-xmr-status-value"><?php echo $woo_ok ? 'Active' : 'Not active'; ?></div>
				<div class="wc-xmr-status-detail"><?php echo $woo_ok ? 'Checkout integration ready' : 'Required for gateway integration'; ?></div>
			</div>
			<div class="wc-xmr-status-card <?php echo $gw_ok ? 'is-ok' : 'is-warn'; ?>">
				<div class="wc-xmr-status-label">Monero Gateway</div>
				<div class="wc-xmr-status-value"><?php echo $gw_ok ? 'Active' : 'Not active'; ?></div>
				<div class="wc-xmr-status-detail"><?php echo $gw_ok ? 'Address injection enabled' : 'Endpoint still works standalone'; ?></div>
			</div>
			<div class="wc-xmr-status-card <?php echo $secret_set ? 'is-ok' : 'is-bad'; ?>">
				<div class="wc-xmr-status-label">Shared secret</div>
				<div class="wc-xmr-status-value"><?php echo $secret_set ? 'Set' : 'Not set'; ?></div>
				<div class="wc-xmr-status-detail"><?php echo $secret_set ? esc_html( substr($secret_plain,0,8).'...'.substr($secret_plain,-4) ) : 'Generate below and Save Changes'; ?></div>
			</div>
			<div class="wc-xmr-status-card is-neutral">
				<div class="wc-xmr-status-label">Endpoint URL</div>
				<div class="wc-xmr-status-value" style="word-break:break-all;"><?php echo esc_html( $home ); ?></div>
				<div class="wc-xmr-status-detail">POST field <code><?php echo esc_html($post_field); ?></code> · GET param <code><?php echo esc_html($status_param); ?></code></div>
			</div>
			<div class="wc-xmr-status-card <?php echo $all_ok ? 'is-ok' : ( $secret_set ? 'is-warn' : 'is-bad' ); ?>">
				<div class="wc-xmr-status-label">Overall</div>
				<div class="wc-xmr-status-value"><?php echo $all_ok ? 'Ready to receive pushes' : 'Needs attention'; ?></div>
				<div class="wc-xmr-status-detail"><?php echo $all_ok ? 'All systems go' : 'See cards above for details'; ?></div>
			</div>
		</div>

		<?php if ( ! $secret_set ) : ?>
			<div class="notice notice-error" style="margin:12px 0;"><p><strong>No shared secret set.</strong> Generate one below, Save Changes, then copy it to the device before anything will work. For local testing the secret is shown in full after you click Reveal.</p></div>
		<?php endif; ?>
		<?php settings_errors(); ?>

		<form method="post" action="options.php">
			<?php settings_fields( 'wc_xmr_push' ); ?>

			<details id="wc-xmr-core" open class="wc-xmr-collapsible">
				<summary>
					<span class="wc-xmr-caret" aria-hidden="true"></span>
					<span class="wc-xmr-summary-title"> Core configuration</span>
					<span class="wc-xmr-summary-desc">Shared secret, endpoint field names, debug toggle</span>
				</summary>
				<div class="wc-xmr-collapsible-body">
					<table class="form-table" role="presentation">
						<tr><th scope="row">Shared secret (hex)</th><td><?php wc_xmr_push_secret_field_html(); ?></td></tr>
						<tr><th scope="row">POST field name</th><td><?php wc_xmr_push_post_field_html(); ?></td></tr>
						<tr><th scope="row">Status query param</th><td><?php wc_xmr_push_status_param_html(); ?></td></tr>
						<tr><th scope="row">Debug logging</th><td><?php wc_xmr_push_debug_log_field_html(); ?></td></tr>
					</table>
					<?php submit_button(); ?>
				</div>
			</details>

			<details id="wc-xmr-phones" class="wc-xmr-collapsible">
				<summary>
					<span class="wc-xmr-caret" aria-hidden="true"></span>
					<span class="wc-xmr-summary-title"> Authorized devices & word pairing</span>
					<span class="wc-xmr-summary-desc">Ed25519 device identity, pairing sessions</span>
				</summary>
				<div class="wc-xmr-collapsible-body">
					<?php wc_xmr_push_phones_section_html(); ?>
					<?php wc_xmr_push_phones_field_html(); ?>
				</div>
			</details>
		</form>

		<details id="wc-xmr-setup" class="wc-xmr-collapsible">
			<summary>
				<span class="wc-xmr-caret" aria-hidden="true"></span>
				<span class="wc-xmr-summary-title"> Local testing quick start</span>
				<span class="wc-xmr-summary-desc">Get a secret onto a device in 4 steps</span>
			</summary>
			<div class="wc-xmr-collapsible-body">
				<ol style="margin:0 0 8px 18px;">
					<li>Set a secret: <em>Generate → Save Changes → Reveal → Copy</em> (full 64 hex chars now visible above).</li>
					<li>Paste into <code>daemon/xmr-pushd.conf</code>: <code>"shared_secret_hex": "PASTE_HERE"</code> and <code>"wp_url": "<?php echo esc_html($home); ?>"</code></li>
					<li>Enable debug logging (checkbox above → Save), then run the daemon: <code>python3 xmr-pushd.py --debug</code></li>
					<li>Test push: <code>curl -X POST -d "msg=$(python3 -c 'import base64,json,time; ...')"</code> or just let daemon poll. Check <em>Debug log</em> below - you should see <code>confirm</code>/<code>addresses</code> entries, not <code>decrypt_fail</code>.</li>
				</ol>
				<p style="margin:0;font-size:12px;color:#666;">Secret is also available via <code>wp option get wc_xmr_push_secret --format=json</code> (decrypt with <code>WC_XMR_Crypto</code> if it starts with <code>enc:v1:</code>) or directly on this page via Reveal.</p>
			</div>
		</details>

		<?php if ( $debug_log_enabled ) : ?>
		<details id="wc-xmr-debuglog" class="wc-xmr-collapsible" style="margin-top:24px;">
			<summary>
				<span class="wc-xmr-caret" aria-hidden="true"></span>
				<span class="wc-xmr-summary-title"> Debug log</span>
				<span class="wc-xmr-summary-desc"><?php echo esc_html( count( $entries ) ); ?> entries<?php echo $last_ts ? ' - last ' . esc_html( human_time_diff( $last_ts ) ) . ' ago' : ''; ?></span>
			</summary>
			<div class="wc-xmr-collapsible-body">
		<?php if ( $last_ts ) : ?>
			<p style="margin-bottom:8px;">
				<?php echo esc_html( count( $entries ) ); ?> entries ·
				Last activity: <?php echo esc_html( human_time_diff( $last_ts ) ); ?> ago
				from <code><?php echo esc_html( $last_ip ); ?></code>
			</p>
		<?php endif; ?>
		<p style="margin-bottom:12px;">
			<?php
			$badges = array(
				'confirm'       => '#2e7d32',
				'addresses'     => '#1565c0',
				'status'        => '#6a1b9a',
				'orphan'        => '#e65100',
				'addr_reject'   => '#b71c1c',
				'phone_log'     => '#00838f',
				'no_crypto'     => '#b71c1c',
				'bad_field'     => '#b71c1c',
				'decrypt_fail'  => '#b71c1c',
				'bad_payload'   => '#e65100',
				'bad_timestamp' => '#e65100',
				'bad_type'      => '#e65100',
				'encrypt_fail'  => '#b71c1c',
				'bad_confirm'   => '#e65100',
				'addr_empty'    => '#666',
				'no_update_fn'  => '#b71c1c',
				'no_settings_fn'=> '#b71c1c',
				'phone_log_empty'=> '#666',
			);
			$labels = array(
				'confirm'       => 'Confirmations',
				'addresses'     => 'Address batches',
				'status'        => 'Status checks',
				'orphan'        => 'Orphaned pushes',
				'addr_reject'   => 'Rejected addresses',
				'phone_log'     => 'Device log pushes',
				'no_crypto'     => 'Sodium missing',
				'bad_field'     => 'Bad POST field',
				'decrypt_fail'  => 'Decrypt failures',
				'bad_payload'   => 'Bad payloads',
				'bad_timestamp' => 'Bad timestamps',
				'bad_type'      => 'Unknown types',
				'encrypt_fail'  => 'Encrypt failures',
				'bad_confirm'   => 'Bad confirmations',
				'addr_empty'    => 'Empty address batches',
				'no_update_fn'  => 'No update_order fn',
				'no_settings_fn'=> 'No settings fn',
				'phone_log_empty'=> 'Empty device logs',
			);
			foreach ( $counts as $type => $n ) :
				if ( $n == 0 ) continue;
				$color = $badges[ $type ] ?? '#666';
				?>
				<span style="display:inline-block;background:<?php echo esc_attr( $color ); ?>;color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;margin-right:8px;margin-bottom:4px;">
					<?php echo esc_html( $n . ' ' . $labels[ $type ] ); ?>
				</span>
			<?php endforeach; ?>
		<?php if ( ! empty( $entries ) ) : ?>
			<?php $debug_clear_url = wp_nonce_url( add_query_arg( 'wc_xmr_push_clear_log', '1' ), 'wc_xmr_push_clear_log' ); ?>
			<a href="<?php echo esc_url( $debug_clear_url ); ?>" class="button button-small" style="vertical-align:middle;">Clear log</a>
		<?php endif; ?>
		</p>

		<?php if ( ! empty( $entries ) ) : ?>
		<table class="wp-list-table widefat fixed striped" style="max-width:100%;">
			<thead>
				<tr>
					<th style="width:130px;">Time</th>
					<th style="width:90px;">Type</th>
					<th style="width:120px;">IP</th>
					<th>Details</th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $entries as $e ) :
				$type  = $e['type'] ?? '?';
				$t_ago = human_time_diff( $e['t'] ?? 0 );
				$ip    = $e['ip'] ?? '?';
				$detail = '';
				switch ( $type ) {
					case 'confirm':
						$detail = sprintf( 'wallet %s idx %d → %.6f XMR, %d confs, %d tx(s), order #%d',
							$e['wallet'] ?? '?', $e['idx'] ?? 0,
							$e['recv'] ?? 0, $e['confs'] ?? 0,
							$e['txs'] ?? 0, $e['order'] ?? 0 );
						break;
					case 'addresses':
						$detail = sprintf( 'stored %d, rejected %d (%s)',
							$e['stored'] ?? 0, $e['rejected'] ?? 0, $e['net'] ?? '?' );
						break;
					case 'status':
						$detail = sprintf( 'free %d/%d, %d reserved%s',
							$e['free'] ?? 0, $e['total'] ?? 0, $e['reserved'] ?? 0,
							isset($e['active']) ? ', ' . $e['active'] . ' active indices' : '' );
						break;
					case 'orphan':
						$detail = sprintf( 'wallet %s idx %d - no reservation matched %.6f XMR/%d confs',
							$e['wallet'] ?? '?', $e['idx'] ?? 0,
							$e['recv'] ?? 0, $e['confs'] ?? 0 );
						break;
					case 'addr_reject':
						$detail = sprintf( 'all %d addresses failed %s validation',
							$e['total'] ?? 0, $e['net'] ?? '?' );
						break;
				case 'phone_log':
					$detail = sprintf( 'received %d log entries from wallet %s',
						$e['entries'] ?? 0, $e['wallet'] ?? '?' );
					break;
					case 'decrypt_fail':
						$detail = sprintf( 'path: %s%s', $e['path'] ?? '?', isset($e['len']) ? ', len: ' . $e['len'] : '' );
						break;
					case 'bad_payload':
						$detail = sprintf( 'path: %s, json: %s', $e['path'] ?? '?', $e['json_err'] ?? '?' );
						break;
					case 'bad_timestamp':
						$detail = sprintf( 'path: %s, ts: %s', $e['path'] ?? '?', $e['ts'] ?? '?' );
						break;
					case 'bad_type':
						$detail = sprintf( 'path: %s, type: %s', $e['path'] ?? '?', $e['type'] ?? '?' );
						break;
					case 'no_crypto':
					case 'encrypt_fail':
						$detail = sprintf( 'path: %s', $e['path'] ?? '?' );
						break;
					case 'bad_confirm':
						$detail = sprintf( 'wallet: %s, idx: %s', $e['wallet'] ?? '?', $e['idx'] ?? '?' );
						break;
					case 'addr_empty':
						$detail = sprintf( 'net: %s', $e['net'] ?? '?' );
						break;
					case 'bad_field':
						$detail = sprintf( 'type: %s', $e['type'] ?? '?' );
						break;
					case 'no_update_fn':
					case 'no_settings_fn':
						$detail = sprintf( 'wallet: %s, idx: %s', $e['wallet'] ?? '?', $e['idx'] ?? '?' );
						break;
					case 'phone_log_empty':
						$detail = 'empty entries array';
						break;
					default:
						$detail = json_encode( $e );
				}
				$color = $badges[ $type ] ?? '#666';
				?>
				<tr>
					<td style="font-size:12px;white-space:nowrap;"><?php echo esc_html( $t_ago ); ?> ago</td>
					<td><span style="background:<?php echo esc_attr( $color ); ?>;color:#fff;padding:1px 6px;border-radius:4px;font-size:11px;"><?php echo esc_html( $type ); ?></span></td>
					<td style="font-family:monospace;font-size:11px;"><?php echo esc_html( $ip ); ?></td>
					<td style="font-size:12px;"><?php echo esc_html( $detail ); ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
			<?php else : ?>
				<p style="color:#999;">No entries yet. Push traffic will appear here when debug logging is enabled.</p>
			<?php endif; ?>
			</div>
		</details>
		<?php endif; ?>

		<?php
		$phone_log = get_option( 'wc_xmr_push_phone_log', null );
		$log_requested = ( get_transient( 'wc_xmr_push_request_phone_log' ) !== false );
		?>
		<details id="wc-xmr-phonelog" class="wc-xmr-collapsible" style="margin-top:24px;">
			<summary>
				<span class="wc-xmr-caret" aria-hidden="true"></span>
				<span class="wc-xmr-summary-title"> Device debug log</span>
				<span class="wc-xmr-summary-desc">Remote daemon diagnostics<?php echo $log_requested ? ' - request queued' : ''; ?></span>
			</summary>
			<div class="wc-xmr-collapsible-body">
		<p style="margin-bottom:12px;">
			<a href="<?php echo esc_url( wp_nonce_url( add_query_arg( 'wc_xmr_push_request_phone_log', '1' ), 'wc_xmr_push_request_phone_log' ) ); ?>" class="button" style="margin-right:8px;">
				<?php echo $log_requested ? 'Request queued - waiting for device...' : 'Request device log'; ?>
			</a>
			<?php if ( $log_requested ) : ?>
				<span style="color:#e65100;">The device will push its log on the next status check. Refresh this page after the push arrives.</span>
			<?php endif; ?>
		</p>

		<?php if ( $phone_log && ! empty( $phone_log['entries'] ) ) : ?>
			<?php
			$p_entries = $phone_log['entries'];
			$p_entries = array_reverse( $p_entries );
			$p_when = human_time_diff( $phone_log['t'] ?? 0 );
			$p_wallet = $phone_log['wallet'] ?? '?';
			?>
			<p>
				<?php echo esc_html( count( $p_entries ) ); ?> entries from wallet <code><?php echo esc_html( $p_wallet ); ?></code> ·
				received <?php echo esc_html( $p_when ); ?> ago
			</p>
			<table class="wp-list-table widefat fixed striped" style="max-width:100%;">
				<thead>
					<tr>
						<th style="width:50px;">#</th>
						<th style="width:130px;">Time</th>
						<th style="width:50px;">Lvl</th>
						<th>Message</th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $p_entries as $i => $pe ) :
					$pe_t    = $pe['t'] ?? 0;
					$pe_lvl  = $pe['level'] ?? 'INFO';
					$pe_msg  = $pe['msg'] ?? '';
					$pe_data = $pe['d'] ?? null;
					$pe_color = $pe_lvl === 'ERROR' ? '#b71c1c' : ( $pe_lvl === 'WARN' ? '#e65100' : ( $pe_lvl === 'DEBUG' ? '#666' : '#333' ) );
					$pe_ago = $pe_t ? human_time_diff( $pe_t ) . ' ago' : '';
					?>
					<tr>
						<td style="font-size:11px;color:#999;"><?php echo esc_html( count( $p_entries ) - $i ); ?></td>
						<td style="font-size:11px;white-space:nowrap;"><?php echo esc_html( $pe_ago ); ?></td>
						<td><span style="color:<?php echo esc_attr( $pe_color ); ?>;font-weight:bold;font-size:11px;"><?php echo esc_html( $pe_lvl ); ?></span></td>
						<td style="font-size:12px;font-family:monospace;">
							<?php echo esc_html( $pe_msg ); ?>
							<?php if ( $pe_data ) : ?>
								<br><small style="color:#999;"><?php echo esc_html( is_array( $pe_data ) ? json_encode( $pe_data ) : (string) $pe_data ); ?></small>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
			<?php else : ?>
				<p style="color:#999;">No device log received yet. Click "Request device log" to queue a request - the device will push its log on the next status check.</p>
			<?php endif; ?>
			</div>
		</details>

		<details id="wc-xmr-ref" class="wc-xmr-collapsible" style="margin-top:24px;">
			<summary>
				<span class="wc-xmr-caret" aria-hidden="true"></span>
				<span class="wc-xmr-summary-title"> API reference & device instructions</span>
				<span class="wc-xmr-summary-desc">Payload formats, endpoints, timestamps</span>
			</summary>
			<div class="wc-xmr-collapsible-body">
		<p>The device (device, laptop, VPS or any host running monero-wallet-rpc) polls its own local wallet-rpc and pushes changes to this WordPress server.</p>

		<h3>Push receiver endpoint</h3>
		<p><strong>URL:</strong> <code><?php echo esc_html( home_url( '/' ) ); ?></code></p>
		<p><strong>Method:</strong> POST</p>
		<p><strong>Field:</strong> <code><?php echo esc_html( get_option( 'wc_xmr_push_post_field', 'msg' ) ); ?></code></p>
		<p>The device encrypts a JSON payload with the shared secret (sodium_secretbox) and sends it as a form field.</p>

		<h3>Status blob endpoint</h3>
		<p><strong>URL:</strong> <code><?php echo esc_html( home_url( '/' ) ); ?>?<?php echo esc_html( get_option( 'wc_xmr_push_status_param', 't' ) ); ?>=&lt;encrypted request&gt;</code></p>
		<p><strong>Method:</strong> GET</p>
		<p>The device sends an encrypted status request as a query parameter. The response is an encrypted status blob.</p>

		<h3>Confirmation push payload format</h3>
		<p>The device encrypts this JSON and sends it in the POST field:</p>
		<pre style="background:#f0f0f1;padding:12px;overflow:auto;">{
  "v": 1,
  "ts": &lt;unix seconds&gt;,
  "type": "confirmation",
  "wallet_id": "&lt;wallet id from main plugin config&gt;",
  "subaddress_index": &lt;integer&gt;,
  "received": &lt;float XMR&gt;,
  "confs": &lt;integer&gt;,
  "hashes": ["&lt;txid&gt;", ...]
}</pre>

		<h3>Address push payload format</h3>
		<p>Pushes a batch of pre-generated subaddresses. Replaces the previous batch for this network.</p>
		<pre style="background:#f0f0f1;padding:12px;overflow:auto;">{
  "v": 1,
  "ts": &lt;unix seconds&gt;,
  "type": "addresses",
  "network": "&lt;mainnet|testnet|stagenet&gt;",
  "addresses": [
    "&lt;address string&gt;",
    {"address": "&lt;address string&gt;", "exact_amount": &lt;float XMR&gt;},
    ...
  ]
}</pre>
		<p>Supports the concurrent-reuse format from the main plugin: plain strings for exclusive-use addresses, objects with <code>exact_amount</code> for addresses shared across multiple concurrent orders (disambiguated by amount).</p>

		<h3>Status request format</h3>
		<p>The device encrypts this JSON and sends it as the query parameter value:</p>
		<pre style="background:#f0f0f1;padding:12px;overflow:auto;">{
  "v": 1,
  "ts": &lt;unix seconds&gt;,
  "type": "status_request",
  "network": "&lt;mainnet|testnet|stagenet&gt;",
  "wallet_id": "&lt;optional wallet id&gt;"
}</pre>
		<p>The response is an encrypted JSON blob containing <code>pool_free</code>, <code>pool_total</code>, <code>reserved_count</code>, <code>detected_count</code>, and <code>burn_rate_24h</code>.</p>

		<h3>Timestamp tolerance</h3>
		<p>Payloads must have a <code>ts</code> field within &plusmn;5 minutes of server time. The device must keep its clock reasonably accurate (NTP).</p>
			</div>
		</details>
	</div>

	<script>
	(function() {
		'use strict';
		if (!window.localStorage) return;

		var LS_KEY = 'wc_xmr_push_page_state_v1';
		var POLL_MS = 8000;
		var nonce = '<?php echo esc_js( wp_create_nonce( 'wc_xmr_push_state_fingerprint' ) ); ?>';
		var ajaxUrl = '<?php echo esc_js( admin_url( 'admin-ajax.php' ) ); ?>';

		var lastFp = null;
		var reloading = false;
		var pendingReload = false;
		var formDirty = false;

		function saveState() {
			var st = { scrollY: window.scrollY, open: {} };
			var details = document.querySelectorAll('details.wc-xmr-collapsible');
			for (var i = 0; i < details.length; i++) {
				if (details[i].id) st.open[details[i].id] = details[i].open;
			}
			try { localStorage.setItem(LS_KEY, JSON.stringify(st)); } catch (e) {}
		}

		function restoreState() {
			var st = null;
			try { st = JSON.parse(localStorage.getItem(LS_KEY) || 'null'); } catch (e) { st = null; }
			var details = document.querySelectorAll('details.wc-xmr-collapsible');
			for (var i = 0; i < details.length; i++) {
				var id = details[i].id;
				if (!id) continue;
				// The admin_head script also persists collapsed state under
				// wc_xmr_collapsed_<id> - treat that as authoritative so both
				// mechanisms agree after a reload.
				var collapsed = null;
				try { collapsed = localStorage.getItem('wc_xmr_collapsed_' + id); } catch (e) {}
				if (collapsed === '1') {
					details[i].open = false;
				} else if (st && st.open && st.open.hasOwnProperty(id)) {
					details[i].open = !!st.open[id];
				}
			}
			if (st && typeof st.scrollY === 'number') {
				window.scrollTo(0, st.scrollY);
			}
		}

		function isBusy() {
			if (formDirty) return true;
			var el = document.activeElement;
			if (!el) return false;
			var tag = el.tagName;
			if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
			if (el.isContentEditable) return true;
			return false;
		}

		function fpKey(d) {
			return [
				'pair=' + (d.pair || 'none'),
				'pair_id=' + (d.pair_id || ''),
				'pair_bits=' + (d.pair_bits || 0),
				'pair_sas=' + (d.pair_sas || ''),
				'phones=' + (d.phones || 0),
				'log=' + (d.log_sig || ''),
				'phone=' + (d.phone_t || 0) + ',' + (d.phone_n || 0)
			].join('|');
		}

		function fetchFp(cb) {
			var xhr = new XMLHttpRequest();
			xhr.open('GET', ajaxUrl + '?action=wc_xmr_push_state_fingerprint&nonce=' + encodeURIComponent(nonce), true);
			xhr.timeout = 8000;
			xhr.onreadystatechange = function() {
				if (xhr.readyState !== 4) return;
				if (xhr.status !== 200) return;
				try {
					var j = JSON.parse(xhr.responseText);
					if (j && j.success) cb(j.data);
				} catch (e) {}
			};
			xhr.send();
		}

		function doReload() {
			if (reloading) return;
			reloading = true;
			saveState();
			location.reload();
		}

		function check() {
			if (reloading) return;
			fetchFp(function(data) {
				var fp = fpKey(data);
				if (lastFp === null) {
					lastFp = fp;
					return;
				}
				if (fp !== lastFp) {
					lastFp = fp;
					if (isBusy()) {
						pendingReload = true;
					} else {
						doReload();
					}
				}
			});
		}

		function onUserFree() {
			// Never reload while the user has unsaved form edits - that would
			// wipe their changes. If they've saved (or discarded) and a change
			// is still pending, reload then.
			if (pendingReload && !formDirty) {
				pendingReload = false;
				doReload();
			}
		}

		document.addEventListener('DOMContentLoaded', function() {
			restoreState();

			var form = document.querySelector('form[action="options.php"], form[action*="options.php"]');
			if (form) {
				form.addEventListener('input', function() { formDirty = true; });
				form.addEventListener('change', function() { formDirty = true; });
			}

			window.addEventListener('beforeunload', saveState);
			window.addEventListener('scroll', function() {
				clearTimeout(window.__wcXmrSaveT);
				window.__wcXmrSaveT = setTimeout(saveState, 250);
			}, { passive: true });
			document.addEventListener('toggle', function(e) {
				if (e.target && e.target.classList && e.target.classList.contains('wc-xmr-collapsible')) saveState();
			}, true);

			document.addEventListener('focusout', onUserFree, true);
			window.addEventListener('focus', function() { onUserFree(); check(); });
			document.addEventListener('visibilitychange', function() {
				if (document.visibilityState === 'visible') { onUserFree(); check(); }
			});

			check();
			setInterval(check, POLL_MS);
		});
	})();
	</script>
	<?php
}

function wc_xmr_push_inject_addresses( $pool, $network, $settings ) {
	if ( ! is_array( $pool ) ) { error_log( 'WC XMR Push: inject_addresses got non-array pool: ' . gettype( $pool ) ); return is_array( $pool ) ? $pool : array(); }
	if ( ! is_string( $network ) || $network === '' ) { error_log( 'WC XMR Push: inject_addresses got invalid network: ' . var_export( $network, true ) ); return $pool; }
	$key = 'wc_xmr_push_' . $network . '_addresses';
	try { $pushed = get_option( $key, array() ); } catch ( Throwable $e ) { error_log( 'WC XMR Push: get_option ' . $key . ' threw: ' . $e->getMessage() ); return $pool; }
	if ( ! is_array( $pushed ) ) { error_log( 'WC XMR Push: pushed addresses for ' . $network . ' is not an array: ' . gettype( $pushed ) ); return $pool; }
	if ( empty( $pushed ) ) return $pool;

	$merged = $pool;
	$skipped_unmatchable = 0;
	foreach ( $pushed as $entry ) {
		// Only serve pushed entries that carry wallet_id/account_index/
		// subaddress_index metadata. A bare entry (pushed before metadata
		// existed, or by a misconfigured device) yields a 'manual'/0
		// reservation that NO confirmation push can ever match - the
		// customer pays, the order silently never updates, and an orphan
		// alert fires. Declining checkout here is strictly better:
		// wc_xmr_pick_address()'s address_failover can rescue the sale,
		// and get_pool_stats() mirrors this exclusion so pool_free reads
		// low and the device re-pushes a metadata-bearing batch.
		if ( is_array( $entry ) && ! empty( $entry['address'] ) && isset( $entry['wallet_id'], $entry['subaddress_index'] ) ) {
			$merged[] = $entry;
		} else {
			$skipped_unmatchable++;
		}
	}

	if ( $skipped_unmatchable > 0 ) {
		error_log( "WC XMR Push: inject_addresses skipped {$skipped_unmatchable} pushed address(es) without wallet_id/subaddress_index metadata - they can never be matched to confirmation pushes." );
		if ( function_exists( 'wc_xmr_alert' ) ) {
			wc_xmr_alert( 'push_pool_unmatchable', sprintf(
				'%d pushed address(es) lack pairing metadata (wallet_id/subaddress_index) and were excluded from checkout. The device will re-push a fresh batch automatically; old checkouts served from these addresses must be resolved manually.',
				$skipped_unmatchable
			) );
		}
	}

	$seen = array();
	$deduped = array();
	foreach ( $merged as $entry ) {
		$addr = is_array( $entry ) ? ( $entry['address'] ?? '' ) : (string) $entry;
		if ( $addr === '' ) continue;
		$key2 = $addr;
		if ( is_array( $entry ) && isset( $entry['exact_amount'] ) ) {
			$key2 .= '|' . (string) $entry['exact_amount'];
		}
		if ( isset( $seen[ $key2 ] ) ) continue;
		$seen[ $key2 ] = true;
		$deduped[] = $entry;
	}

	return $deduped;
}

register_activation_hook( __FILE__, function() {
	if ( ! WC_XMR_Push_Crypto::available() ) {
		deactivate_plugins( plugin_basename( __FILE__ ) );
		wp_die(
			'The Monero Push Companion requires the PHP sodium extension (libsodium). This extension is bundled with PHP 7.2+. Please enable it on your server.',
			'Plugin dependency missing',
			array( 'back_link' => true )
		);
	}
	$existing = get_option( 'wc_xmr_push_secret', '' );
	if ( $existing === '' ) {
		try {
			$gen = WC_XMR_Push_Crypto::generate_key();
			if ( class_exists( 'WC_XMR_Crypto' ) && WC_XMR_Crypto::enabled() ) {
				$enc = WC_XMR_Crypto::encrypt( $gen );
				if ( $enc !== '' && $enc !== false ) $gen = $enc;
			}
			update_option( 'wc_xmr_push_secret', $gen, false );
		} catch ( Throwable $e ) { error_log( 'WC XMR Push: auto-generate secret on activation failed: ' . $e->getMessage() ); }
	}
});

register_deactivation_hook( __FILE__, function() {
	try { WC_XMR_Push_Crypto::clear_key_cache(); } catch ( Throwable $e ) { error_log( 'WC XMR Push: clear_key_cache threw on deactivation: ' . $e->getMessage() ); }
});

/**
 * Word-based pairing UI - shown on the settings page.
 */
function wc_xmr_push_pairing_ui_html() {
	if ( ! class_exists( 'WC_XMR_Push_Pairing' ) ) return;

	$sessions = WC_XMR_Push_Pairing::get_sessions();
	$active_session = null;
	foreach ( $sessions as $s ) {
		if ( in_array( $s['status'], array( 'waiting', 'sas_ready', 'claimed', 'rejected' ), true ) ) {
			$active_session = $s;
			break;
		}
	}

	// Check if any devices are authorized (for signing warning).
	$has_phones = class_exists( 'WC_XMR_Push_Sig' ) && WC_XMR_Push_Sig::has_any();
	$phones = $has_phones ? WC_XMR_Push_Sig::get_phones() : array();

	?>
	<div style="background:#fff;border:1px solid #ccd0d4;padding:16px 20px;margin:16px 0;max-width:760px;">
		<h3 style="margin:0 0 8px;"> Word-based pairing</h3>
		<p style="margin:0 0 12px;color:#555;font-size:13px;">
			Pair a remote device running <code>xmr-pushd.py</code> with this server. The device generates an Ed25519 keypair
			and exchanges it through an ECDH-encrypted channel. Both sides display 3 SAS verification words -
			you must confirm they match over a separate channel (phone call, video call, etc.).
		</p>

		<?php if ( $has_phones ) : ?>
			<div style="background:#e3f2fd;border:1px solid #90caf9;padding:10px 14px;margin-bottom:12px;border-radius:4px;">
				<p style="margin:0 0 6px;font-size:13px;"><strong><?php echo count( $phones ); ?> device(s) authorized</strong> - all pushes must be signed with Ed25519.</p>
				<p style="margin:0;font-size:12px;color:#1565c0;">
					Ensure your daemon config includes <code>"signing_privkey_hex"</code> and <code>"signing_pubkey_hex"</code>.
					Unsigned pushes will be rejected while devices are authorized.
				</p>
			</div>
		<?php else : ?>
			<div style="background:#fff3e0;border:1px solid #ffcc80;padding:10px 14px;margin-bottom:12px;border-radius:4px;">
				<p style="margin:0;font-size:13px;color:#e65100;">
					<strong>No devices authorized yet.</strong> Pushes are accepted with only the shared secret (encryption, no signing).
					Pair a device to enable Ed25519 signing for device-level identity and revocation.
				</p>
			</div>
		<?php endif; ?>

		<?php if ( $active_session ) : ?>
			<?php
			$status = $active_session['status'];
			$words = $active_session['sas_words'] ?? array();
			$bits = $active_session['bits'] ?? 0;
			$code_words = WC_XMR_Push_Pairing::bits_to_words( $bits );
			$expires_in = max( 0, $active_session['expires_at'] - time() );
			$pairing_id = $active_session['pairing_id'];
			?>
			<div style="background:#f6f7f7;border:1px solid #ccd0d4;padding:14px 16px;margin-bottom:12px;border-radius:4px;">
				<p style="margin:0 0 8px;font-size:14px;">
					<strong>Active pairing session</strong>
					<span style="color:#e65100;font-size:12px;margin-left:8px;">expires in <?php echo (int) $expires_in; ?>s</span>
				</p>

				<div style="background:#fff;border:1px solid #ddd;padding:12px 14px;margin-bottom:10px;border-radius:4px;">
					<p style="margin:0 0 8px;font-size:13px;font-weight:600;">Code words - give these to the device owner:</p>
					<div style="display:flex;gap:8px;margin-bottom:8px;">
						<code style="font-size:18px;background:#f0f0f1;padding:6px 14px;border:1px solid #ccc;border-radius:4px;font-weight:bold;"><?php echo esc_html( $code_words[0] ); ?></code>
						<code style="font-size:18px;background:#f0f0f1;padding:6px 14px;border:1px solid #ccc;border-radius:4px;font-weight:bold;"><?php echo esc_html( $code_words[1] ); ?></code>
						<code style="font-size:18px;background:#f0f0f1;padding:6px 14px;border:1px solid #ccc;border-radius:4px;font-weight:bold;"><?php echo esc_html( $code_words[2] ); ?></code>
					</div>
					<p style="margin:0;font-size:12px;color:#666;">
						Device command: <code style="background:#f0f0f1;padding:2px 6px;">python3 xmr-pushd.py --pair <?php echo esc_html( $code_words[0] ); ?> <?php echo esc_html( $code_words[1] ); ?> <?php echo esc_html( $code_words[2] ); ?></code>
					</p>
				</div>

				<?php if ( $status === 'sas_ready' && ! empty( $words ) && isset( $words[2] ) ) : ?>
					<div style="background:#e8f5e9;border:1px solid #a5d6a7;padding:14px 16px;margin:10px 0;border-radius:4px;">
						<p style="margin:0 0 8px;font-size:14px;font-weight:600;">Device connected - verify SAS words:</p>
						<div style="display:flex;gap:8px;margin-bottom:8px;">
							<code style="font-size:18px;background:#fff;padding:6px 14px;border:2px solid #4caf50;border-radius:4px;font-weight:bold;"><?php echo esc_html( $words[0] ); ?></code>
							<code style="font-size:18px;background:#fff;padding:6px 14px;border:2px solid #4caf50;border-radius:4px;font-weight:bold;"><?php echo esc_html( $words[1] ); ?></code>
							<code style="font-size:18px;background:#fff;padding:6px 14px;border:2px solid #4caf50;border-radius:4px;font-weight:bold;"><?php echo esc_html( $words[2] ); ?></code>
						</div>
						<p style="margin:0 0 10px;font-size:12px;color:#2e7d32;">
							Ask the device owner: <em>"What three words do you see?"</em> - they must match exactly.
							If they don't match, someone may be intercepting the connection. Cancel and try again.
						</p>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;">
							<input type="hidden" name="action" value="wc_xmr_push_confirm_pairing">
							<?php wp_nonce_field( 'wc_xmr_push_confirm_pairing', '_wpnonce' ); ?>
							<input type="hidden" name="pairing_id" value="<?php echo esc_attr( $pairing_id ); ?>">
							<button type="submit" class="button button-primary" onclick="return confirm('Did you verify the SAS words with the device owner over a separate channel? The words must match exactly.');">
								Confirm - words match, authorize device
							</button>
						</form>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;margin-left:8px;">
							<input type="hidden" name="action" value="wc_xmr_push_reject_pairing">
							<?php wp_nonce_field( 'wc_xmr_push_reject_pairing', '_wpnonce' ); ?>
							<input type="hidden" name="pairing_id" value="<?php echo esc_attr( $pairing_id ); ?>">
							<button type="submit" class="button" style="border-color:#d32f2f;color:#d32f2f;" onclick="return confirm('The SAS words did not match? This will immediately revoke the pairing session. The device will NOT be authorized.');">
								Words do NOT match - reject
							</button>
						</form>
					</div>
				<?php elseif ( $status === 'rejected' ) : ?>
					<div style="background:#ffebee;border:1px solid #ef9a9a;padding:10px 14px;margin:10px 0;border-radius:4px;">
						<p style="margin:0;font-size:13px;color:#c62828;">This pairing session was <strong>rejected</strong> (SAS mismatch, too many attempts, or manual rejection). The device was NOT authorized. Cancel the session to start fresh.</p>
					</div>
				<?php elseif ( $status === 'waiting' ) : ?>
					<div style="background:#fff8e1;border:1px solid #ffe082;padding:10px 14px;margin:10px 0;border-radius:4px;">
						<p style="margin:0;font-size:13px;color:#f57f17;">Waiting for device to connect with the code words above...</p>
					</div>
				<?php elseif ( $status === 'claimed' ) : ?>
					<div style="background:#fff8e1;border:1px solid #ffe082;padding:10px 14px;margin:10px 0;border-radius:4px;">
						<p style="margin:0;font-size:13px;color:#f57f17;"> Device is connecting... awaiting its encrypted key exchange.</p>
					</div>
				<?php endif; ?>

				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:10px;">
					<input type="hidden" name="action" value="wc_xmr_push_cancel_pairing">
					<?php wp_nonce_field( 'wc_xmr_push_cancel_pairing', '_wpnonce' ); ?>
					<input type="hidden" name="pairing_id" value="<?php echo esc_attr( $pairing_id ); ?>">
					<button type="submit" class="button">Cancel pairing</button>
				</form>
			</div>
		<?php else : ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="wc_xmr_push_start_pairing">
				<?php wp_nonce_field( 'wc_xmr_push_start_pairing', '_wpnonce' ); ?>
				<button type="submit" class="button button-primary">Start Word Pairing</button>
				<p class="description" style="margin-top:6px;font-size:13px;">
					Generates 3 code words. Tell them to the device owner. They enter them on the device.
					You then verify 3 SAS words match before authorizing the device.
				</p>
			</form>
		<?php endif; ?>
	</div>
	<?php
}

// Admin handlers for pairing.
add_action( 'admin_post_wc_xmr_push_start_pairing', function() {
	if ( ! wc_xmr_push_can_manage() ) wp_die( 'no' );
	check_admin_referer( 'wc_xmr_push_start_pairing' );
	$result = class_exists( 'WC_XMR_Push_Pairing' ) ? WC_XMR_Push_Pairing::generate_session() : new WP_Error( 'no_class', 'Pairing class missing' );
	if ( is_wp_error( $result ) ) {
		wp_safe_redirect( add_query_arg( array( 'wc_xmr_push_err' => $result->get_error_message() ), admin_url( 'options-general.php?page=wc-xmr-push' ) ) ); exit;
	}
	wp_safe_redirect( admin_url( 'options-general.php?page=wc-xmr-push' ) ); exit;
});

add_action( 'admin_post_wc_xmr_push_confirm_pairing', function() {
	if ( ! wc_xmr_push_can_manage() ) wp_die( 'no' );
	check_admin_referer( 'wc_xmr_push_confirm_pairing' );
	$pairing_id = isset( $_POST['pairing_id'] ) ? (string) wp_unslash( $_POST['pairing_id'] ) : '';
	$result = class_exists( 'WC_XMR_Push_Pairing' ) ? WC_XMR_Push_Pairing::confirm( $pairing_id ) : new WP_Error( 'no_class', 'Pairing class missing' );
	if ( is_wp_error( $result ) ) {
		wp_safe_redirect( add_query_arg( array( 'wc_xmr_push_err' => $result->get_error_message() ), admin_url( 'options-general.php?page=wc-xmr-push' ) ) ); exit;
	}
	wp_safe_redirect( admin_url( 'options-general.php?page=wc-xmr-push' ) ); exit;
});

add_action( 'admin_post_wc_xmr_push_reject_pairing', function() {
	if ( ! wc_xmr_push_can_manage() ) wp_die( 'no' );
	check_admin_referer( 'wc_xmr_push_reject_pairing' );
	$pairing_id = isset( $_POST['pairing_id'] ) ? (string) wp_unslash( $_POST['pairing_id'] ) : '';
	$result = class_exists( 'WC_XMR_Push_Pairing' ) ? WC_XMR_Push_Pairing::reject( $pairing_id ) : new WP_Error( 'no_class', 'Pairing class missing' );
	if ( is_wp_error( $result ) ) {
		wp_safe_redirect( add_query_arg( array( 'wc_xmr_push_err' => $result->get_error_message() ), admin_url( 'options-general.php?page=wc-xmr-push' ) ) ); exit;
	}
	wp_safe_redirect( admin_url( 'options-general.php?page=wc-xmr-push' ) ); exit;
});

add_action( 'admin_post_wc_xmr_push_cancel_pairing', function() {
	if ( ! wc_xmr_push_can_manage() ) wp_die( 'no' );
	check_admin_referer( 'wc_xmr_push_cancel_pairing' );
	$pairing_id = isset( $_POST['pairing_id'] ) ? (string) wp_unslash( $_POST['pairing_id'] ) : '';
	if ( class_exists( 'WC_XMR_Push_Pairing' ) ) {
		WC_XMR_Push_Pairing::cancel( $pairing_id );
	}
	wp_safe_redirect( admin_url( 'options-general.php?page=wc-xmr-push' ) ); exit;
});

/**
 * Lightweight state fingerprint for the settings page auto-refresh.
 * Returns only fields that change when "something happens" (pairing
 * status, device auth, confirmations, device log). Routine status pings are
 * intentionally excluded so the page doesn't reload on every poll cycle.
 */
add_action( 'wp_ajax_wc_xmr_push_state_fingerprint', function() {
	if ( ! wc_xmr_push_can_manage() ) { wp_send_json_error( 'no' ); }
	check_ajax_referer( 'wc_xmr_push_state_fingerprint', 'nonce' );

	$fp = array(
		'pair'     => 'none',
		'pair_id'  => '',
		'pair_bits'=> 0,
		'pair_sas' => '',
		'phones'   => 0,
		'log_sig'  => '',
		'phone_t'  => 0,
		'phone_n'  => 0,
	);

	try {
		if ( class_exists( 'WC_XMR_Push_Pairing' ) ) {
			foreach ( WC_XMR_Push_Pairing::get_sessions() as $s ) {
				if ( in_array( $s['status'], array( 'waiting', 'sas_ready', 'claimed', 'rejected' ), true ) ) {
					$fp['pair']      = $s['status'];
					$fp['pair_id']   = (string) ( $s['pairing_id'] ?? '' );
					$fp['pair_bits'] = (int) ( $s['bits'] ?? 0 );
					$fp['pair_sas']  = isset( $s['sas_words'] ) ? implode( '|', array_map( 'strval', (array) $s['sas_words'] ) ) : '';
					break;
				}
			}
		}

		if ( class_exists( 'WC_XMR_Push_Sig' ) && WC_XMR_Push_Sig::has_any() ) {
			$fp['phones'] = count( (array) WC_XMR_Push_Sig::get_phones() );
		}

		$interesting = array( 'confirm', 'addresses', 'phone_log', 'phone_log_empty', 'decrypt_fail', 'bad_payload', 'bad_timestamp', 'bad_type', 'bad_field', 'orphan', 'addr_reject', 'bad_confirm', 'encrypt_fail', 'no_crypto' );
		if ( class_exists( 'WC_XMR_Push_Logger' ) ) {
			$entries = WC_XMR_Push_Logger::get_entries();
			foreach ( (array) $entries as $e ) {
				$t = (string) ( $e['type'] ?? '' );
				if ( in_array( $t, $interesting, true ) ) {
					$fp['log_sig'] .= $t . ':' . ( (int) ( $e['t'] ?? 0 ) ) . ';';
				}
			}
		}

		$phone_log = get_option( 'wc_xmr_push_phone_log', null );
		if ( is_array( $phone_log ) ) {
			$fp['phone_t'] = (int) ( $phone_log['t'] ?? 0 );
			$fp['phone_n'] = is_array( $phone_log['entries'] ?? null ) ? count( $phone_log['entries'] ) : 0;
		}
	} catch ( Throwable $e ) {
		error_log( 'WC XMR Push: state fingerprint crashed: ' . $e->getMessage() );
	}

	wp_send_json_success( $fp );
});
